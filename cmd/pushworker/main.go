package main

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/redis/go-redis/v9"
	"github.com/vpereira/trivy_runner/internal/airbrake"
	"github.com/vpereira/trivy_runner/internal/error_handler"
	"github.com/vpereira/trivy_runner/internal/metrics"
	"github.com/vpereira/trivy_runner/internal/redisutil"
	"github.com/vpereira/trivy_runner/internal/sentry"
	"go.uber.org/zap"
)

type ScanResult struct {
	Image   string          `json:"image"`
	RanAt   string          `json:"ran_at"`
	Results json.RawMessage `json:"results"`
}

type UncompressedSize struct {
	Image             string         `json:"image"`
	UncompressedSizes map[string]int `json:"uncompressed_sizes"`
}

// TODO
// We have it as well on getsizeworker/main.go
// Response represents the response to be returned to the user.
type Response struct {
	Image string           `json:"image"`
	Sizes map[string]int64 `json:"sizes"`
}

var (
	ctx               = context.Background()
	rdb               *redis.Client
	logger            *zap.Logger
	airbrakeNotifier  *airbrake.AirbrakeNotifier
	sentryNotifier    sentry.Notifier
	errorHandler      *error_handler.ErrorHandler
	prometheusMetrics *metrics.Metrics
)

func main() {
	var err error
	logger, err = zap.NewProduction()

	if err != nil {
		log.Fatal("Failed to create logger:", err)
	}

	defer logger.Sync()

	airbrakeNotifier = airbrake.NewAirbrakeNotifier()

	if airbrakeNotifier == nil {
		logger.Error("Failed to create airbrake notifier")
	}

	sentryNotifier = sentry.NewSentryNotifier()

	if sentryNotifier == nil {
		logger.Error("Failed to create sentry notifier")
	}

	prometheusMetrics = metrics.NewMetrics(
		prometheus.CounterOpts{
			Name: "pushworker_processed_ops_total",
			Help: "Total number of processed operations by the pushworker.",
		},
		prometheus.CounterOpts{
			Name: "pushworker_processed_errors_total",
			Help: "Total number of processed errors by the pushworker.",
		},
	)

	prometheusMetrics.Register()

	errorHandler = error_handler.NewErrorHandler(logger, prometheusMetrics.ProcessedErrorsCounter, airbrakeNotifier, sentryNotifier)

	webhookURL := os.Getenv("WEBHOOK_URL")

	if webhookURL == "" {
		logger.Error("WEBHOOK_URL environment variable is not set")
	}

	rdb = redisutil.InitializeClient()

	go metrics.StartMetricsServer("8083")

	for {
		processQueue(webhookURL)
	}
}

func processQueue(webhookURL string) {
	redisAnswer, err := rdb.BRPop(ctx, 0, "topush").Result()

	if err != nil {
		errorHandler.Handle(err)
		return
	}

	// TODO: Adapt it when adapting getsizeworker to support
	// multiple architectures

	// Split the answer
	// [topush registry.suse.com/bci/bci-busybox:latest|/app/reports/registry.suse.com_bci_bci-busybox_latest.json]
	// or
	// [topush registry.suse.com/bci/bci-busybox:latest|31337]
	parts := strings.Split(redisAnswer[1], "|")

	if len(parts) != 2 {
		errorHandler.Handle(err)
		return
	}

	imageName := parts[0]
	secondPart := parts[1]

	var uncompressedSizes Response

	err = json.Unmarshal([]byte(secondPart), &uncompressedSizes)

	if err == nil {
		logger.Info("First part:", zap.String("imageName", imageName), zap.Any("uncompressedSizes", uncompressedSizes))
		go sendToWebhook(webhookURL, uncompressedSizes)
	} else {
		logger.Info("Second part:", zap.String("imageName", imageName), zap.String("secondPart", secondPart))
		scanResults, err := extractResults(secondPart)

		if err != nil {
			errorHandler.Handle(err)
			return
		}

		scanResult := ScanResult{
			Image:   imageName,
			RanAt:   time.Now().Format(time.RFC3339),
			Results: scanResults,
		}
		go sendToWebhook(webhookURL, scanResult)
	}

}

func extractResults(filePath string) (json.RawMessage, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		errorHandler.Handle(err)
		return nil, err
	}

	// unmarshal the data
	var result ScanResult
	err = json.Unmarshal(data, &result)
	if err != nil {
		return nil, err
	}

	return result.Results, nil
}

func sendToWebhook(webhookURL string, result interface{}) {
	jsonData, err := json.Marshal(result)
	imageName := reflect.TypeOf(result).Name()

	if err != nil {
		errorHandler.Handle(err)
		return
	}

	req, err := http.NewRequest("POST", webhookURL, bytes.NewBuffer(jsonData))

	if err != nil {
		errorHandler.Handle(err)
		return
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)

	if err != nil {
		errorHandler.Handle(err)
		return
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		errorHandler.Handle(err)
		return
	}
	logger.Info("Report sent successfully for image:", zap.String("image", imageName))
	prometheusMetrics.IncOpsProcessed()
}
