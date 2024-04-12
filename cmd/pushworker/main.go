package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
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
	Image string `json:"image"`
	Size  int    `json:"size"`
}

var (
	ctx               = context.Background()
	rdb               *redis.Client
	logger            *zap.Logger
	airbrakeNotifier  *airbrake.AirbrakeNotifier
	sentryNotifier    *sentry.SentryNotifier
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

	parts := strings.Split(redisAnswer[1], ":")

	if len(parts) == 2 && strings.Contains(parts[1], "size") {
		size, err := strconv.Atoi(parts[1])
		if err != nil {
			errorHandler.Handle(err)
			return
		}

		uncompressedSize := UncompressedSize{
			Image: parts[0],
			Size:  size,
		}

		go sendSizeToWebhook(webhookURL, uncompressedSize)
	} else {
		processAndSendScanResult(webhookURL, parts[0], parts[1])
	}
}

func processAndSendScanResult(webhookURL, imageName, reportPath string) {
	scanResults, err := extractResults(reportPath)
	if err != nil {
		errorHandler.Handle(err)
		return
	}

	scanResult := ScanResult{
		Image:   imageName,
		RanAt:   time.Now().Format(time.RFC3339),
		Results: scanResults,
	}

	go sendToWebhook(webhookURL, scanResult, imageName)
}

func extractResults(filePath string) (json.RawMessage, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var result ScanResult
	err = json.Unmarshal(data, &result)
	if err != nil {
		return nil, err
	}

	return result.Results, nil
}

func sendSizeToWebhook(webhookURL string, size UncompressedSize) {
	jsonData, err := json.Marshal(size)
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
		errorHandler.Handle(fmt.Errorf("HTTP error: %d", resp.StatusCode))
		return
	}

	logger.Info("Uncompressed size sent successfully for image:", zap.String("imageName", size.Image))
	prometheusMetrics.IncOpsProcessed()
}

func sendToWebhook(webhookURL string, result ScanResult, imageName string) {
	jsonData, err := json.Marshal(result)
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
		errorHandler.Handle(fmt.Errorf("HTTP error: %d", resp.StatusCode))
		return
	}

	logger.Info("Report sent successfully for image:", zap.String("imageName", imageName))
	prometheusMetrics.IncOpsProcessed()
}
