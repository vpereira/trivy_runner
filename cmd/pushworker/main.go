package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/vpereira/trivy_runner/internal/airbrake"
	"github.com/vpereira/trivy_runner/internal/redisutil"
	"go.uber.org/zap"
)

type ScanResult struct {
	Image   string          `json:"image"`
	RanAt   string          `json:"ran_at"`
	Results json.RawMessage `json:"results"`
}

var ctx = context.Background()
var rdb *redis.Client
var logger *zap.Logger

var airbrakeNotifier *airbrake.AirbrakeNotifier

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

	webhookURL := os.Getenv("WEBHOOK_URL")

	if webhookURL == "" {
		logger.Error("WEBHOOK_URL environment variable is not set")
	}

	rdb = redisutil.InitializeClient()

	for {
		processQueue(webhookURL)
	}
}

func processQueue(webhookURL string) {
	redisAnswer, err := rdb.BRPop(ctx, 0, "topush").Result()
	if err != nil {
		logger.Error("Error:", zap.Error(err))
		airbrakeNotifier.NotifyAirbrake(err)
		return
	}

	// Split the answer
	// [topush registry.suse.com/bci/bci-busybox:latest|/app/reports/registry.suse.com_bci_bci-busybox_latest.json]
	parts := strings.Split(redisAnswer[1], "|")
	if len(parts) != 2 {
		logger.Error("Error: invalid format in Redis answer", zap.Strings("parts", parts))
		airbrakeNotifier.NotifyAirbrake(fmt.Errorf("Invalid format in Redis answer: %v", parts))
		return
	}

	imageName := parts[0]
	reportPath := parts[1]

	scanResults, err := extractResults(reportPath)

	if err != nil {
		logger.Error("Error processing file:", zap.String("json_report", reportPath), zap.Error(err))
		airbrakeNotifier.NotifyAirbrake(err)
		return
	}

	scanResult := ScanResult{
		Image:   imageName,
		RanAt:   time.Now().Format(time.RFC3339),
		Results: scanResults,
	}
	// send it with a goroutine
	go sendToWebhook(webhookURL, scanResult, imageName)
}

func extractResults(filePath string) (json.RawMessage, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("Failed to read file: %v", err)
	}

	// unmarshal the data
	var result ScanResult
	err = json.Unmarshal(data, &result)
	if err != nil {
		return nil, fmt.Errorf("Failed to unmarshal data: %v", err)
	}

	return result.Results, nil
}

func sendToWebhook(webhookURL string, result ScanResult, imageName string) {

	jsonData, err := json.Marshal(result)

	if err != nil {
		logger.Error("Error marshaling JSON:", zap.Error(err))
		airbrakeNotifier.NotifyAirbrake(err)
		return
	}

	req, err := http.NewRequest("POST", webhookURL, bytes.NewBuffer(jsonData))

	if err != nil {
		logger.Error("Error creating request:", zap.Error(err))
		airbrakeNotifier.NotifyAirbrake(err)
		return
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)

	if err != nil {
		logger.Error("Failed to send report:", zap.Error(err))
		airbrakeNotifier.NotifyAirbrake(err)
		return
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		logger.Error("Failed to send report, status code:", zap.Int("status_code", resp.StatusCode))
		airbrakeNotifier.NotifyAirbrake(err)
	} else {
		logger.Info("Report sent successfully for image:", zap.String("imageName", imageName))
	}
}
