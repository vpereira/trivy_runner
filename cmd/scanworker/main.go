package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"

	"github.com/redis/go-redis/v9"
	"github.com/vpereira/trivy_runner/internal/airbrake"
	"github.com/vpereira/trivy_runner/internal/redisutil"
	"go.uber.org/zap"
)

var ctx = context.Background()
var rdb *redis.Client
var airbrakeNotifier *airbrake.AirbrakeNotifier
var reportsAppDir string
var logger *zap.Logger

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

	rdb = redisutil.InitializeClient()

	reportsAppDir = redisutil.GetEnv("REPORTS_APP_DIR", "/app/reports")

	err = os.MkdirAll(reportsAppDir, os.ModePerm)

	if err != nil {
		logger.Error("Failed to create base directory:", zap.String("dir", reportsAppDir), zap.Error(err))
		airbrakeNotifier.NotifyAirbrake(err)
	}

	// Start processing loop
	for {
		processQueue()
	}
}

func processQueue() {
	// Block until an image name is available in the 'toscan' queue
	redisAnswer, err := rdb.BRPop(ctx, 0, "toscan").Result()
	if err != nil {
		logger.Error("Error:", zap.Error(err))
		airbrakeNotifier.NotifyAirbrake(err)
		return
	}

	// Split the answer
	// [toscan registry.suse.com/bci/bci-busybox:latest|/app/images/trivy-scan-1918888852]
	parts := strings.Split(redisAnswer[1], "|")
	if len(parts) != 2 {
		logger.Error("Error: invalid format in Redis answer", zap.Strings("parts", parts))
		airbrakeNotifier.NotifyAirbrake(fmt.Errorf("Invalid format in Redis answer: %v", parts))
		return
	}

	imageName := parts[0]
	targetDir := parts[1]

	// Delete the image when we're done
	defer os.RemoveAll(targetDir)

	// Sanitize the image name to create a valid filename
	safeImageName := strings.ReplaceAll(imageName, "/", "_")
	safeImageName = strings.ReplaceAll(safeImageName, ":", "_")
	resultFileName := reportsAppDir + safeImageName + ".json"

	logger.Info("Scanning image:", zap.String("image", imageName))
	logger.Info("Saving results to:", zap.String("json_report", resultFileName))

	cmd := exec.Command("trivy", "image", "--format", "json", "--output", resultFileName, "--input", targetDir)

	if err := cmd.Run(); err != nil {
		logger.Error("Failed to scan image:", zap.String("image", imageName), zap.Error(err))
		airbrakeNotifier.NotifyAirbrake(err)
		return
	}

	logger.Info("Scan complete for image:", zap.String("image", imageName), zap.String("json_report", resultFileName))

	if os.Getenv("PUSH_TO_CATALOG") != "" {
		err = rdb.LPush(ctx, "topush", fmt.Sprintf("%s|%s", imageName, resultFileName)).Err()
		if err != nil {
			logger.Info("Error pushing image to toscan queue:", zap.Error(err))
			airbrakeNotifier.NotifyAirbrake(err)
		}
	}
}
