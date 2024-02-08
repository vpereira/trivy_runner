package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/redis/go-redis/v9"
	"github.com/vpereira/trivy_runner/internal/airbrake"
	"github.com/vpereira/trivy_runner/internal/redisutil"
	"go.uber.org/zap"
)

var (
	ctx                 = context.Background()
	rdb                 *redis.Client
	airbrakeNotifier    *airbrake.AirbrakeNotifier
	reportsAppDir       string
	logger              *zap.Logger
	processedOpsCounter = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "scanworker_processed_ops_total",
		Help: "Total number of processed operations by the scanworker.",
	})
	processedErrorsCounter = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "scanworker_processed_errors_total",
		Help: "Total number of processed errors by the scanworker.",
	})
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

	rdb = redisutil.InitializeClient()

	reportsAppDir = redisutil.GetEnv("REPORTS_APP_DIR", "/app/reports")

	err = os.MkdirAll(reportsAppDir, os.ModePerm)

	if err != nil {
		logger.Error("Failed to create base directory:", zap.String("dir", reportsAppDir), zap.Error(err))
		airbrakeNotifier.NotifyAirbrake(err)
	}

	prometheus.MustRegister(processedOpsCounter)
	prometheus.MustRegister(processedErrorsCounter)

	// Expose the registered metrics via HTTP.
	http.Handle("/metrics", promhttp.Handler())
	go func() {
		logger.Info("Server started on :8081")
		log.Fatal(http.ListenAndServe(":8081", nil))
	}()

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
		processedErrorsCounter.Inc()
		airbrakeNotifier.NotifyAirbrake(err)
		return
	}

	// Split the answer
	// [toscan registry.suse.com/bci/bci-busybox:latest|/app/images/trivy-scan-1918888852]
	parts := strings.Split(redisAnswer[1], "|")
	if len(parts) != 2 {
		logger.Error("Error: invalid format in Redis answer", zap.Strings("parts", parts))
		processedErrorsCounter.Inc()
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
	resultFileName := filepath.Join(reportsAppDir, safeImageName+".json")

	logger.Info("Scanning image:", zap.String("image", imageName))
	logger.Info("Saving results to:", zap.String("json_report", resultFileName))

	cmd := exec.Command("trivy", "image", "--format", "json", "--output", resultFileName, "--input", targetDir)

	if err := cmd.Run(); err != nil {
		logger.Error("Failed to scan image:", zap.String("image", imageName), zap.Error(err))
		processedErrorsCounter.Inc()
		airbrakeNotifier.NotifyAirbrake(err)
		return
	}

	logger.Info("Scan complete for image:", zap.String("image", imageName), zap.String("json_report", resultFileName))

	if os.Getenv("PUSH_TO_CATALOG") != "" {
		err = rdb.LPush(ctx, "topush", fmt.Sprintf("%s|%s", imageName, resultFileName)).Err()
		if err != nil {
			logger.Info("Error pushing image to toscan queue:", zap.Error(err))
			processedErrorsCounter.Inc()
			airbrakeNotifier.NotifyAirbrake(err)
		} else {
			processedOpsCounter.Inc()
		}
	}
}
