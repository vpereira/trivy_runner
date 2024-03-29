package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/redis/go-redis/v9"
	"github.com/vpereira/trivy_runner/internal/airbrake"
	"github.com/vpereira/trivy_runner/internal/error_handler"
	"github.com/vpereira/trivy_runner/internal/metrics"
	"github.com/vpereira/trivy_runner/internal/redisutil"
	"github.com/vpereira/trivy_runner/pkg/exec_command"
	"go.uber.org/zap"
)

var (
	ctx                       = context.Background()
	rdb                       *redis.Client
	airbrakeNotifier          *airbrake.AirbrakeNotifier
	reportsAppDir             string
	errorHandler              *error_handler.ErrorHandler
	logger                    *zap.Logger
	prometheusMetrics         *metrics.Metrics
	commandExecutionHistogram = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "trivy_execution_duration_seconds",
		Help:    "Duration of trivy execution.",
		Buckets: prometheus.LinearBuckets(0.1, 0.2, 20),
	}, []string{"trivy"})
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

	prometheusMetrics = metrics.NewMetrics(
		prometheus.CounterOpts{
			Name: "scanworker_processed_ops_total",
			Help: "Total number of processed operations by the scanworker.",
		},
		prometheus.CounterOpts{
			Name: "scanworker_processed_errors_total",
			Help: "Total number of processed errors by the scanworker.",
		},
		commandExecutionHistogram,
	)

	prometheusMetrics.Register()

	errorHandler = error_handler.NewErrorHandler(logger, prometheusMetrics.ProcessedErrorsCounter, airbrakeNotifier)

	rdb = redisutil.InitializeClient()

	reportsAppDir = redisutil.GetEnv("REPORTS_APP_DIR", "/app/reports")

	err = os.MkdirAll(reportsAppDir, os.ModePerm)

	if err != nil {
		logger.Error("Failed to create base directory:", zap.String("dir", reportsAppDir), zap.Error(err))
		airbrakeNotifier.NotifyAirbrake(err)
	}

	go metrics.StartMetricsServer("8081")

	// Start processing loop
	for {
		processQueue()
	}
}

func processQueue() {
	// Block until an image name is available in the 'toscan' queue
	redisAnswer, err := rdb.BRPop(ctx, 0, "toscan").Result()
	if err != nil {
		errorHandler.Handle(err)
		return
	}

	// Split the answer
	// [toscan registry.suse.com/bci/bci-busybox:latest|/app/images/trivy-scan-1918888852]
	parts := strings.Split(redisAnswer[1], "|")
	if len(parts) != 2 {
		err = fmt.Errorf("invalid format in Redis answer: %v", zap.Strings("parts", parts))
		errorHandler.Handle(err)
		return
	}

	imageName := parts[0]
	targetDir := parts[1]

	// Delete the image when we're done
	defer os.RemoveAll(targetDir)

	// Sanitize the image name to create a valid filename
	resultFileName := calculateResultName(imageName)

	logger.Info("Scanning image:", zap.String("image", imageName))
	logger.Info("Saving results to:", zap.String("json_report", resultFileName))

	cmdArgs := generateTrivyCmdArgs(resultFileName, targetDir)

	startTime := time.Now()
	cmd := exec_command.NewExecShellCommander("trivy", cmdArgs...)

	if _, err := cmd.Output(); err != nil {
		errorHandler.Handle(err)
		return
	}

	duration := time.Since(startTime).Seconds()
	logger.Info("Scan complete for image:", zap.String("image", imageName), zap.String("json_report", resultFileName))

	if os.Getenv("PUSH_TO_CATALOG") != "" {
		err = rdb.LPush(ctx, "topush", fmt.Sprintf("%s|%s", imageName, resultFileName)).Err()
		if err != nil {
			errorHandler.Handle(err)
			return
		}
	}
	prometheusMetrics.CommandExecutionDurationHistogram.WithLabelValues("trivy").Observe(duration)
	prometheusMetrics.IncOpsProcessed()
}

func calculateResultName(imageName string) string {
	safeImageName := strings.ReplaceAll(imageName, "/", "_")
	safeImageName = strings.ReplaceAll(safeImageName, ":", "_")
	return filepath.Join(reportsAppDir, safeImageName+".json")
}

func generateTrivyCmdArgs(resultFileName, targetDir string) []string {
	return []string{"image", "--format", "json", "--output", resultFileName, "--input", targetDir}
}
