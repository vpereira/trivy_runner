package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/redis/go-redis/v9"
	"github.com/vpereira/trivy_runner/internal/airbrake"
	"github.com/vpereira/trivy_runner/internal/error_handler"
	"github.com/vpereira/trivy_runner/internal/metrics"
	"github.com/vpereira/trivy_runner/internal/pushworker"
	"github.com/vpereira/trivy_runner/internal/redisutil"
	"github.com/vpereira/trivy_runner/internal/sentry"
	"github.com/vpereira/trivy_runner/internal/trivy"
	"github.com/vpereira/trivy_runner/internal/util"
	"github.com/vpereira/trivy_runner/pkg/exec_command"
	"go.uber.org/zap"
)

var (
	ctx                       = context.Background()
	rdb                       *redis.Client
	airbrakeNotifier          *airbrake.AirbrakeNotifier
	sentryNotifier            sentry.Notifier
	reportsAppDir             string
	errorHandler              *error_handler.ErrorHandler
	logger                    *zap.Logger
	prometheusMetrics         *metrics.Metrics
	commandExecutionHistogram = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "trivy_execution_duration_seconds",
		Help:    "Duration of trivy execution.",
		Buckets: prometheus.LinearBuckets(0, 5, 20),
	}, []string{"trivy"})
)

func init() {
	var err error
	logger, err = zap.NewProduction()

	if err != nil {
		log.Fatal("Failed to create logger:", err)
	}

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
			Name: "sbomworker_processed_ops_total",
			Help: "Total number of processed operations by the sbomworker.",
		},
		prometheus.CounterOpts{
			Name: "sbomworker_processed_errors_total",
			Help: "Total number of processed errors by the sbomworker.",
		},
		commandExecutionHistogram,
	)

	reportsAppDir = util.GetEnv("REPORTS_APP_DIR", "/app/reports")

	prometheusMetrics.Register()
}

func main() {
	defer logger.Sync()

	errorHandler = error_handler.NewErrorHandler(logger, prometheusMetrics.ProcessedErrorsCounter, airbrakeNotifier, sentryNotifier)

	rdb = redisutil.InitializeClient()

	err := os.MkdirAll(reportsAppDir, os.ModePerm)

	if err != nil {
		logger.Error("Failed to create base directory:", zap.String("dir", reportsAppDir), zap.Error(err))
		airbrakeNotifier.NotifyAirbrake(err)
	}

	go metrics.StartMetricsServer("8085")

	// Start processing loop
	for {
		processQueue()
	}
}

func processQueue() {
	// Block until an image name is available in the 'tosbom' queue
	redisAnswer, err := rdb.BRPop(ctx, 0, "tosbom").Result()
	if err != nil {
		errorHandler.Handle(err)
		return
	}

	// Split the answer
	// [tosbom registry.suse.com/bci/bci-busybox:latest|/app/images/trivy-scan-1918888852]
	parts := strings.Split(redisAnswer[1], "|")
	if len(parts) != 2 {
		err = fmt.Errorf("invalid format in Redis answer: %v", zap.Strings("parts", parts))
		errorHandler.Handle(err)
		return
	}

	imageName := parts[0]
	target := parts[1]

	sentryNotifier.AddTag("gun", imageName)
	sentryNotifier.AddTag("target-dir", target)
	// Delete the image when we're done
	defer os.RemoveAll(target)

	// Sanitize the image name to create a valid filename
	resultFileName := util.CalculateResultName(imageName, reportsAppDir)

	logger.Info("Fetching SBOM for image:", zap.String("image", imageName))
	logger.Info("Saving results to:", zap.String("json_report", resultFileName))

	cmdArgs := trivy.GenerateTrivySBOMCmdArgs(resultFileName, target)

	startTime := time.Now()
	cmd := exec_command.NewExecShellCommander("trivy", cmdArgs...)

	if output, err := cmd.CombinedOutput(); err != nil {
		if sentryNotifier != nil {
			sentryNotifier.AddTag("gun", imageName)
		}
		errorHandler.Handle(fmt.Errorf("trivy output: %s, error: %s", string(output), err.Error()))
		return
	}

	executionTime := time.Since(startTime).Seconds()
	logger.Info("SBOM generation complete for image:", zap.String("image", imageName), zap.String("json_report", resultFileName))

	if os.Getenv("PUSH_TO_CATALOG") != "" {
		payload := pushworker.NewScanDTO()
		payload.ResultFilePath = resultFileName
		payload.Image = imageName

		jsonData, err := payload.ToJSON()
		if err != nil {
			errorHandler.Handle(err)
			return
		}

		toPushString := string(jsonData)
		logger.Info("Pushing image scan to topush queue:", zap.String("payload", toPushString))

		err = rdb.LPush(ctx, "topush", jsonData).Err()
		if err != nil {
			errorHandler.Handle(err)
			return
		}
	}
	prometheusMetrics.CommandExecutionDurationHistogram.WithLabelValues(imageName).Observe(executionTime)
	prometheusMetrics.IncOpsProcessed()
}
