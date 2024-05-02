package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/redis/go-redis/v9"
	"github.com/vpereira/trivy_runner/internal/airbrake"
	"github.com/vpereira/trivy_runner/internal/error_handler"
	"github.com/vpereira/trivy_runner/internal/metrics"
	"github.com/vpereira/trivy_runner/internal/redisutil"
	"github.com/vpereira/trivy_runner/internal/sentry"
	"github.com/vpereira/trivy_runner/pkg/exec_command"
	"go.uber.org/zap"
)

var (
	ctx                       = context.Background()
	rdb                       *redis.Client
	airbrakeNotifier          *airbrake.AirbrakeNotifier
	sentryNotifier            sentry.Notifier
	errorHandler              *error_handler.ErrorHandler
	imagesAppDir              string
	logger                    *zap.Logger
	prometheusMetrics         *metrics.Metrics
	commandExecutionHistogram = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "skopeo_execution_duration_seconds",
		Help:    "Duration of skopeo execution.",
		Buckets: prometheus.LinearBuckets(0, 5, 20),
	}, []string{"skopeo"})
)

func main() {
	var err error

	logger, err = zap.NewProduction()

	if err != nil {
		log.Fatal("Failed to create logger:", err)
	}

	defer func() { _ = logger.Sync() }()

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
			Name: "getsize_worker_processed_ops_total",
			Help: "Total number of processed operations by the getsize_worker.",
		},
		prometheus.CounterOpts{
			Name: "getsize_worker_processed_errors_total",
			Help: "Total number of processed errors by the getsize_worker.",
		},
		commandExecutionHistogram,
	)

	prometheusMetrics.Register()

	errorHandler = error_handler.NewErrorHandler(logger, prometheusMetrics.ProcessedErrorsCounter, airbrakeNotifier, sentryNotifier)

	rdb = redisutil.InitializeClient()

	imagesAppDir = redisutil.GetEnv("IMAGES_APP_DIR", "/app/images")

	err = os.MkdirAll(imagesAppDir, os.ModePerm)

	if err != nil {
		logger.Error("Failed to create base directory:", zap.Error(err))
		airbrakeNotifier.NotifyAirbrake(err)
	}

	// Start the metrics server in a separate goroutine
	go metrics.StartMetricsServer("8084")

	// Start processing loop
	for {
		processQueue()
	}
}

func processQueue() {
	// Block until an image name is available in the 'topull' queue
	result, err := rdb.BRPopLPush(ctx, "getsize", "processing_getsize", 0).Result()

	if err != nil {
		errorHandler.Handle(err)
		return
	}

	targetDir, err := os.MkdirTemp(imagesAppDir, "trivy-scan-*")
	tarballFilename := fmt.Sprintf("%s/image.tar", targetDir)

	if err != nil {
		errorHandler.Handle(err)
		return
	}

	imageName := result

	if imageName == "" {
		errorHandler.Handle(err)
		return
	}

	logger.Info("Processing image: ", zap.String("imageName", imageName))
	logger.Info("Target directory: ", zap.String("targetDir", targetDir))
	logger.Info("Target tarball: ", zap.String("targetDir", tarballFilename))

	cmdArgs := GenerateSkopeoCmdArgs(imageName, tarballFilename)

	startTime := time.Now()

	cmd := exec_command.NewExecShellCommander("skopeo", cmdArgs...)

	if _, err := cmd.Output(); err != nil {
		errorHandler.Handle(err)
		return
	}

	executionTime := time.Since(startTime).Seconds()

	// Move the image name from 'processing_getsize' to 'topush'
	_, err = rdb.LRem(ctx, "processing_getsize", 1, imageName).Result()
	if err != nil {
		errorHandler.Handle(err)
		return
	}

	imageSize, err := getFileSize(tarballFilename)

	if err != nil {
		errorHandler.Handle(err)
		return
	}

	toPushString := fmt.Sprintf("%s|%d", imageName, imageSize)

	logger.Info("Pushing image uncompressed size to topush queue:", zap.String("image", toPushString))

	err = rdb.LPush(ctx, "topush", toPushString).Err()

	if err != nil {
		errorHandler.Handle(err)
		return
	}
	prometheusMetrics.CommandExecutionDurationHistogram.WithLabelValues(imageName).Observe(executionTime)
	prometheusMetrics.IncOpsProcessed()
}

// getFileSize returns the size of the file at the given path in bytes.
func getFileSize(filePath string) (int64, error) {
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return 0, err
	}
	return fileInfo.Size(), nil
}

// GenerateSkopeoCmdArgs generates the command line arguments for the skopeo command based on environment variables and input parameters.
func GenerateSkopeoCmdArgs(imageName, targetFilename string) []string {
	cmdArgs := []string{"copy", "--remove-signatures"}

	// Check and add registry credentials if they are set
	registryUsername, usernameSet := os.LookupEnv("REGISTRY_USERNAME")
	registryPassword, passwordSet := os.LookupEnv("REGISTRY_PASSWORD")

	if usernameSet && passwordSet {
		cmdArgs = append(cmdArgs, "--src-username", registryUsername, "--src-password", registryPassword)
	}

	// Add the rest of the command
	cmdArgs = append(cmdArgs, fmt.Sprintf("docker://%s", imageName), fmt.Sprintf("docker-archive://%s", targetFilename))

	return cmdArgs
}
