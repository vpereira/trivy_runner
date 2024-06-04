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
	"github.com/vpereira/trivy_runner/internal/skopeo"
	"github.com/vpereira/trivy_runner/internal/util"
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
			Name: "pullworker_processed_ops_total",
			Help: "Total number of processed operations by the pullworker.",
		},
		prometheus.CounterOpts{
			Name: "pullworker_processed_errors_total",
			Help: "Total number of processed errors by the pullworker.",
		},
		commandExecutionHistogram,
	)
	imagesAppDir = util.GetEnv("IMAGES_APP_DIR", "/app/images")
}

func main() {
	defer func() { _ = logger.Sync() }()

	prometheusMetrics.Register()

	errorHandler = error_handler.NewErrorHandler(logger, prometheusMetrics.ProcessedErrorsCounter, airbrakeNotifier, sentryNotifier)

	rdb = redisutil.InitializeClient()

	err := os.MkdirAll(imagesAppDir, os.ModePerm)

	if err != nil {
		logger.Error("Failed to create base directory:", zap.Error(err))
		airbrakeNotifier.NotifyAirbrake(err)
	}

	// Start the metrics server in a separate goroutine
	go metrics.StartMetricsServer("8082")

	// Start processing loop
	for {
		processQueue()
	}
}

func processQueue() {
	// Block until an image name is available in the 'topull' queue
	result, err := rdb.BRPopLPush(ctx, "topull", "processing", 0).Result()

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

	toPullArch := "amd64"
	// TODO
	// if we want to make trivy multi arch, we need to pull all the archs
	supportedArchitectures, err := skopeo.GetSupportedArchitectures(imageName)

	if err != nil {
		errorHandler.Handle(err)
		return
	}

	if !util.Contains(supportedArchitectures, "amd64") {
		toPullArch = supportedArchitectures[0]
	}

	sentryNotifier.AddTag("image.name", imageName)
	logger.Info("Processing image: ", zap.String("imageName", imageName))
	logger.Info("Architecture to pull: ", zap.String("architecture", toPullArch))
	logger.Info("Target directory: ", zap.String("targetDir", targetDir))
	logger.Info("Target tarball: ", zap.String("targetDir", tarballFilename))

	cmdArgs := skopeo.GenerateSkopeoCmdArgs(imageName, tarballFilename, toPullArch)

	startTime := time.Now()

	cmd := exec_command.NewExecShellCommander("skopeo", cmdArgs...)

	if output, err := cmd.CombinedOutput(); err != nil {
		errorHandler.Handle(fmt.Errorf("skopeo output: %s, error: %s", string(output), err.Error()))
		return
	}

	executionTime := time.Since(startTime).Seconds()

	// Move the image name from 'processing' to 'toscan'
	_, err = rdb.LRem(ctx, "processing", 1, imageName).Result()
	if err != nil {
		errorHandler.Handle(err)
		return
	}

	toScanString := fmt.Sprintf("%s|%s", imageName, tarballFilename)

	logger.Info("Pushing image to toscan queue:", zap.String("image", toScanString))

	err = rdb.LPush(ctx, "toscan", toScanString).Err()

	if err != nil {
		errorHandler.Handle(err)
		return
	}
	prometheusMetrics.CommandExecutionDurationHistogram.WithLabelValues(imageName).Observe(executionTime)
	prometheusMetrics.IncOpsProcessed()
}
