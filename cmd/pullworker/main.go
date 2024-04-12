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
	sentryNotifier            *sentry.SentryNotifier
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

type imageProcessResult struct {
	queueName string
	imageName string
	err       error
}

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
			Name: "pullworker_processed_ops_total",
			Help: "Total number of processed operations by the pullworker.",
		},
		prometheus.CounterOpts{
			Name: "pullworker_processed_errors_total",
			Help: "Total number of processed errors by the pullworker.",
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
	go metrics.StartMetricsServer("8082")

	processedImages := make(chan imageProcessResult)

	// Start listening on both queues in separate goroutines
	go listenQueue("topull", processedImages)
	go listenQueue("getsize", processedImages)

	// Process results from both queues as they come in
	for result := range processedImages {
		if result.err != nil {
			errorHandler.Handle(result.err)
		} else {
			logger.Info("Processed image", zap.String("imageName", result.imageName),
				zap.String("fromQueue", result.queueName), zap.String("status", "success"))
		}
	}
}

func listenQueue(queueName string, processed chan<- imageProcessResult) {
	for {
		imageName, err := rdb.BRPopLPush(ctx, queueName, "processing", 0).Result()
		if err != nil {
			processed <- imageProcessResult{queueName: queueName, imageName: imageName, err: err}
			continue
		}

		if imageName == "" {
			processed <- imageProcessResult{queueName: queueName, imageName: imageName, err: fmt.Errorf("received empty image name from queue")}
			continue
		}

		processImage(queueName, imageName, processed)
	}
}

func processImage(queueName, imageName string, processed chan<- imageProcessResult) {
	targetDir, err := os.MkdirTemp(imagesAppDir, "trivy-scan-*")
	tarballFilename := fmt.Sprintf("%s/image.tar", targetDir)

	if err != nil {
		processed <- imageProcessResult{queueName: queueName, imageName: imageName, err: err}
		return
	}

	cmdArgs := GenerateSkopeoCmdArgs(imageName, tarballFilename)
	startTime := time.Now()

	cmd := exec_command.NewExecShellCommander("skopeo", cmdArgs...)

	if _, err := cmd.Output(); err != nil {
		processed <- imageProcessResult{queueName: queueName, imageName: imageName, err: err}
		return
	}

	executionTime := time.Since(startTime).Seconds()
	prometheusMetrics.CommandExecutionDurationHistogram.WithLabelValues(imageName).Observe(executionTime)
	prometheusMetrics.IncOpsProcessed()

	var pushQueue string
	var pushData string

	if queueName == "topull" {
		pushQueue = "toscan"
		pushData = fmt.Sprintf("%s|%s", imageName, tarballFilename)
	} else { // "getsize"
		info, err := os.Stat(tarballFilename)
		if err != nil {
			processed <- imageProcessResult{queueName: queueName, imageName: imageName, err: err}
			return
		}
		size := info.Size()
		pushQueue = "topush"
		pushData = fmt.Sprintf("%s:%d", imageName, size)
	}

	err = rdb.LPush(ctx, pushQueue, pushData).Err()
	if err != nil {
		processed <- imageProcessResult{queueName: queueName, imageName: imageName, err: err}
		return
	}

	// Send the successful process result to the main goroutine
	processed <- imageProcessResult{queueName: queueName, imageName: imageName, err: nil}
}

// GenerateSkopeoCmdArgs generates the command line arguments for the skopeo command based on environment variables and input parameters.
func GenerateSkopeoCmdArgs(imageName, targetFilename string) []string {
	cmdArgs := []string{"copy", "--remove-signatures"}

	// Check and add registry credentials if they are set
	registryUsername, usernameSet := os.LookupEnv("REGISTRY_USERNAME")
	registryPassword, passwordSet := os.LookupEnv("REGISTRY_PASSWORD")

	if usernameSet && passwordSet {
		cmdArgs = append(cmdArgs, "--dest-username", registryUsername, "--dest-password", registryPassword)
	}

	// Add the rest of the command
	cmdArgs = append(cmdArgs, fmt.Sprintf("docker://%s", imageName), fmt.Sprintf("docker-archive://%s", targetFilename))

	return cmdArgs
}
