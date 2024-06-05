package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
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

// ImageSize represents the size of the image for a specific architecture.
type ImageSize struct {
	Architecture string `json:"architecture"`
	Size         int64  `json:"size"`
}

// Response represents the response to be returned to the user.
type Response struct {
	Image string           `json:"image"`
	Sizes map[string]int64 `json:"sizes"`
}

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
			Name: "getsize_worker_processed_ops_total",
			Help: "Total number of processed operations by the getsize_worker.",
		},
		prometheus.CounterOpts{
			Name: "getsize_worker_processed_errors_total",
			Help: "Total number of processed errors by the getsize_worker.",
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
	go metrics.StartMetricsServer("8084")

	// Start processing loop
	for {
		processQueue()
	}
}

func downloadImageAndGetSize(image, architecture, filePath string) (int64, error) {
	cmdArgs := skopeo.GenerateSkopeoCmdArgs(image, filePath, architecture)

	logger.Info("Executing skopeo with arguments", zap.String("arguments", strings.Join(cmdArgs, " ")))

	cmd := exec_command.NewExecShellCommander("skopeo", cmdArgs...)

	output, err := cmd.CombinedOutput()

	if err != nil {
		return 0, fmt.Errorf("skopeo output: %s, error: %s", string(output), err.Error())
	}

	logger.Info("skopeo output", zap.String("architecture", architecture), zap.String("output", string(output)))

	// Ensure the file was created
	if _, err := os.Stat(filePath); err != nil {
		return 0, fmt.Errorf("error verifying file creation: %s", err.Error())
	}

	size, err := getFileSize(filePath)
	if err != nil {
		return 0, err
	}

	return size, nil
}

func processQueue() {
	// Block until an image name is available in the 'topull' queue
	result, err := rdb.BRPopLPush(ctx, "getsize", "processing_getsize", 0).Result()

	if err != nil {
		errorHandler.Handle(err)
		return
	}

	imageName := result

	imageNameSanitized := sanitizeImageName(imageName)

	targetDir, err := os.MkdirTemp(imagesAppDir, "trivy-scan-*")

	if err != nil {
		errorHandler.Handle(err)
		return
	}

	logger.Info("Processing image: ", zap.String("imageName", imageName))
	logger.Info("Target directory: ", zap.String("targetDir", targetDir))

	// Get the supported architectures for the image
	architectures, err := skopeo.GetSupportedArchitectures(imageName)

	if err != nil {
		errorHandler.Handle(err)
		return
	}

	defer os.RemoveAll(targetDir)

	var wg sync.WaitGroup
	sizeResults := make(chan ImageSize, len(architectures))

	startTime := time.Now()
	// Move the image name from 'processing_getsize' to 'topush'
	_, err = rdb.LRem(ctx, "processing_getsize", 1, imageName).Result()
	if err != nil {
		errorHandler.Handle(err)
		return
	}
	for _, arch := range architectures {
		wg.Add(1)
		go func(architecture string) {
			defer wg.Done()
			tarballFilename := filepath.Join(targetDir, fmt.Sprintf("%s_%s.tar", imageNameSanitized, architecture))
			logger.Info("Target tarball: ", zap.String("targetDir", tarballFilename))
			size, err := downloadImageAndGetSize(imageName, architecture, tarballFilename)
			if err != nil {
				errorHandler.Handle(err)
				return
			}
			sizeResults <- ImageSize{Architecture: architecture, Size: size}
		}(arch)
	}
	wg.Wait()
	close(sizeResults)
	executionTime := time.Since(startTime).Seconds()

	sizes := make(map[string]int64)
	for result := range sizeResults {
		sizes[result.Architecture] = result.Size
	}

	imageSizes := Response{Image: imageName, Sizes: sizes}

	imageSizesJSON, err := json.Marshal(imageSizes)

	if err != nil {
		errorHandler.Handle(err)
		return
	}

	toPushString := fmt.Sprintf("%s|%s", imageName, string(imageSizesJSON))

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

// sanitizeImageName replaces slashes and colons in the image name with underscores.
func sanitizeImageName(image string) string {
	return strings.NewReplacer("/", "_", ":", "_").Replace(image)
}
