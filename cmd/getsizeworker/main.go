package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
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

func downloadImageAndGetSize(image, architecture, filePath string) (int64, error) {
	cmdArgs := GenerateSkopeoCmdArgs(image, filePath, architecture)

	fmt.Printf("Executing skopeo with arguments: %v\n", cmdArgs)
	cmd := exec.Command("skopeo", cmdArgs...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return 0, fmt.Errorf("skopeo output: %s, error: %s", string(output), err.Error())
	}

	fmt.Printf("skopeo output for architecture %s: %s\n", architecture, string(output))

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
	architectures, err := getSupportedArchitectures(imageName)

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
				fmt.Printf("Error downloading image for architecture %s: %s\n", architecture, err.Error())
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

	toPushString := fmt.Sprintf("%s|%d", imageName, imageSizesJSON)

	logger.Info("Pushing image uncompressed size to topush queue:", zap.String("image", toPushString))

	err = rdb.LPush(ctx, "topush", toPushString).Err()

	if err != nil {
		errorHandler.Handle(err)
		return
	}
	prometheusMetrics.CommandExecutionDurationHistogram.WithLabelValues(imageName).Observe(executionTime)
	prometheusMetrics.IncOpsProcessed()
}

// GenerateSkopeoInspectCmdArgs generates the command line arguments for the skopeo inspect to fetch all supported architectures
func GenerateSkopeoInspectCmdArgs(imageName string) []string {
	return []string{"inspect", "--raw", fmt.Sprintf("docker://%s", imageName)}
}

// getSupportedArchitectures gets the list of supported architectures for a Docker image.
func getSupportedArchitectures(image string) ([]string, error) {
	cmdArgs := GenerateSkopeoInspectCmdArgs(image)
	cmd := exec.Command("skopeo", cmdArgs...)
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var manifest struct {
		Manifests []struct {
			Platform struct {
				Architecture string `json:"architecture"`
			} `json:"platform"`
		} `json:"manifests"`
	}
	if err := json.Unmarshal(output, &manifest); err != nil {
		return nil, err
	}

	var architectures []string
	for _, m := range manifest.Manifests {
		architectures = append(architectures, m.Platform.Architecture)
	}

	// Ensure at least "amd64" is included if no architectures were found
	if len(architectures) == 0 {
		architectures = []string{"amd64"}
	}

	return architectures, nil
}

// getFileSize returns the size of the file at the given path in bytes.
func getFileSize(filePath string) (int64, error) {
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return 0, err
	}
	return fileInfo.Size(), nil
}

func GenerateSkopeoCmdArgs(imageName, targetFilename, architecture string) []string {
	cmdArgs := []string{"copy", "--remove-signatures"}

	// Check and add registry credentials if they are set
	registryUsername, usernameSet := os.LookupEnv("REGISTRY_USERNAME")
	registryPassword, passwordSet := os.LookupEnv("REGISTRY_PASSWORD")

	if usernameSet && passwordSet {
		cmdArgs = append(cmdArgs, "--src-username", registryUsername, "--src-password", registryPassword)
	}

	// Add architecture override if specified
	if architecture != "" {
		cmdArgs = append(cmdArgs, "--override-arch", architecture)
	}

	// Add the rest of the command source image and destination tar
	cmdArgs = append(cmdArgs, fmt.Sprintf("docker://%s", imageName), fmt.Sprintf("docker-archive://%s", targetFilename))

	return cmdArgs
}

// sanitizeImageName replaces slashes and colons in the image name with underscores.
func sanitizeImageName(image string) string {
	return strings.NewReplacer("/", "_", ":", "_").Replace(image)
}
