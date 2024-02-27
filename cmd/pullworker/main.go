package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/redis/go-redis/v9"
	"github.com/vpereira/trivy_runner/internal/airbrake"
	"github.com/vpereira/trivy_runner/internal/redisutil"
	"github.com/vpereira/trivy_runner/pkg/exec_command"
	"go.uber.org/zap"
)

var (
	ctx                 = context.Background()
	rdb                 *redis.Client
	airbrakeNotifier    *airbrake.AirbrakeNotifier
	imagesAppDir        string
	logger              *zap.Logger
	processedOpsCounter = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "pullworker_processed_ops_total",
		Help: "Total number of processed operations by the pullworker.",
	})
	processedErrorsCounter = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "pullworker_processed_errors_total",
		Help: "Total number of processed errors by the pullworker.",
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

	imagesAppDir = redisutil.GetEnv("IMAGES_APP_DIR", "/app/images")

	err = os.MkdirAll(imagesAppDir, os.ModePerm)

	if err != nil {
		logger.Error("Failed to create base directory:", zap.Error(err))
		airbrakeNotifier.NotifyAirbrake(err)
	}

	prometheus.MustRegister(processedOpsCounter)
	prometheus.MustRegister(processedErrorsCounter)

	// Start processing loop
	for {
		processQueue()
	}
}

func processQueue() {
	// Block until an image name is available in the 'topull' queue
	result, err := rdb.BRPopLPush(ctx, "topull", "processing", 0).Result()

	if err != nil {
		logger.Error("Error:", zap.Error(err))
		processedErrorsCounter.Inc()
		airbrakeNotifier.NotifyAirbrake(err)
		return
	}

	targetDir, err := os.MkdirTemp(imagesAppDir, "trivy-scan-*")

	if err != nil {
		logger.Error("Failed to create temp directory:", zap.Error(err))
		processedErrorsCounter.Inc()
		airbrakeNotifier.NotifyAirbrake(err)
		return
	}

	imageName := result

	if imageName == "" {
		logger.Error("No image name found in queue")
		processedErrorsCounter.Inc()
		return
	}

	logger.Info("Processing image: ", zap.String("imageName", imageName))
	logger.Info("Target directory: ", zap.String("targetDir", targetDir))

	cmdArgs := GenerateSkopeoCmdArgs(imageName, targetDir)
	cmd := exec_command.NewExecShellCommander("skopeo", cmdArgs...)

	if _, err := cmd.Output(); err != nil {
		logger.Error("Failed to copy image:", zap.String("image", imageName), zap.Error(err))
		processedErrorsCounter.Inc()
		airbrakeNotifier.NotifyAirbrake(err)
		return
	}

	// Move the image name from 'processing' to 'toscan'
	_, err = rdb.LRem(ctx, "processing", 1, imageName).Result()
	if err != nil {
		logger.Error("Error removing image from processing queue:", zap.Error(err))
		processedErrorsCounter.Inc()
		airbrakeNotifier.NotifyAirbrake(err)
		return
	}

	toScanString := fmt.Sprintf("%s|%s", imageName, targetDir)

	logger.Info("Pushing image to toscan queue:", zap.String("image", toScanString))

	err = rdb.LPush(ctx, "toscan", toScanString).Err()

	if err != nil {
		logger.Error("Error pushing image to toscan queue:", zap.Error(err))
		processedErrorsCounter.Inc()
		airbrakeNotifier.NotifyAirbrake(err)
		return
	}

	processedOpsCounter.Inc()
}

// GenerateSkopeoCmdArgs generates the command line arguments for the skopeo command based on environment variables and input parameters.
func GenerateSkopeoCmdArgs(imageName, targetDir string) []string {
	cmdArgs := []string{"copy", "--remove-signatures"}

	// Check and add registry credentials if they are set
	registryUsername, usernameSet := os.LookupEnv("REGISTRY_USERNAME")
	registryPassword, passwordSet := os.LookupEnv("REGISTRY_PASSWORD")

	if usernameSet && passwordSet {
		cmdArgs = append(cmdArgs, "--dest-username", registryUsername, "--dest-password", registryPassword)
	}

	// Add the rest of the command
	cmdArgs = append(cmdArgs, fmt.Sprintf("docker://%s", imageName), "oci://"+targetDir)

	return cmdArgs
}
