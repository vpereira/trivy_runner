package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"

	"github.com/redis/go-redis/v9"
	"github.com/vpereira/trivy_runner/internal/airbrake"
	"github.com/vpereira/trivy_runner/internal/redisutil"
	"go.uber.org/zap"
)

var ctx = context.Background()
var rdb *redis.Client
var airbrakeNotifier *airbrake.AirbrakeNotifier
var imagesAppDir string
var logger *zap.Logger

func main() {

	logger, err := zap.NewProduction()

	if err != nil {
		log.Fatal("Failed to create logger:", err)
	}

	defer logger.Sync()

	rdb = redisutil.InitializeClient()

	imagesAppDir = redisutil.GetEnv("IMAGES_APP_DIR", "/app/images")

	err = os.MkdirAll(imagesAppDir, os.ModePerm)

	if err != nil {
		logger.Error("Failed to create base directory:", zap.Error(err))
		airbrakeNotifier.NotifyAirbrake(err)
	}

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
		airbrakeNotifier.NotifyAirbrake(err)
		return
	}

	targetDir, err := os.MkdirTemp(imagesAppDir, "trivy-scan-*")

	if err != nil {
		logger.Error("Failed to create temp directory:", zap.Error(err))
		airbrakeNotifier.NotifyAirbrake(err)
	}

	imageName := result

	logger.Info("Processing image: ", zap.String("imageName", imageName))
	logger.Info("Target directory: ", zap.String("targetDir", targetDir))

	// Equivalent of `skopeo copy --remove-signatures "$image" "oci://${target_dir}"`
	cmd := exec.Command("skopeo", "copy", "--remove-signatures", fmt.Sprintf("docker://%s", imageName), "oci://"+targetDir)

	if err := cmd.Run(); err != nil {
		logger.Error("Failed to copy image:", zap.String("image", imageName), zap.Error(err))
		airbrakeNotifier.NotifyAirbrake(err)
		return
	}

	// Move the image name from 'processing' to 'toscan'
	_, err = rdb.LRem(ctx, "processing", 1, imageName).Result()
	if err != nil {
		logger.Error("Error removing image from processing queue:", zap.Error(err))
		airbrakeNotifier.NotifyAirbrake(err)
		return
	}

	toScanString := fmt.Sprintf("%s|%s", imageName, targetDir)

	logger.Info("Pushing image to toscan queue:", zap.String("image", toScanString))

	err = rdb.LPush(ctx, "toscan", toScanString).Err()

	if err != nil {
		logger.Error("Error pushing image to toscan queue:", zap.Error(err))
		airbrakeNotifier.NotifyAirbrake(err)
	}
}
