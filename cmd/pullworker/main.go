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
)

var ctx = context.Background()
var rdb *redis.Client
var airbrakeNotifier *airbrake.AirbrakeNotifier
var imagesAppDir string

func main() {

	rdb = redisutil.InitializeClient()

	imagesAppDir = redisutil.GetEnv("IMAGES_APP_DIR", "/app/images")

	err := os.MkdirAll(imagesAppDir, os.ModePerm)

	if err != nil {
		log.Fatal("Failed to create base directory:", err)
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
		log.Println("Error:", err)
		airbrakeNotifier.NotifyAirbrake(err)
		return
	}

	targetDir, err := os.MkdirTemp(imagesAppDir, "trivy-scan-*")

	if err != nil {
		log.Fatal("Failed to create temp directory:", err)
		airbrakeNotifier.NotifyAirbrake(err)
	}

	imageName := result

	log.Println("Processing image: ", imageName)
	log.Println("Target directory: ", targetDir)

	// Equivalent of `skopeo copy --remove-signatures "$image" "oci://${target_dir}"`
	cmd := exec.Command("skopeo", "copy", "--remove-signatures", fmt.Sprintf("docker://%s", imageName), "oci://"+targetDir)

	if err := cmd.Run(); err != nil {
		log.Println("Failed to copy image:", imageName, "Error:", err)
		airbrakeNotifier.NotifyAirbrake(err)
		return
	}

	// Move the image name from 'processing' to 'toscan'
	_, err = rdb.LRem(ctx, "processing", 1, imageName).Result()
	if err != nil {
		log.Println("Error removing image from processing queue:", err)
		airbrakeNotifier.NotifyAirbrake(err)
		return
	}

	toScanString := fmt.Sprintf("%s|%s", imageName, targetDir)

	log.Println("Pushing image to toscan queue:", toScanString)

	err = rdb.LPush(ctx, "toscan", toScanString).Err()
	if err != nil {
		log.Println("Error pushing image to toscan queue:", err)
		airbrakeNotifier.NotifyAirbrake(err)
	}
}
