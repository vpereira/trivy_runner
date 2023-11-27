package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"

	"github.com/go-redis/redis/v8"
)

var ctx = context.Background()
var rdb *redis.Client

func main() {
	redisHost := os.Getenv("REDIS_HOST")
	if redisHost == "" {
		redisHost = "localhost" // Default value if not set
	}

	redisPort := os.Getenv("REDIS_PORT")
	if redisPort == "" {
		redisPort = "6379" // Default value if not set
	}

	redisURL := redisHost + ":" + redisPort
	log.Println("Connecting to Redis at:", redisURL)

	rdb = redis.NewClient(&redis.Options{
		Addr:     redisURL, // Update with your Redis address
		Password: "",       // No password set
		DB:       0,        // Default DB
	})

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
		return
	}

	targetDir, err := os.MkdirTemp("/app/images", "trivy-scan-*")

	if err != nil {
		log.Fatal("Failed to create temp directory:", err)
	}

	imageName := result

	// Equivalent of `skopeo copy --remove-signatures "$image" "oci://${target_dir}"`
	cmd := exec.Command("skopeo", "copy", "--remove-signatures", fmt.Sprintf("docker://%s", imageName), "oci://"+targetDir)

	if err := cmd.Run(); err != nil {
		log.Println("Failed to copy image:", imageName, "Error:", err)
		return
	}

	// Move the image name from 'processing' to 'toscan'
	_, err = rdb.LRem(ctx, "processing", 1, imageName).Result()
	if err != nil {
		log.Println("Error removing image from processing queue:", err)
		return
	}

	toScanString := fmt.Sprintf("%s|%s", imageName, targetDir)

	err = rdb.LPush(ctx, "toscan", toScanString).Err()
	if err != nil {
		log.Println("Error pushing image to toscan queue:", err)
	}
}
