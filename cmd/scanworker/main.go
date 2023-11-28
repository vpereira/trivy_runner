package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"

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
	// Block until an image name is available in the 'toscan' queue
	redisAnswer, err := rdb.BRPop(ctx, 0, "toscan").Result()
	if err != nil {
		log.Println("Error:", err)
		return
	}

	// Split the answer
	// [toscan registry.suse.com/bci/bci-busybox:latest|/app/images/trivy-scan-1918888852]
	parts := strings.Split(redisAnswer[1], "|")
	if len(parts) != 2 {
		log.Println("Error: invalid format in Redis answer")
		return
	}

	imageName := parts[0]
	targetDir := parts[1]

	// Delete the image when we're done
	defer os.RemoveAll(targetDir)

	// Sanitize the image name to create a valid filename
	safeImageName := strings.ReplaceAll(imageName, "/", "_")
	safeImageName = strings.ReplaceAll(safeImageName, ":", "_")
	resultFileName := "/app/reports/" + safeImageName + ".json"

	log.Println("Scanning image:", imageName)
	log.Println("Saving results to:", resultFileName)

	cmd := exec.Command("trivy", "image", "--format", "json", "--output", resultFileName, "--input", targetDir)
	if err := cmd.Run(); err != nil {
		log.Println("Failed to scan image:", imageName, "Error:", err)
		return
	}
	log.Println("Scan complete for image:", imageName, "Results saved to:", resultFileName)

	if os.Getenv("PUSH_TO_CATALOG") != "" {
		err = rdb.LPush(ctx, "topush", fmt.Sprintf("%s|%s", imageName, resultFileName)).Err()
		if err != nil {
			log.Println("Error pushing image to toscan queue:", err)
		}
	}
}
