package main

import (
	"context"
	"log"
	"os/exec"
	"strings"

	"github.com/go-redis/redis/v8"
)

var ctx = context.Background()
var rdb *redis.Client

func main() {
	rdb = redis.NewClient(&redis.Options{
		Addr:     "redis:6379", // Update with your Redis address
		Password: "",           // No password set
		DB:       0,            // Default DB
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

	imageName := redisAnswer[1]
	// Sanitize the image name to create a valid filename
	safeImageName := strings.ReplaceAll(imageName, "/", "_")
	safeImageName = strings.ReplaceAll(safeImageName, ":", "_")
	resultFileName := "/app/reports/" + safeImageName + ".json"

	log.Println("Scanning image:", imageName)
	log.Println("Saving results to:", resultFileName)
	cmd := exec.Command("trivy", "image", "--format", "json", "--output", resultFileName, imageName)
	if err := cmd.Run(); err != nil {
		log.Println("Failed to scan image:", imageName, "Error:", err)
		return
	}

	log.Println("Scan complete for image:", imageName, "Results saved to:", resultFileName)
}
