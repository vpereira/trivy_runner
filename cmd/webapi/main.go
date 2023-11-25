package main

import (
	"os"
	"context"
	"encoding/json"
	"log"
	"net/http"

	"github.com/go-redis/redis/v8"                      // Ensure this is in your go.mod
	"github.com/vpereira/trivy_runner/internal/logging" // Adjust the import path as necessary
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


	// Initialize Redis Client
	rdb = redis.NewClient(&redis.Options{
		Addr:     redisURL, // Update with your Redis address
		Password: "",           // No password by default
		DB:       0,            // Default DB
	})

	// Setup HTTP server
	http.Handle("/scan", logging.LoggingMiddleware(http.HandlerFunc(handleScan)))
	log.Println("Server started on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func handleScan(w http.ResponseWriter, r *http.Request) {
	imageName := r.URL.Query().Get("image")
	if imageName == "" {
		http.Error(w, "Image name is required", http.StatusBadRequest)
		return
	}

	// Push the image name to Redis
	err := rdb.LPush(ctx, "topull", imageName).Err()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Respond with the path for the result
	resultPath := "/app/reports/" + imageName + ".json" // Customize as needed
	response := map[string]string{"resultPath": resultPath}
	json.NewEncoder(w).Encode(response)
}
