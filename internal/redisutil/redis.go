package redisutil

import (
	"context"
	"log"
	"os"

	"github.com/redis/go-redis/v9"
)

// InitializeClient sets up and returns a new Redis client.
func InitializeClient() *redis.Client {
	redisHost := getEnv("REDIS_HOST", "localhost")
	redisPort := getEnv("REDIS_PORT", "6379")
	redisURL := redisHost + ":" + redisPort

	log.Println("Connecting to Redis at:", redisURL)

	redisClient := redis.NewClient(&redis.Options{
		Addr:     redisURL,
		Password: "", // No password by default
		DB:       0,  // Default DB
	})

	// Perform a ping test to check connection
	_, err := redisClient.Ping(context.Background()).Result()
	if err != nil {
		log.Fatalf("Failed to connect to Redis at %s: %v", redisURL, err)
	}

	log.Printf("Successfully connected to Redis at %s", redisURL)
	return redisClient
}

// getEnv retrieves an environment variable or returns a default value.
func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}
