package redisutil

import (
	"log"
	"os"

	"github.com/go-redis/redis/v8"
)

// InitializeClient sets up and returns a new Redis client.
func InitializeClient() *redis.Client {
	redisHost := getEnv("REDIS_HOST", "localhost")
	redisPort := getEnv("REDIS_PORT", "6379")
	redisURL := redisHost + ":" + redisPort

	log.Println("Connecting to Redis at:", redisURL)

	return redis.NewClient(&redis.Options{
		Addr:     redisURL,
		Password: "", // No password by default
		DB:       0,  // Default DB
	})
}

// getEnv retrieves an environment variable or returns a default value.
func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}
