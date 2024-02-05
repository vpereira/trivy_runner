package redisutil

import (
	"context"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

func InitializeClient() *redis.Client {

	logger, err := zap.NewProduction()

	if err != nil {
		log.Fatal("Failed to create logger:", err)
	}

	redisHost := GetEnv("REDIS_HOST", "localhost")
	redisPort := GetEnv("REDIS_PORT", "6379")
	redisURL := redisHost + ":" + redisPort

	redisClient := redis.NewClient(&redis.Options{
		Addr:     redisURL,
		Password: "", // No password by default
		DB:       0,  // Default DB
	})

	// Retry configuration
	maxRetries := GetEnvAsInt("REDIS_MAX_TRIES", 5)
	retryInterval := time.Duration(GetEnvAsInt("REDIS_CONNECTION_INTERVAL_RETRY", 2)) * time.Second

	for i := 0; i < maxRetries; i++ {
		_, err := redisClient.Ping(context.Background()).Result()
		if err != nil {
			logger.Info("Redis Connection Failed:", zap.Int("try", i+1), zap.String("redis_url", redisURL), zap.Error(err))
			log.Printf("Attempt %d: Failed to connect to Redis at %s: %v", i+1, redisURL, err)
			time.Sleep(retryInterval)
			continue
		}

		log.Printf("Successfully connected to Redis at %s", redisURL)
		return redisClient
	}

	log.Fatalf("Failed to connect to Redis after %d attempts", maxRetries)
	return nil
}

// GetEnv retrieves an environment variable or returns a default value.
// TODO move this to a common package
func GetEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}

// GetEnvAsInt gets an environment variable as an integer, with a fallback default value.
// TODO move this to a common package
func GetEnvAsInt(key string, fallback int) int {
	valueStr := os.Getenv(key)
	if value, err := strconv.Atoi(valueStr); err == nil {
		return value
	}
	return fallback
}
