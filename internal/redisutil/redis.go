package redisutil

import (
	"context"
	"log"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/vpereira/trivy_runner/internal/util"
	"go.uber.org/zap"
)

func InitializeClient() *redis.Client {

	logger, err := zap.NewProduction()

	if err != nil {
		log.Fatal("Failed to create logger:", err)
	}

	redisHost := util.GetEnv("REDIS_HOST", "localhost")
	redisPort := util.GetEnv("REDIS_PORT", "6379")
	redisURL := redisHost + ":" + redisPort

	redisClient := redis.NewClient(&redis.Options{
		Addr:     redisURL,
		Password: "", // No password by default
		DB:       0,  // Default DB
	})

	// Retry configuration
	maxRetries := util.GetEnvAsInt("REDIS_MAX_TRIES", 5)
	retryInterval := time.Duration(util.GetEnvAsInt("REDIS_CONNECTION_INTERVAL_RETRY", 2)) * time.Second

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
