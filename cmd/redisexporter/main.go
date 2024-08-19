package main

import (
	"context"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/redis/go-redis/v9"
	"github.com/vpereira/trivy_runner/internal/metrics"
	"github.com/vpereira/trivy_runner/internal/redisutil"
	"go.uber.org/zap"
)

type Config struct {
	rdb      *redis.Client
	Hostname string
	Queues   map[string]string
}

var (
	logger, _        = zap.NewProduction()
	redisQueueLength *prometheus.GaugeVec
	once             sync.Once
)

func initMetrics() {
	once.Do(func() {
		redisQueueLength = promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "redis_queue_length",
				Help: "Length of Redis queues",
			},
			[]string{"host", "queue_name"},
		)
	})
}

func getQueuesFromEnv() map[string]string {
	queuesEnv := os.Getenv("REDIS_QUEUES")
	queues := make(map[string]string)

	if queuesEnv != "" {
		queueList := strings.Fields(queuesEnv) // Split the string by whitespace
		for _, queueName := range queueList {
			queues[queueName] = "" // Set each queue name with an empty string as the value
		}
	}

	return queues
}

func updateQueueMetrics(ctx context.Context, config Config) {
	for {
		select {
		case <-ctx.Done():
			logger.Info("Shutting down updateQueueMetrics goroutine")
			return
		default:
			for queueName := range config.Queues {
				length, err := config.rdb.LLen(ctx, queueName).Result()
				if err != nil {
					logger.Error("Error getting length of queue", zap.String("queue", queueName), zap.Error(err))
					continue
				}
				redisQueueLength.WithLabelValues(config.Hostname, queueName).Set(float64(length))
			}
			time.Sleep(10 * time.Second) // Update every 10 seconds
		}
	}
}

func main() {
	defer logger.Sync()

	rdb := redisutil.InitializeClient()
	queues := getQueuesFromEnv()
	hostName, _ := os.Hostname()

	initMetrics()

	config := Config{
		rdb:      rdb,
		Queues:   queues,
		Hostname: hostName,
	}

	// Metrics are already registered inside initMetrics() with promauto

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start the metrics update in a separate goroutine
	go updateQueueMetrics(ctx, config)
	go metrics.StartMetricsServer("8086")

	// Graceful shutdown on interrupt signal
	stopChan := make(chan os.Signal, 1)
	signal.Notify(stopChan, syscall.SIGINT, syscall.SIGTERM)

	<-stopChan
	logger.Info("Received shutdown signal, shutting down gracefully...")
	cancel()                    // Signal all goroutines to finish
	time.Sleep(1 * time.Second) // Give goroutines time to shutdown
}
