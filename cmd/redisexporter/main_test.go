package main

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/redis/go-redis/v9"
)

func init() {
	// Reset the global Prometheus registry before each test
	prometheus.DefaultRegisterer = prometheus.NewRegistry()
}

func TestGetQueuesFromEnv(t *testing.T) {
	tests := []struct {
		envValue string
		expected map[string]string
	}{
		{
			envValue: "queueA queueB queueC",
			expected: map[string]string{
				"queueA": "",
				"queueB": "",
				"queueC": "",
			},
		},
		{
			envValue: "queue1 queue2",
			expected: map[string]string{
				"queue1": "",
				"queue2": "",
			},
		},
		{
			envValue: "",
			expected: map[string]string{},
		},
	}

	for _, tt := range tests {
		// Set environment variable
		t.Setenv("REDIS_QUEUES", tt.envValue)

		// Get queues from environment
		result := getQueuesFromEnv()

		// Compare result with expected value
		if len(result) != len(tt.expected) {
			t.Fatalf("expected %v queues, got %v", len(tt.expected), len(result))
		}

		for queue := range tt.expected {
			if _, ok := result[queue]; !ok {
				t.Errorf("expected queue %v to be in the result", queue)
			}
		}
	}
}

func TestUpdateQueueMetrics(t *testing.T) {
	// Start a miniredis server
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("Failed to start miniredis: %v", err)
	}
	defer mr.Close()

	// Populate miniredis with some data
	mr.Lpush("queueA", "item1")
	mr.Lpush("queueA", "item1")
	mr.Lpush("queueA", "item1")
	mr.Lpush("queueB", "item1")
	mr.Lpush("queueB", "item1")

	// Create a real Redis client connected to miniredis
	rdb := redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
	})

	initMetrics() // Initialize the metrics

	config := Config{
		rdb:      rdb,
		Hostname: "localhost",
		Queues:   map[string]string{"queueA": "", "queueB": ""},
	}

	// Create a context to control the lifecycle of the goroutine
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Run the metrics update in a goroutine
	go updateQueueMetrics(ctx, config)

	// Allow some time for the metrics to be updated
	time.Sleep(1 * time.Second)

	// Validate the metrics
	metric := testutil.ToFloat64(redisQueueLength.WithLabelValues("localhost", "queueA"))
	if metric != 3 {
		t.Errorf("Expected metric value 3 for queueA, got %v", metric)
	}

	metric = testutil.ToFloat64(redisQueueLength.WithLabelValues("localhost", "queueB"))
	if metric != 2 {
		t.Errorf("Expected metric value 2 for queueB, got %v", metric)
	}
}
