package main

import (
	"os"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/redis/go-redis/v9"
	"github.com/vpereira/trivy_runner/internal/metrics"
	"github.com/vpereira/trivy_runner/internal/util"
	"go.uber.org/zap"
)

func TestProcessQueue(t *testing.T) {
	logger, _ = zap.NewProduction()
	// Mock Redis server
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	defer mr.Close()

	os.Setenv("REDIS_HOST", mr.Host())
	os.Setenv("REDIS_PORT", mr.Port())
	os.Setenv("IMAGES_APP_DIR", "/tmp")

	// Initialize Redis client and push a mock entry
	rdb = redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
	})
	_, err = rdb.RPush(ctx, "getsize", "registry.suse.com/bci/bci-busybox:latest").Result()

	if err != nil {
		t.Fatal(err)
	}
	imagesAppDir = util.GetEnv("IMAGES_APP_DIR", "/app/images")

	prometheusMetrics = metrics.NewMetrics(
		prometheus.CounterOpts{
			Name: "pullworker_processed_ops_total",
			Help: "Total number of processed operations by the pullworker.",
		},
		prometheus.CounterOpts{
			Name: "pullworker_processed_errors_total",
			Help: "Total number of processed errors by the pullworker.",
		},
		commandExecutionHistogram,
	)

	prometheusMetrics.Register()

	// Ensure to unregister metrics to avoid pollution across tests
	defer prometheus.Unregister(prometheusMetrics.ProcessedOpsCounter)
	defer prometheus.Unregister(prometheusMetrics.ProcessedErrorsCounter)
	defer prometheus.Unregister(commandExecutionHistogram)

	processQueue()
}
