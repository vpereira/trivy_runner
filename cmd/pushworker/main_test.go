package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/redis/go-redis/v9"
	"github.com/vpereira/trivy_runner/internal/metrics"
	"github.com/vpereira/trivy_runner/internal/pushworker"
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

	// Mock webhook server
	webhookServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		result := pushworker.NewPayload()
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &result)

		if result.Image != "registry.suse.com/bci/bci-busybox:latest" {
			t.Errorf("Unexpected image name: %s", result.Image)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		if result.Operation != "scan" {
			t.Errorf("Unexpected image name: %s", result.Image)
			w.WriteHeader(http.StatusBadRequest)
		}

		if result.Results == nil {
			t.Errorf("Unexpected empty results: %+v", result.Results)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		w.WriteHeader(http.StatusOK)
	}))

	defer webhookServer.Close()

	// Set environment variables
	os.Setenv("WEBHOOK_URL", webhookServer.URL)
	os.Setenv("REDIS_HOST", mr.Host())
	os.Setenv("REDIS_PORT", mr.Port())

	// Initialize Redis client and push a mock entry
	rdb = redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
	})

	var dto pushworker.DTO = pushworker.NewScanDTO()
	dto.Image = "registry.suse.com/bci/bci-busybox:latest"
	dto.ResultFilePath = "./test_reports/registry.suse.com_bci_bci-busybox_latest.json"
	content, err := dto.ToJSON()
	if err != nil {
		t.Fatal(err)
	}

	_, err = rdb.RPush(ctx, "topush", string(content)).Result()
	if err != nil {
		t.Fatal(err)
	}

	prometheusMetrics = metrics.NewMetrics(
		prometheus.CounterOpts{
			Name: "pushworker_processed_ops_total",
			Help: "Total number of processed operations by the pushworker.",
		},
		prometheus.CounterOpts{
			Name: "pushworker_processed_errors_total",
			Help: "Total number of processed errors by the pushworker.",
		},
	)

	prometheusMetrics.Register()

	// Ensure to unregister metrics to avoid pollution across tests
	defer prometheus.Unregister(prometheusMetrics.ProcessedOpsCounter)
	defer prometheus.Unregister(prometheusMetrics.ProcessedErrorsCounter)

	// Call the function to process the queue
	processQueue(webhookServer.URL)

	// Allow some time for the HTTP request to complete
	time.Sleep(time.Second)
}

func TestProcessQueueForImageSize(t *testing.T) {
	logger, _ = zap.NewProduction()
	// Mock Redis server
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	defer mr.Close()

	// Mock webhook server
	webhookServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		result := pushworker.NewPayload()
		body, _ := io.ReadAll(r.Body)

		_ = json.Unmarshal(body, &result)

		if result.Operation != "get-uncompressed-size" {
			t.Errorf("Unexpected image name: %s", result.Image)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		if result.Image != "registry.suse.com/bci/dotnet-sdk:7.0" {
			t.Errorf("Unexpected image name: %s", result.Image)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		if gotSize := result.Sizes["amd64"]; gotSize != 760144384 {
			t.Errorf("Unexpected image size: %+v", gotSize)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		w.WriteHeader(http.StatusOK)
	}))

	defer webhookServer.Close()

	// Set environment variables
	os.Setenv("WEBHOOK_URL", webhookServer.URL)
	os.Setenv("REDIS_HOST", mr.Host())
	os.Setenv("REDIS_PORT", mr.Port())

	// Initialize Redis client and push a mock entry
	rdb = redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
	})

	var dto pushworker.DTO = pushworker.NewGetSizeDTO()
	dto.Image = "registry.suse.com/bci/dotnet-sdk:7.0"
	dto.Sizes["amd64"] = 760144384

	content, err := dto.ToJSON()
	if err != nil {
		t.Fatal(err)
	}

	_, err = rdb.RPush(ctx, "topush", string(content)).Result()
	if err != nil {
		t.Fatal(err)
	}

	prometheusMetrics = metrics.NewMetrics(
		prometheus.CounterOpts{
			Name: "pushworker_processed_ops_total",
			Help: "Total number of processed operations by the pushworker.",
		},
		prometheus.CounterOpts{
			Name: "pushworker_processed_errors_total",
			Help: "Total number of processed errors by the pushworker.",
		},
	)

	prometheusMetrics.Register()

	// Ensure to unregister metrics to avoid pollution across tests
	defer prometheus.Unregister(prometheusMetrics.ProcessedOpsCounter)
	defer prometheus.Unregister(prometheusMetrics.ProcessedErrorsCounter)

	// Call the function to process the queue
	processQueue(webhookServer.URL)

	// Allow some time for the HTTP request to complete
	time.Sleep(time.Second)
}
