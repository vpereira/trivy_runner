package skopeo_worker

import (
	"os"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/prometheus/client_golang/prometheus"
)

func TestInitializeWorker(t *testing.T) {

	// Set up a miniredis instance
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	defer mr.Close()

	// Set up environment variables
	os.Setenv("REDIS_HOST", mr.Host())
	os.Setenv("REDIS_PORT", mr.Port())
	os.Setenv("SKIP_METRICS_SERVER", "true")
	os.Setenv("IMAGES_APP_DIR", "/tmp/images")

	// Define a config for the worker
	config := Config{
		QueueName:       "topull",
		OpsTotalName:    "pullworker_processed_ops_total",
		OpsTotalHelp:    "Total number of processed operations by the pullworker.",
		ErrorsTotalName: "pullworker_processed_errors_total",
		ErrorsTotalHelp: "Total number of processed errors by the pullworker.",
		ServerPort:      "8082",
	}

	// Call InitializeWorker
	worker, err := InitializeWorker(config)
	// Ensure to unregister metrics to avoid pollution across tests
	defer prometheus.Unregister(worker.CommandExecutionHistogram)
	defer prometheus.Unregister(worker.PrometheusMetrics.ProcessedOpsCounter)
	defer prometheus.Unregister(worker.PrometheusMetrics.ProcessedErrorsCounter)

	if err != nil {
		t.Fatalf("Failed to initialize worker: %v", err)
	}

	// Check if components are correctly initialized
	if worker.ImagesAppDir != "/tmp/images" {
		t.Errorf("Expected ImagesAppDir to be '/tmp/images', got %s", worker.ImagesAppDir)
	}

	if worker.SentryNotifier == nil {
		t.Errorf("Expected SentryNotifier to be the mocked notifier")
	}

	if worker.Rdb == nil {
		t.Errorf("Expected Rdb to be initialized")
	}
}
