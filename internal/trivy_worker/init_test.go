package trivy_worker

import (
	"os"
	"testing"

	"github.com/alicebob/miniredis/v2"
)

func TestInitializeWorker(t *testing.T) {
	// Set up environment variables
	os.Setenv("REPORTS_APP_DIR", "/tmp/reports")

	mr, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}

	os.Setenv("REDIS_HOST", mr.Host())
	os.Setenv("REDIS_PORT", mr.Port())

	defer mr.Close()

	// Define a config for the worker
	config := Config{
		QueueName:       "toscan",
		OpsTotalName:    "scanworker_processed_ops_total",
		OpsTotalHelp:    "Total number of processed operations by the scanworker.",
		ErrorsTotalName: "scanworker_processed_errors_total",
		ErrorsTotalHelp: "Total number of processed errors by the scanworker.",
		ServerPort:      "8081",
	}

	// Call InitializeWorker
	worker, err := InitializeWorker(config)

	if err != nil {
		t.Fatalf("Failed to initialize worker: %v", err)
	}

	// Check if components are correctly initialized
	if worker.ReportsAppDir != "/tmp/reports" {
		t.Errorf("Expected ReportsAppDir to be '/tmp/reports', got %s", worker.ReportsAppDir)
	}

	if worker.Logger == nil {
		t.Errorf("Expected Logger not to be nil")
	}

	if worker.SentryNotifier == nil {
		t.Errorf("Expected SentryNotifier not to be nil")
	}

	if worker.Rdb == nil {
		t.Errorf("Expected Rdb to be initialized")
	}
}
