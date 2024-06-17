package main

import (
	"log"

	"github.com/vpereira/trivy_runner/internal/skopeo_worker"
	"github.com/vpereira/trivy_runner/internal/util"
)

func main() {
	config := skopeo_worker.Config{
		QueueName:       "getsize",
		OpsTotalName:    "getsize_worker_processed_ops_total",
		OpsTotalHelp:    "Total number of processed operations by the getsize_worker.",
		ErrorsTotalName: "getsize_worker_processed_errors_total",
		ErrorsTotalHelp: "Total number of processed errors by the getsize_worker.",
		ServerPort:      util.GetEnv("PROMETHEUS_EXPORTER_PORT", "8084"),
		MultiArch:       true, // Set to true for multi-architecture support
	}

	getSizeWorker, err := skopeo_worker.InitializeWorker(config)
	if err != nil {
		log.Fatalf("Failed to initialize worker: %v", err)
	}

	defer getSizeWorker.Logger.Sync()

	getSizeWorker.Run()
}
