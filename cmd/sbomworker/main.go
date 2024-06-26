package main

import (
	"log"

	"github.com/vpereira/trivy_runner/internal/trivy_worker"
	"github.com/vpereira/trivy_runner/internal/util"
)

func main() {
	config := trivy_worker.Config{
		QueueName:       "tosbom",
		OpsTotalName:    "sbomworker_processed_ops_total",
		OpsTotalHelp:    "Total number of processed operations by the sbomworker.",
		ErrorsTotalName: "sbomworker_processed_errors_total",
		ErrorsTotalHelp: "Total number of processed errors by the sbomworker.",
		ServerPort:      util.GetEnv("PROMETHEUS_EXPORTER_PORT", "8085"),
		RunSBOMOnly:     true,
	}

	sbomWorker, err := trivy_worker.InitializeWorker(config)
	if err != nil {
		log.Fatalf("Failed to initialize worker: %v", err)
	}

	defer sbomWorker.Logger.Sync()

	sbomWorker.Run()
}
