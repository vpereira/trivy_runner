package main

import (
	"log"

	"github.com/vpereira/trivy_runner/internal/trivy_worker"
)

func main() {
	sbomWorker, err := trivy_worker.InitializeWorker(
		"tosbom",
		"sbomworker_processed_ops_total",
		"Total number of processed operations by the sbomworker.",
		"sbomworker_processed_errors_total",
		"Total number of processed errors by the sbomworker.",
		"8085",
	)
	if err != nil {
		log.Fatalf("Failed to initialize worker: %v", err)
	}

	defer sbomWorker.Logger.Sync()

	sbomWorker.Run()
}
