package main

import (
	"log"

	"github.com/vpereira/trivy_runner/internal/trivy_worker"
)

func main() {
	scanWorker, err := trivy_worker.InitializeWorker(
		"toscan",
		"scanworker_processed_ops_total",
		"Total number of processed operations by the scanworker.",
		"scanworker_processed_errors_total",
		"Total number of processed errors by the scanworker.",
		"8081",
	)
	if err != nil {
		log.Fatalf("Failed to initialize worker: %v", err)
	}

	defer scanWorker.Logger.Sync()

	scanWorker.Run()
}
