package main

import (
	"log"

	"github.com/vpereira/trivy_runner/internal/trivy_worker"
)

func main() {
	config := trivy_worker.Config{
		QueueName:       "toscan",
		OpsTotalName:    "scanworker_processed_ops_total",
		OpsTotalHelp:    "Total number of processed operations by the scanworker.",
		ErrorsTotalName: "scanworker_processed_errors_total",
		ErrorsTotalHelp: "Total number of processed errors by the scanworker.",
		ServerPort:      "8081",
	}

	scanWorker, err := trivy_worker.InitializeWorker(config)
	if err != nil {
		log.Fatalf("Failed to initialize worker: %v", err)
	}

	defer scanWorker.Logger.Sync()

	scanWorker.Run()
}
