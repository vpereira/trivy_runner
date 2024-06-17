package main

import (
	"log"

	"github.com/vpereira/trivy_runner/internal/skopeo_worker"
	"github.com/vpereira/trivy_runner/internal/util"
)

func main() {
	config := skopeo_worker.Config{
		QueueName:       "topull",
		OpsTotalName:    "pullworker_processed_ops_total",
		OpsTotalHelp:    "Total number of processed operations by the pullworker.",
		ErrorsTotalName: "pullworker_processed_errors_total",
		ErrorsTotalHelp: "Total number of processed errors by the pullworker.",
		ServerPort:      util.GetEnv("PROMETHEUS_EXPORTER_PORT", "8082"),
		MultiArch:       false,
	}

	pullWorker, err := skopeo_worker.InitializeWorker(config)
	if err != nil {
		log.Fatalf("Failed to initialize worker: %v", err)
	}

	defer pullWorker.Logger.Sync()

	pullWorker.Run()
}
