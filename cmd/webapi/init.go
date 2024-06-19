package main

import (
	"log"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/vpereira/trivy_runner/internal/error_handler"
	"github.com/vpereira/trivy_runner/internal/metrics"
	"github.com/vpereira/trivy_runner/internal/sentry"
	"go.uber.org/zap"
)

func init() {
	var err error
	logger, err = zap.NewProduction()
	if err != nil {
		log.Fatal("Failed to create logger:", err)
	}

	sentryNotifier := sentry.NewSentryNotifier()
	if sentryNotifier == nil {
		logger.Error("Failed to create sentry notifier")
	}

	prometheusMetrics = metrics.NewMetrics(
		prometheus.CounterOpts{
			Name: "webapi_processed_ops_total",
			Help: "Total number of processed operations by the webapi.",
		},
		prometheus.CounterOpts{
			Name: "webapi_processed_errors_total",
			Help: "Total number of processed errors by the webapi.",
		},
	)
	prometheusMetrics.Register()

	errorHandler = error_handler.NewErrorHandler(logger, prometheusMetrics.ProcessedErrorsCounter, sentryNotifier)
}
