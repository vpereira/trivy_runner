package trivy_worker

import (
	"context"
	"log"
	"os"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/vpereira/trivy_runner/internal/error_handler"
	"github.com/vpereira/trivy_runner/internal/metrics"
	"github.com/vpereira/trivy_runner/internal/redisutil"
	"github.com/vpereira/trivy_runner/internal/sentry"
	"github.com/vpereira/trivy_runner/pkg/exec_command"
	"go.uber.org/zap"
)

func InitializeWorker(config Config) (*TrivyWorker, error) {
	var err error
	logger, err := zap.NewProduction()

	if err != nil {
		log.Fatal("Failed to create logger:", err)
	}

	sentryNotifier := sentry.NewSentryNotifier()
	if sentryNotifier == nil {
		logger.Error("Failed to create sentry notifier")
	}

	commandExecutionHistogram := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "trivy_execution_duration_seconds",
		Help:    "Duration of trivy execution.",
		Buckets: prometheus.LinearBuckets(0, 5, 20),
	}, []string{"trivy"})

	prometheusMetrics := metrics.NewMetrics(
		prometheus.CounterOpts{
			Name: config.OpsTotalName,
			Help: config.OpsTotalHelp,
		},
		prometheus.CounterOpts{
			Name: config.ErrorsTotalName,
			Help: config.ErrorsTotalHelp,
		},
		commandExecutionHistogram,
	)

	reportsAppDir := os.Getenv("REPORTS_APP_DIR")
	if reportsAppDir == "" {
		reportsAppDir = "/app/reports"
	}

	prometheusMetrics.Register()

	errorHandler := error_handler.NewErrorHandler(logger, prometheusMetrics.ProcessedErrorsCounter, sentryNotifier)

	rdb := redisutil.InitializeClient()

	err = os.MkdirAll(reportsAppDir, os.ModePerm)
	if err != nil {
		logger.Error("Failed to create base directory:", zap.String("dir", reportsAppDir), zap.Error(err))
		errorHandler.Handle(err)
	}

	if os.Getenv("SKIP_METRICS_SERVER") != "true" {
		go metrics.StartMetricsServer(config.ServerPort)
	}

	return &TrivyWorker{
		Ctx:                       context.Background(),
		Rdb:                       rdb,
		SentryNotifier:            sentryNotifier,
		ErrorHandler:              errorHandler,
		Logger:                    logger,
		ReportsAppDir:             reportsAppDir,
		CommandExecutionHistogram: commandExecutionHistogram,
		PrometheusMetrics:         prometheusMetrics,
		ProcessQueueName:          config.QueueName,
		CommandFactory:            exec_command.NewExecShellCommander,
		ProcessFunc:               ProcessQueue,
	}, nil
}
