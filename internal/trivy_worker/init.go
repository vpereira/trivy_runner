package trivy_worker

import (
	"context"
	"log"
	"os"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/vpereira/trivy_runner/internal/airbrake"
	"github.com/vpereira/trivy_runner/internal/error_handler"
	"github.com/vpereira/trivy_runner/internal/metrics"
	"github.com/vpereira/trivy_runner/internal/redisutil"
	"github.com/vpereira/trivy_runner/internal/sentry"
	"github.com/vpereira/trivy_runner/pkg/exec_command"
	"go.uber.org/zap"
)

func InitializeWorker(queueName string, opsTotalName string, opsTotalHelp string, errorsTotalName string, errorsTotalHelp string, serverPort string) (*TrivyWorker, error) {
	var err error
	logger, err := zap.NewProduction()

	if err != nil {
		log.Fatal("Failed to create logger:", err)
		return nil, err
	}

	airbrakeNotifier := airbrake.NewAirbrakeNotifier()
	if airbrakeNotifier == nil {
		logger.Error("Failed to create airbrake notifier")
		return nil, err
	}

	sentryNotifier := sentry.NewSentryNotifier()
	if sentryNotifier == nil {
		logger.Error("Failed to create sentry notifier")
		return nil, err
	}

	commandExecutionHistogram := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "trivy_execution_duration_seconds",
		Help:    "Duration of trivy execution.",
		Buckets: prometheus.LinearBuckets(0, 5, 20),
	}, []string{"trivy"})

	prometheusMetrics := metrics.NewMetrics(
		prometheus.CounterOpts{
			Name: opsTotalName,
			Help: opsTotalHelp,
		},
		prometheus.CounterOpts{
			Name: errorsTotalName,
			Help: errorsTotalHelp,
		},
		commandExecutionHistogram,
	)

	reportsAppDir := os.Getenv("REPORTS_APP_DIR")
	if reportsAppDir == "" {
		reportsAppDir = "/app/reports"
	}

	prometheusMetrics.Register()

	errorHandler := error_handler.NewErrorHandler(logger, prometheusMetrics.ProcessedErrorsCounter, airbrakeNotifier, sentryNotifier)

	rdb := redisutil.InitializeClient()

	err = os.MkdirAll(reportsAppDir, os.ModePerm)
	if err != nil {
		logger.Error("Failed to create base directory:", zap.String("dir", reportsAppDir), zap.Error(err))
		airbrakeNotifier.NotifyAirbrake(err)
		return nil, err
	}

	go metrics.StartMetricsServer(serverPort)

	return &TrivyWorker{
		Ctx:                       context.Background(),
		Rdb:                       rdb,
		SentryNotifier:            sentryNotifier,
		ErrorHandler:              errorHandler,
		Logger:                    logger,
		ReportsAppDir:             reportsAppDir,
		CommandExecutionHistogram: commandExecutionHistogram,
		ProcessQueueName:          queueName,
		CommandFactory:            exec_command.NewExecShellCommander,
		ProcessFunc:               ProcessQueue,
	}, nil
}
