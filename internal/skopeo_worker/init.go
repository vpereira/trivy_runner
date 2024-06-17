package skopeo_worker

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

func InitializeWorker(config Config) (*SkopeoWorker, error) {
	var err error
	logger, err := zap.NewProduction()

	if err != nil {
		log.Fatal("Failed to create logger:", err)
	}

	airbrakeNotifier := airbrake.NewAirbrakeNotifier()
	if airbrakeNotifier == nil {
		logger.Error("Failed to create airbrake notifier")
	}

	sentryNotifier := sentry.NewSentryNotifier()
	if sentryNotifier == nil {
		logger.Error("Failed to create sentry notifier")
	}

	commandExecutionHistogram := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "skopeo_execution_duration_seconds",
		Help:    "Duration of skopeo execution.",
		Buckets: prometheus.LinearBuckets(0, 5, 20),
	}, []string{"skopeo"})

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

	imagesAppDir := os.Getenv("IMAGES_APP_DIR")
	if imagesAppDir == "" {
		imagesAppDir = "/app/images"
	}

	prometheusMetrics.Register()

	errorHandler := error_handler.NewErrorHandler(logger, prometheusMetrics.ProcessedErrorsCounter, airbrakeNotifier, sentryNotifier)

	rdb := redisutil.InitializeClient()

	err = os.MkdirAll(imagesAppDir, os.ModePerm)
	if err != nil {
		logger.Error("Failed to create base directory:", zap.String("dir", imagesAppDir), zap.Error(err))
		airbrakeNotifier.NotifyAirbrake(err)
	}

	if os.Getenv("SKIP_METRICS_SERVER") != "true" {
		go metrics.StartMetricsServer(config.ServerPort)
	}

	return &SkopeoWorker{
		Ctx:                       context.Background(),
		Rdb:                       rdb,
		SentryNotifier:            sentryNotifier,
		ErrorHandler:              errorHandler,
		Logger:                    logger,
		ImagesAppDir:              imagesAppDir,
		CommandExecutionHistogram: commandExecutionHistogram,
		PrometheusMetrics:         prometheusMetrics,
		ProcessQueueName:          config.QueueName,
		MultiArch:                 config.MultiArch,
		CommandFactory:            exec_command.NewExecShellCommander,
		ProcessFunc:               ProcessQueue,
	}, nil
}
