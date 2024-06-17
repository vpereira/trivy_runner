package skopeo_worker

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/redis/go-redis/v9"
	"github.com/vpereira/trivy_runner/internal/error_handler"
	"github.com/vpereira/trivy_runner/internal/metrics"
	"github.com/vpereira/trivy_runner/internal/sentry"
	"github.com/vpereira/trivy_runner/internal/skopeo"
	"github.com/vpereira/trivy_runner/internal/util"
	"github.com/vpereira/trivy_runner/pkg/exec_command"
	"go.uber.org/zap"
)

type SkopeoWorker struct {
	Ctx                       context.Context
	Rdb                       *redis.Client
	SentryNotifier            sentry.Notifier
	ErrorHandler              *error_handler.ErrorHandler
	Logger                    *zap.Logger
	ImagesAppDir              string
	CommandExecutionHistogram *prometheus.HistogramVec
	PrometheusMetrics         *metrics.Metrics
	ProcessQueueName          string
	MultiArch                 bool
	ProcessFunc               func(commandFactory func(name string, arg ...string) exec_command.IShellCommand, worker *SkopeoWorker)
	CommandFactory            func(name string, arg ...string) exec_command.IShellCommand
}

func NewSkopeoWorker(ctx context.Context, rdb *redis.Client, sentryNotifier sentry.Notifier, errorHandler *error_handler.ErrorHandler, logger *zap.Logger, imagesAppDir string, histogram *prometheus.HistogramVec, processQueueName string, multiArch bool, processFunc func(commandFactory func(name string, arg ...string) exec_command.IShellCommand, worker *SkopeoWorker), commandFactory func(name string, arg ...string) exec_command.IShellCommand) *SkopeoWorker {
	return &SkopeoWorker{
		Ctx:                       ctx,
		Rdb:                       rdb,
		SentryNotifier:            sentryNotifier,
		ErrorHandler:              errorHandler,
		Logger:                    logger,
		ImagesAppDir:              imagesAppDir,
		CommandExecutionHistogram: histogram,
		ProcessQueueName:          processQueueName,
		MultiArch:                 multiArch,
		ProcessFunc:               processFunc,
		CommandFactory:            commandFactory,
	}
}

func (w *SkopeoWorker) Run() {
	for {
		w.ProcessFunc(w.CommandFactory, w)
	}
}

func ProcessQueue(commandFactory func(name string, arg ...string) exec_command.IShellCommand, worker *SkopeoWorker) {
	// Block until an image name is available in the 'topull' queue
	result, err := worker.Rdb.BRPopLPush(worker.Ctx, worker.ProcessQueueName, "processing", 0).Result()
	if err != nil {
		worker.ErrorHandler.Handle(err)
		return
	}

	targetDir, err := os.MkdirTemp(worker.ImagesAppDir, "trivy-scan-*")
	if err != nil {
		worker.ErrorHandler.Handle(err)
		return
	}
	tarballFilename := fmt.Sprintf("%s/image.tar", targetDir)

	imageName := result
	if imageName == "" {
		worker.ErrorHandler.Handle(err)
		return
	}

	toPullArch := "amd64"
	supportedArchitectures, err := skopeo.GetSupportedArchitectures(imageName)
	if err != nil {
		worker.ErrorHandler.Handle(err)
		return
	}

	if !util.Contains(supportedArchitectures, "amd64") {
		toPullArch = supportedArchitectures[0]
	}

	worker.SentryNotifier.AddTag("image.name", imageName)
	worker.Logger.Info("Processing image: ", zap.String("imageName", imageName))
	worker.Logger.Info("Architecture to pull: ", zap.String("architecture", toPullArch))
	worker.Logger.Info("Target directory: ", zap.String("targetDir", targetDir))
	worker.Logger.Info("Target tarball: ", zap.String("tarball", tarballFilename))

	cmdArgs := skopeo.GenerateSkopeoCmdArgs(imageName, tarballFilename, toPullArch)
	startTime := time.Now()

	cmd := commandFactory("skopeo", cmdArgs...)
	if output, err := cmd.CombinedOutput(); err != nil {
		worker.ErrorHandler.Handle(fmt.Errorf("skopeo output: %s, error: %s", string(output), err.Error()))
		return
	}

	executionTime := time.Since(startTime).Seconds()

	_, err = worker.Rdb.LRem(worker.Ctx, "processing", 1, imageName).Result()
	if err != nil {
		worker.ErrorHandler.Handle(err)
		return
	}

	toScanString := fmt.Sprintf("%s|%s", imageName, tarballFilename)
	worker.Logger.Info("Pushing image to toscan queue:", zap.String("image", toScanString))

	err = worker.Rdb.LPush(worker.Ctx, "toscan", toScanString).Err()
	if err != nil {
		worker.ErrorHandler.Handle(err)
		return
	}

	worker.CommandExecutionHistogram.WithLabelValues(imageName).Observe(executionTime)
	worker.PrometheusMetrics.IncOpsProcessed()
}
