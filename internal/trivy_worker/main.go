package trivy_worker

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/redis/go-redis/v9"
	"github.com/vpereira/trivy_runner/internal/error_handler"
	"github.com/vpereira/trivy_runner/internal/metrics"
	"github.com/vpereira/trivy_runner/internal/pushworker"
	"github.com/vpereira/trivy_runner/internal/sentry"
	"github.com/vpereira/trivy_runner/internal/trivy"
	"github.com/vpereira/trivy_runner/internal/util"
	"github.com/vpereira/trivy_runner/pkg/exec_command"
	"go.uber.org/zap"
)

type TrivyWorker struct {
	Ctx                       context.Context
	Rdb                       *redis.Client
	SentryNotifier            sentry.Notifier
	ErrorHandler              *error_handler.ErrorHandler
	Logger                    *zap.Logger
	ReportsAppDir             string
	CommandExecutionHistogram *prometheus.HistogramVec
	PrometheusMetrics         *metrics.Metrics
	ProcessQueueName          string
	RunSBOMOnly               bool
	ProcessFunc               func(commandFactory func(name string, arg ...string) exec_command.IShellCommand, worker *TrivyWorker)
	CommandFactory            func(name string, arg ...string) exec_command.IShellCommand
}

func NewTrivyWorker(ctx context.Context, rdb *redis.Client, sentryNotifier sentry.Notifier, errorHandler *error_handler.ErrorHandler, logger *zap.Logger, reportsAppDir string, histogram *prometheus.HistogramVec, processQueueName string, runSBOMmonly bool, processFunc func(commandFactory func(name string, arg ...string) exec_command.IShellCommand, worker *TrivyWorker), commandFactory func(name string, arg ...string) exec_command.IShellCommand) *TrivyWorker {
	return &TrivyWorker{
		Ctx:                       ctx,
		Rdb:                       rdb,
		SentryNotifier:            sentryNotifier,
		ErrorHandler:              errorHandler,
		Logger:                    logger,
		ReportsAppDir:             reportsAppDir,
		CommandExecutionHistogram: histogram,
		ProcessQueueName:          processQueueName,
		RunSBOMOnly:               runSBOMmonly,
		ProcessFunc:               processFunc,
		CommandFactory:            commandFactory,
	}
}

func (w *TrivyWorker) Run() {
	for {
		w.ProcessFunc(w.CommandFactory, w)
	}
}

func ProcessQueue(commandFactory func(name string, arg ...string) exec_command.IShellCommand, worker *TrivyWorker) {
	// Block until an image name is available in the specified queue
	redisAnswer, err := worker.Rdb.BRPop(worker.Ctx, 0, worker.ProcessQueueName).Result()
	if err != nil {
		worker.ErrorHandler.Handle(err)
		return
	}

	// Split the answer
	// [queue_name image_name|target_path]
	parts := strings.Split(redisAnswer[1], "|")
	if len(parts) != 2 {
		err = fmt.Errorf("invalid format in Redis answer: %v", parts)
		worker.ErrorHandler.Handle(err)
		return
	}

	imageName := parts[0]
	target := parts[1]

	worker.SentryNotifier.AddTag("gun", imageName)
	worker.SentryNotifier.AddTag("target-dir", target)
	// Delete the image when we're done
	defer os.RemoveAll(target)

	// Sanitize the image name to create a valid filename
	resultFileName := util.CalculateResultName(imageName, worker.ReportsAppDir)

	worker.Logger.Info("Processing image:", zap.String("image", imageName))
	worker.Logger.Info("Saving results to:", zap.String("json_report", resultFileName))

	cmdArgs := trivy.GenerateTrivyScanCmdArgs(resultFileName, target) // Adjust based on the worker type

	startTime := time.Now()
	cmd := commandFactory("trivy", cmdArgs...)

	if output, err := cmd.CombinedOutput(); err != nil {
		if worker.SentryNotifier != nil {
			worker.SentryNotifier.AddTag("gun", imageName)
		}
		worker.ErrorHandler.Handle(fmt.Errorf("trivy output: %s, error: %s", string(output), err.Error()))
		return
	}

	executionTime := time.Since(startTime).Seconds()
	worker.Logger.Info("Processing complete for image:", zap.String("image", imageName), zap.String("json_report", resultFileName))

	if os.Getenv("PUSH_TO_CATALOG") != "" {
		payload := pushworker.NewScanDTO()
		payload.ResultFilePath = resultFileName
		payload.Image = imageName

		jsonData, err := payload.ToJSON()
		if err != nil {
			worker.ErrorHandler.Handle(err)
			return
		}

		toPushString := string(jsonData)
		worker.Logger.Info("Pushing image scan to topush queue:", zap.String("payload", toPushString))

		err = worker.Rdb.LPush(worker.Ctx, "topush", jsonData).Err()
		if err != nil {
			worker.ErrorHandler.Handle(err)
			return
		}
	}
	worker.PrometheusMetrics.IncOpsProcessed()
	worker.CommandExecutionHistogram.WithLabelValues(imageName).Observe(executionTime)
}
