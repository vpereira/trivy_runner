package skopeo_worker

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/redis/go-redis/v9"
	"github.com/vpereira/trivy_runner/internal/error_handler"
	"github.com/vpereira/trivy_runner/internal/metrics"
	"github.com/vpereira/trivy_runner/internal/pushworker"
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

// ImageSize represents the size of the image for a specific architecture.
type ImageSize struct {
	Architecture string `json:"architecture"`
	Size         int64  `json:"size"`
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
	if w.MultiArch {
		w.ProcessFunc = ProcessQueueMultiArch
	} else {
		w.ProcessFunc = ProcessQueue
	}

	for {
		w.ProcessFunc(w.CommandFactory, w)
	}
}

func (w *SkopeoWorker) getProcessingQueueName() string {
	return fmt.Sprintf("processing_%s", w.ProcessQueueName)
}

func ProcessQueueMultiArch(commandFactory func(name string, arg ...string) exec_command.IShellCommand, worker *SkopeoWorker) {

	// Block until an image name is available in the 'topull' queue
	messageJSON, err := worker.Rdb.BRPopLPush(worker.Ctx, worker.ProcessQueueName, "processing", 0).Result()

	if err != nil {
		worker.ErrorHandler.Handle(err)
		return
	}

	// Decode the JSON message
	var queueMessage util.PullWorkerQueueMessage
	if err := json.Unmarshal([]byte(messageJSON), &queueMessage); err != nil {
		worker.ErrorHandler.Handle(err)
		return
	}

	imageName := queueMessage.ImageName
	nextAction := queueMessage.NextAction

	imageNameSanitized := util.SanitizeImageName(imageName)

	targetDir, err := os.MkdirTemp(worker.ImagesAppDir, "trivy-scan-*")

	if err != nil {
		worker.ErrorHandler.Handle(err)
		return
	}

	worker.SentryNotifier.AddTag("image.name", imageName)
	worker.Logger.Info("Processing image: ", zap.String("imageName", imageName))
	worker.Logger.Info("Target directory: ", zap.String("targetDir", targetDir))
	worker.Logger.Info("Next action: ", zap.String("nextAction", nextAction))

	// Get the supported architectures for the image
	architectures, err := skopeo.GetSupportedArchitectures(imageName)

	if err != nil {
		worker.ErrorHandler.Handle(err)
		return
	}

	defer os.RemoveAll(targetDir)

	var wg sync.WaitGroup
	sizeResults := make(chan ImageSize, len(architectures))

	startTime := time.Now()
	// pull next from 'processing' queue
	_, err = worker.Rdb.LRem(worker.Ctx, worker.getProcessingQueueName(), 1, imageName).Result()
	if err != nil {
		worker.ErrorHandler.Handle(err)
		return
	}
	for _, arch := range architectures {
		wg.Add(1)
		go func(architecture string) {
			defer wg.Done()
			tarballFilename := filepath.Join(targetDir, fmt.Sprintf("%s_%s.tar", imageNameSanitized, architecture))
			worker.Logger.Info("Target tarball: ", zap.String("targetDir", tarballFilename))
			size, err := downloadImageAndGetSize(imageName, architecture, tarballFilename, worker)
			if err != nil {
				worker.ErrorHandler.Handle(err)
				return
			}
			sizeResults <- ImageSize{Architecture: architecture, Size: size}
		}(arch)
	}
	wg.Wait()
	close(sizeResults)
	executionTime := time.Since(startTime).Seconds()

	sizes := make(map[string]int64)
	for result := range sizeResults {
		sizes[result.Architecture] = result.Size
	}

	payload := pushworker.NewGetSizeDTO()
	payload.Sizes = sizes
	payload.Image = imageName

	jsonData, err := payload.ToJSON()

	if err != nil {
		worker.ErrorHandler.Handle(err)
		return
	}

	toPushString := string(jsonData)

	worker.Logger.Info("Pushing image uncompressed size to topush queue:", zap.String("payload", toPushString))

	err = worker.Rdb.LPush(worker.Ctx, "topush", toPushString).Err()

	if err != nil {
		worker.ErrorHandler.Handle(err)
		return
	}
	worker.PrometheusMetrics.CommandExecutionDurationHistogram.WithLabelValues(imageName).Observe(executionTime)
	worker.PrometheusMetrics.IncOpsProcessed()
}

func ProcessQueue(commandFactory func(name string, arg ...string) exec_command.IShellCommand, worker *SkopeoWorker) {
	// Block until an image name is available in the 'topull' queue
	messageJSON, err := worker.Rdb.BRPopLPush(worker.Ctx, worker.ProcessQueueName, "processing", 0).Result()

	if err != nil {
		worker.ErrorHandler.Handle(err)
		return
	}

	// Decode the JSON message
	var queueMessage util.PullWorkerQueueMessage
	if err := json.Unmarshal([]byte(messageJSON), &queueMessage); err != nil {
		worker.ErrorHandler.Handle(err)
		return
	}

	imageName := queueMessage.ImageName
	nextAction := queueMessage.NextAction

	targetDir, err := os.MkdirTemp(worker.ImagesAppDir, "trivy-scan-*")

	if err != nil {
		worker.ErrorHandler.Handle(err)
		return
	}

	tarballFilename := fmt.Sprintf("%s/image.tar", targetDir)

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
	worker.Logger.Info("Next action: ", zap.String("nextAction", nextAction))

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
	worker.Logger.Info("Pushing image: ", zap.String("queue", nextAction), zap.String("image", toScanString))

	if nextAction == "scan" {
		err = worker.Rdb.LPush(worker.Ctx, "toscan", toScanString).Err()
	} else {
		err = worker.Rdb.LPush(worker.Ctx, "sbom", toScanString).Err()
	}

	if err != nil {
		worker.ErrorHandler.Handle(err)
		return
	}

	worker.CommandExecutionHistogram.WithLabelValues(imageName).Observe(executionTime)
	worker.PrometheusMetrics.IncOpsProcessed()
}

func downloadImageAndGetSize(image, architecture, filePath string, worker *SkopeoWorker) (int64, error) {
	cmdArgs := skopeo.GenerateSkopeoCmdArgs(image, filePath, architecture)

	worker.Logger.Info("Executing skopeo with arguments", zap.String("arguments", strings.Join(cmdArgs, " ")))

	cmd := exec_command.NewExecShellCommander("skopeo", cmdArgs...)

	output, err := cmd.CombinedOutput()

	if err != nil {
		return 0, fmt.Errorf("skopeo output: %s, error: %s", string(output), err.Error())
	}

	worker.Logger.Info("skopeo output", zap.String("architecture", architecture), zap.String("output", string(output)))

	// Ensure the file was created
	if _, err := os.Stat(filePath); err != nil {
		return 0, fmt.Errorf("error verifying file creation: %s", err.Error())
	}

	size, err := getFileSize(filePath)
	if err != nil {
		return 0, err
	}

	return size, nil
}

// getFileSize returns the size of the file at the given path in bytes.
func getFileSize(filePath string) (int64, error) {
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return 0, err
	}
	return fileInfo.Size(), nil
}
