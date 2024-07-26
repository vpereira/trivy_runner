package skopeo_worker

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/redis/go-redis/v9"
	"github.com/vpereira/trivy_runner/internal/util"
	"github.com/vpereira/trivy_runner/pkg/exec_command"
	"github.com/vpereira/trivy_runner/pkg/exec_command/mocks"
	"go.uber.org/mock/gomock"
)

func TestProcessRedis(t *testing.T) {
	// Mocking the command execution
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockShellCommand := mocks.NewMockIShellCommand(ctrl)
	mockShellCommand.EXPECT().CombinedOutput().Return([]byte("output"), fmt.Errorf("error"))

	mockCommandFactory := func(name string, arg ...string) exec_command.IShellCommand {
		return mockShellCommand
	}

	mockNotifier := &FakeNotifier{
		Tags: make(map[string]string),
	}
	sentryNotifier := mockNotifier

	// Set up a miniredis instance
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	defer mr.Close()

	os.Setenv("REDIS_HOST", mr.Host())
	os.Setenv("REDIS_PORT", mr.Port())
	os.Setenv("IMAGES_APP_DIR", "/tmp/images")

	// Initialize Redis client and push a mock entry
	rdb := redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
	})

	queueName := util.PullWorkerQueueMessage{
		ImageName:  "registry.suse.com/bci/bci-busybox:latest",
		NextAction: "scan",
	}

	messageJSON, _ := json.Marshal(queueName)

	_, err = rdb.RPush(context.Background(), "topull", messageJSON).Result()
	if err != nil {
		t.Fatal(err)
	}

	config := Config{
		QueueName:       "topull",
		OpsTotalName:    "skopeoworker_processed_ops_total",
		OpsTotalHelp:    "Total number of processed operations by the pullworker.",
		ErrorsTotalName: "pullworker_processed_errors_total",
		ErrorsTotalHelp: "Total number of processed errors by the pullworker.",
		ServerPort:      "8777",
	}

	skopeoWorker, err := InitializeWorker(config)
	if err != nil {
		t.Fatalf("Failed to initialize worker: %v", err)
	}

	if skopeoWorker == nil {
		t.Fatalf("Failed to initialize worker")
	}

	skopeoWorker.SentryNotifier = sentryNotifier
	// Ensure to unregister metrics to avoid pollution across tests
	defer prometheus.Unregister(skopeoWorker.CommandExecutionHistogram)
	defer prometheus.Unregister(skopeoWorker.PrometheusMetrics.ProcessedOpsCounter)
	defer prometheus.Unregister(skopeoWorker.PrometheusMetrics.ProcessedErrorsCounter)

	osHostname, _ := os.Hostname()

	processingQueueName := skopeoWorker.getProcessingQueueName(osHostname)

	if processingQueueName == fmt.Sprintf("processing_to_pull_%s", osHostname) {
		t.Fatalf("Failed to get processing queue name")
	}

	numRecs, _ := rdb.LLen(context.Background(), "topull").Result()

	if numRecs != 1 {
		t.Fatalf("Expected 1 element in the topull queue")
	}

	numRecs, _ = rdb.LLen(context.Background(), processingQueueName).Result()

	if numRecs != 0 {
		t.Fatalf("Expected 0 element in the processing queue")
	}

	skopeoWorker.ProcessFunc(mockCommandFactory, skopeoWorker)

	numRecs, _ = rdb.LLen(context.Background(), "topull").Result()

	if numRecs > 0 {
		t.Fatalf("Expected 0 element in the topull queue")
	}
}
