package skopeo_worker

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/redis/go-redis/v9"
	"github.com/vpereira/trivy_runner/pkg/exec_command"
	"github.com/vpereira/trivy_runner/pkg/exec_command/mocks"
	"go.uber.org/mock/gomock"
)

type FakeNotifier struct {
	Enabled bool
	Tags    map[string]string
}

func (fn *FakeNotifier) NotifySentry(err error) {}

func (fn *FakeNotifier) AddTag(name string, value string) {
	fn.Tags[name] = value
}

func TestProcessQueue(t *testing.T) {
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
	_, err = rdb.RPush(context.Background(), "topull", "registry.suse.com/bci/bci-busybox:latest").Result()
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

	skopeoWorker.ProcessFunc(mockCommandFactory, skopeoWorker)

	_, ok := mockNotifier.Tags["image.name"]

	if !ok {
		t.Fatalf("Expected tag 'image.name' not found")
	}
}
