package trivy_worker

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

// FakeNotifier is a mock implementation of the sentry.Notifier interface.
type FakeNotifier struct {
	Enabled bool
	Tags    map[string]string
}

func (fn *FakeNotifier) NotifySentry(err error) {}

func (fn *FakeNotifier) AddTag(name string, value string) {
	fn.Tags[name] = value
}

func TestProcessQueueReturnError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockNotifier := &FakeNotifier{
		Tags: make(map[string]string),
	}
	sentryNotifier := mockNotifier

	mockShellCommand := mocks.NewMockIShellCommand(ctrl)
	mockShellCommand.EXPECT().CombinedOutput().Return([]byte("output"), fmt.Errorf("error error"))

	mockCommandFactory := func(name string, arg ...string) exec_command.IShellCommand {
		return mockShellCommand
	}

	mr, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	defer mr.Close()

	os.Setenv("REDIS_HOST", mr.Host())
	os.Setenv("REDIS_PORT", mr.Port())
	os.Setenv("IMAGES_APP_DIR", "/tmp")

	rdb := redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
	})

	_, err = rdb.RPush(context.Background(), "toscan", "registry.suse.com/bci/bci-busybox:latest|/app/images/trivy-scan-1918888852").Result()
	if err != nil {
		t.Fatal(err)
	}

	config := Config{
		QueueName:       "toscan",
		OpsTotalName:    "scanworker_processed_ops_total",
		OpsTotalHelp:    "Total number of processed operations by the scanworker.",
		ErrorsTotalName: "scanworker_processed_errors_total",
		ErrorsTotalHelp: "Total number of processed errors by the scanworker.",
		ServerPort:      "8081",
	}

	trivyWorker, err := InitializeWorker(config)
	if err != nil {
		t.Fatalf("Failed to initialize worker: %v", err)
	}

	// Ensure to unregister metrics to avoid pollution across tests
	defer prometheus.Unregister(trivyWorker.CommandExecutionHistogram)
	defer prometheus.Unregister(trivyWorker.PrometheusMetrics.ProcessedOpsCounter)
	defer prometheus.Unregister(trivyWorker.PrometheusMetrics.ProcessedErrorsCounter)

	// Inject the mocks into the TrivyWorker struct
	trivyWorker.SentryNotifier = sentryNotifier

	trivyWorker.ProcessFunc(mockCommandFactory, trivyWorker)

	value, ok := mockNotifier.Tags["gun"]
	gun := "registry.suse.com/bci/bci-busybox:latest"

	if !ok {
		t.Errorf("Sentry tag %s not set", "gun")
	}

	if value != gun {
		t.Errorf("Sentry tag %s does not match. Want %s got %s", "gun", "registry.suse.com/bci/bci-busybox:latest", value)
	}
}
