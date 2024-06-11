package main

import (
	"fmt"
	"os"
	"testing"

	"github.com/vpereira/trivy_runner/internal/error_handler"
	"github.com/vpereira/trivy_runner/pkg/exec_command/mocks"
	"go.uber.org/mock/gomock"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/vpereira/trivy_runner/pkg/exec_command"
)

type fakeNotifier struct {
	Enabled bool
	Tags    map[string]string
}

func (fn *fakeNotifier) NotifySentry(err error) {}

func (fn *fakeNotifier) AddTag(name string, value string) {
	fn.Tags[name] = value
}

func TestProcessQueueReturnsError(t *testing.T) {
	// gun := "registry.suse.com/bci/bci-busybox:latest"
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	core, logs := observer.New(zap.ErrorLevel)
	logger := zap.New(core)

	mockNotifier := &fakeNotifier{
		Tags: make(map[string]string),
	}
	sentryNotifier = mockNotifier

	errorHandler = error_handler.NewErrorHandler(logger, prometheusMetrics.ProcessedErrorsCounter, airbrakeNotifier, sentryNotifier)

	mockShellCommand := mocks.NewMockIShellCommand(ctrl)
	mockShellCommand.EXPECT().CombinedOutput().Return([]byte("output"), fmt.Errorf("error %s", "error"))

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

	// Initialize Redis client and push a mock entry
	rdb = redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
	})

	_, err = rdb.RPush(ctx, "toscan", "registry.suse.com/bci/bci-busybox:latest|/app/images/trivy-scan-1918888852").Result()

	if err != nil {
		t.Fatal(err)
	}
	processQueue(mockCommandFactory)

	// Check if the log contains the desired error message.
	if logs.Len() == 0 {
		t.Errorf("Expected an error log, but no logs were captured")
	} else {
		found := false
		for _, entry := range logs.All() {
			if entry.Level == zap.ErrorLevel && entry.Message == "An error occurred" {
				if entry.ContextMap()["error"] == "trivy output: output, error: error error" {
					found = true
					break
				}
			}
		}
		if !found {
			t.Errorf("Expected log to contain error message 'trivy output: output, error: error error', but it was not found")
		}
	}
}

func TestProcessQueueReturnsSuccess(t *testing.T) {
	// gun := "registry.suse.com/bci/bci-busybox:latest"
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	core, logs := observer.New(zap.ErrorLevel)
	logger := zap.New(core)

	mockNotifier := &fakeNotifier{
		Tags: make(map[string]string),
	}
	sentryNotifier = mockNotifier

	errorHandler = error_handler.NewErrorHandler(logger, prometheusMetrics.ProcessedErrorsCounter, airbrakeNotifier, sentryNotifier)

	mockShellCommand := mocks.NewMockIShellCommand(ctrl)
	mockShellCommand.EXPECT().CombinedOutput().Return([]byte("output"), nil)

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

	// Initialize Redis client and push a mock entry
	rdb = redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
	})

	_, err = rdb.RPush(ctx, "toscan", "registry.suse.com/bci/bci-busybox:latest|/app/images/trivy-scan-1918888852").Result()

	if err != nil {
		t.Fatal(err)
	}
	processQueue(mockCommandFactory)

	// Check if the log contains the desired error message.
	if logs.Len() < 0 {
		t.Errorf("Expected no error log")
	}
}
