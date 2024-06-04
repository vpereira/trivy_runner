package main

import (
	"os"
	"reflect"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/redis/go-redis/v9"
	"github.com/vpereira/trivy_runner/internal/metrics"
	"github.com/vpereira/trivy_runner/internal/util"
	"go.uber.org/zap"
)

func TestProcessQueue(t *testing.T) {
	logger, _ = zap.NewProduction()
	// Mock Redis server
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
	_, err = rdb.RPush(ctx, "getsize", "registry.suse.com/bci/bci-busybox:latest").Result()

	if err != nil {
		t.Fatal(err)
	}
	imagesAppDir = util.GetEnv("IMAGES_APP_DIR", "/app/images")

	prometheusMetrics = metrics.NewMetrics(
		prometheus.CounterOpts{
			Name: "pullworker_processed_ops_total",
			Help: "Total number of processed operations by the pullworker.",
		},
		prometheus.CounterOpts{
			Name: "pullworker_processed_errors_total",
			Help: "Total number of processed errors by the pullworker.",
		},
		commandExecutionHistogram,
	)

	prometheusMetrics.Register()

	// Ensure to unregister metrics to avoid pollution across tests
	defer prometheus.Unregister(prometheusMetrics.ProcessedOpsCounter)
	defer prometheus.Unregister(prometheusMetrics.ProcessedErrorsCounter)
	defer prometheus.Unregister(commandExecutionHistogram)

	processQueue()
}

func TestGenerateSkopeoCmdArgs(t *testing.T) {
	// Define test cases
	tests := []struct {
		name           string
		imageName      string
		architecture   string
		targetDir      string
		envUsername    string
		envPassword    string
		expectedResult []string
	}{
		{
			name:         "without credentials",
			imageName:    "registry.example.com/myimage:latest",
			targetDir:    "/tmp/targetdir",
			architecture: "amd64",
			expectedResult: []string{
				"copy", "--remove-signatures",
				"--override-arch", "amd64",
				"docker://registry.example.com/myimage:latest",
				"docker-archive:///tmp/targetdir",
			},
		},
		{
			name:         "with credentials",
			imageName:    "registry.example.com/myimage:latest",
			targetDir:    "/tmp/targetdir",
			envUsername:  "testuser",
			envPassword:  "testpass",
			architecture: "amd64",
			expectedResult: []string{
				"copy", "--remove-signatures",
				"--src-username", "testuser", "--src-password", "testpass",
				"--override-arch", "amd64",
				"docker://registry.example.com/myimage:latest",
				"docker-archive:///tmp/targetdir",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Set up environment variables if needed
			if tc.envUsername != "" && tc.envPassword != "" {
				os.Setenv("REGISTRY_USERNAME", tc.envUsername)
				os.Setenv("REGISTRY_PASSWORD", tc.envPassword)
				defer os.Unsetenv("REGISTRY_USERNAME")
				defer os.Unsetenv("REGISTRY_PASSWORD")
			}

			// Call the method under test
			result := GenerateSkopeoCmdArgs(tc.imageName, tc.targetDir, tc.architecture)

			// Verify the result
			if !reflect.DeepEqual(result, tc.expectedResult) {
				t.Errorf("GenerateSkopeoCmdArgs(%s, %s) got %v, want %v", tc.imageName, tc.targetDir, result, tc.expectedResult)
			}
		})
	}
}
