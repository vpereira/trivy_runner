package main

import (
	"os"
	"reflect"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
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

	// Initialize Redis client and push a mock entry
	rdb = redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
	})
	_, err = rdb.RPush(ctx, "topull", "registry.suse.com/bci/bci-busybox:latest").Result()
	if err != nil {
		t.Fatal(err)
	}

	processQueue()
}

func TestGenerateSkopeoCmdArgs(t *testing.T) {
	// Define test cases
	tests := []struct {
		name           string
		imageName      string
		targetDir      string
		envUsername    string
		envPassword    string
		expectedResult []string
	}{
		{
			name:      "without credentials",
			imageName: "registry.example.com/myimage:latest",
			targetDir: "/tmp/targetdir",
			expectedResult: []string{
				"copy", "--remove-signatures",
				"docker://registry.example.com/myimage:latest",
				"oci:///tmp/targetdir",
			},
		},
		{
			name:        "with credentials",
			imageName:   "registry.example.com/myimage:latest",
			targetDir:   "/tmp/targetdir",
			envUsername: "testuser",
			envPassword: "testpass",
			expectedResult: []string{
				"copy", "--remove-signatures",
				"--dest-username", "testuser", "--dest-password", "testpass",
				"docker://registry.example.com/myimage:latest",
				"oci:///tmp/targetdir",
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
			result := GenerateSkopeoCmdArgs(tc.imageName, tc.targetDir)

			// Verify the result
			if !reflect.DeepEqual(result, tc.expectedResult) {
				t.Errorf("GenerateSkopeoCmdArgs(%s, %s) got %v, want %v", tc.imageName, tc.targetDir, result, tc.expectedResult)
			}
		})
	}
}
