package redisutil_test

import (
	"os"
	"testing"
	"your_project_root/internal/redisutil"
)

func TestInitializeClient(t *testing.T) {
	// Set environment variables for testing
	os.Setenv("REDIS_HOST", "localhost")
	os.Setenv("REDIS_PORT", "6379")

	client := redisutil.InitializeClient()

	if client == nil {
		t.Error("Expected non-nil Redis client")
	}
}
