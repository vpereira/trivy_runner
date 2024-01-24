package redisutil_test

import (
	"os"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/vpereira/trivy_runner/internal/redisutil"
)

func TestInitializeClient(t *testing.T) {
	// Create a miniredis server
	s, err := miniredis.Run()
	if err != nil {
		t.Fatalf("Failed to start miniredis: %v", err)
	}
	defer s.Close()

	// Set environment variables for testing
	os.Setenv("REDIS_HOST", "localhost")
	os.Setenv("REDIS_PORT", s.Port())

	client := redisutil.InitializeClient()

	if client == nil {
		t.Error("Expected non-nil Redis client")
	}
}
