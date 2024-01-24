package main

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func TestProcessQueue(t *testing.T) {
	// Mock Redis server
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	defer mr.Close()

	// Mock webhook server
	webhookServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var result ScanResult
		body, _ := ioutil.ReadAll(r.Body)
		_ = json.Unmarshal(body, &result)

		if result.Image != "registry.suse.com/bci/bci-busybox:latest" {
			t.Errorf("Unexpected image name: %s", result.Image)
		}

		w.WriteHeader(http.StatusOK)
	}))
	defer webhookServer.Close()

	// Set environment variables
	os.Setenv("WEBHOOK_URL", webhookServer.URL)
	os.Setenv("REDIS_HOST", mr.Host())
	os.Setenv("REDIS_PORT", mr.Port())

	// Initialize Redis client and push a mock entry
	rdb = redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
	})
	_, err = rdb.RPush(ctx, "topush", "registry.suse.com/bci/bci-busybox:latest|/app/reports/registry.suse.com_bci_bci-busybox_latest.json").Result()
	if err != nil {
		t.Fatal(err)
	}

	// Call the function to process the queue
	processQueue(webhookServer.URL)

	// Allow some time for the HTTP request to complete
	time.Sleep(time.Second)
}
