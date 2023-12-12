package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/redis/go-redis/v9"
	"github.com/vpereira/trivy_runner/internal/logging"
	"github.com/vpereira/trivy_runner/internal/redisutil"
	"github.com/vpereira/trivy_runner/pkg/utils"
)

var ctx = context.Background()
var rdb *redis.Client
var opsProcessed = promauto.NewCounter(prometheus.CounterOpts{
	Name: "webapi_processed_ops_total",
	Help: "The total number of processed events",
})

func main() {

	rdb = redisutil.InitializeClient()

	// Setup HTTP server
	http.Handle("/metrics", promhttp.Handler())
	http.Handle("/scan", logging.LoggingMiddleware(http.HandlerFunc(handleScan)))
	http.Handle("/report", logging.LoggingMiddleware(http.HandlerFunc(handleReport)))
	log.Println("Server started on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func handleReport(w http.ResponseWriter, r *http.Request) {
	// Extract the image name from the query parameter
	imageName := r.URL.Query().Get("image")
	if imageName == "" {
		http.Error(w, "Image name is required", http.StatusBadRequest)
		return
	}

	// Construct the file path
	filePath := utils.ImageToFilename(imageName)

	// Check if the file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "Report not found"})
		return
	}

	// Read and return the file content
	report, err := os.ReadFile(filePath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Set the content type and write the response
	w.Header().Set("Content-Type", "application/json")
	w.Write(report)
}

func handleScan(w http.ResponseWriter, r *http.Request) {
	imageName := r.URL.Query().Get("image")
	if imageName == "" {
		http.Error(w, "Image name is required", http.StatusBadRequest)
		return
	}

	// Push the image name to Redis
	err := rdb.LPush(ctx, "topull", imageName).Err()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Increment Prometheus counter
	opsProcessed.Inc()
	// Respond with the path for the result
	filePath := utils.ImageToFilename(imageName)
	response := map[string]string{"resultPath": filePath}
	json.NewEncoder(w).Encode(response)
}
