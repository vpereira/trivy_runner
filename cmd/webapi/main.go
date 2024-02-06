package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"

	"go.uber.org/zap"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/redis/go-redis/v9"
	"github.com/vpereira/trivy_runner/internal/airbrake"
	"github.com/vpereira/trivy_runner/internal/logging"
	"github.com/vpereira/trivy_runner/internal/redisutil"
	"github.com/vpereira/trivy_runner/pkg/utils"
)

var logger *zap.Logger

var ctx = context.Background()
var rdb *redis.Client

var airbrakeNotifier *airbrake.AirbrakeNotifier

var opsProcessed = promauto.NewCounter(prometheus.CounterOpts{
	Name: "webapi_processed_ops_total",
	Help: "The total number of processed events",
})

var opsProcessedError = promauto.NewCounter(prometheus.CounterOpts{
	Name: "webapi_processed_errors_total",
	Help: "The total number of errors while processing events",
})

func main() {
	var err error
	logger, err = zap.NewProduction()

	if err != nil {
		log.Fatal("Failed to create logger:", err)
	}

	defer logger.Sync()

	airbrakeNotifier = airbrake.NewAirbrakeNotifier()

	if airbrakeNotifier == nil {
		logger.Error("Failed to create airbrake notifier")
	}

	rdb = redisutil.InitializeClient()

	// prometheus.MustRegister(opsProcessed)
	// prometheus.MustRegister(opsProcessedError)

	// Setup HTTP server
	http.Handle("/health", logging.LoggingMiddleware(http.HandlerFunc(handleHealth)))
	http.Handle("/metrics", promhttp.Handler())
	http.Handle("/scan", logging.LoggingMiddleware(http.HandlerFunc(handleScan)))
	http.Handle("/report", logging.LoggingMiddleware(http.HandlerFunc(handleReport)))
	logger.Info("Server started on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	// Set the content type and write the response
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	response := map[string]string{"result": "ok"}
	json.NewEncoder(w).Encode(response)
}

func handleReport(w http.ResponseWriter, r *http.Request) {
	// Extract the image name from the query parameter
	imageName := r.URL.Query().Get("image")
	if imageName == "" {
		http.Error(w, "Image name is required", http.StatusBadRequest)
		go increasePrometheusErrors()
		return
	}

	// Construct the file path
	filePath := utils.ImageToFilename(imageName)

	// Check if the file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "Report not found"})
		go increasePrometheusErrors()
		return
	}

	// Read and return the file content
	report, err := os.ReadFile(filePath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		go increasePrometheusErrors()
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
		go increasePrometheusErrors()
		return
	}

	// Push the image name to Redis
	err := rdb.LPush(ctx, "topull", imageName).Err()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		go increasePrometheusErrors()
		logger.Error("Failed to push image to queue", zap.String("image", imageName), zap.Error(err))
		airbrakeNotifier.NotifyAirbrake(err)
		return
	}

	// Increment Prometheus counter in a goroutine
	go increasePrometheusCounter()

	// Respond with the path for the result
	filePath := utils.ImageToFilename(imageName)
	response := map[string]string{"resultPath": filePath}
	json.NewEncoder(w).Encode(response)
}

func increasePrometheusCounter() {
	opsProcessed.Inc()
}

func increasePrometheusErrors() {
	opsProcessedError.Inc()
}
