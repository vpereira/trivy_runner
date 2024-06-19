package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"

	"go.uber.org/zap"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/redis/go-redis/v9"
	"github.com/vpereira/trivy_runner/internal/error_handler"
	"github.com/vpereira/trivy_runner/internal/logging"
	"github.com/vpereira/trivy_runner/internal/metrics"
	"github.com/vpereira/trivy_runner/internal/redisutil"
	"github.com/vpereira/trivy_runner/internal/util"
)

var (
	logger            *zap.Logger
	ctx               = context.Background()
	rdb               *redis.Client
	prometheusMetrics *metrics.Metrics
	errorHandler      *error_handler.ErrorHandler
)

func main() {
	defer logger.Sync()
	rdb = redisutil.InitializeClient()
	logger.Info("Server started on :8080")
	// Setup HTTP server routes
	http.Handle("/health", logging.LoggingMiddleware(http.HandlerFunc(handleHealth)))
	http.Handle("/metrics", promhttp.Handler())
	http.Handle("/scan", logging.LoggingMiddleware(http.HandlerFunc(handleScan)))
	http.Handle("/get-uncompressed-size", logging.LoggingMiddleware(http.HandlerFunc(handleGetUncompressedSize)))
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func handleGetUncompressedSize(w http.ResponseWriter, r *http.Request) {
	imageName := r.URL.Query().Get("image")
	if imageName == "" {
		http.Error(w, "Image name is required", http.StatusBadRequest)
		go prometheusMetrics.IncOpsProcessedErrors()
		return
	}

	queueName := util.PullWorkerQueueMessage{
		ImageName:  imageName,
		NextAction: "scan",
	}

	messageJSON, err := json.Marshal(queueName)

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		go prometheusMetrics.IncOpsProcessedErrors()
		logger.Error("Failed to unmarshal messageJSON", zap.String("image", imageName), zap.Error(err))
		errorHandler.Handle(err)
		return
	}

	// Push the image name to Redis
	err = rdb.LPush(ctx, "getsize", messageJSON).Err()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		go prometheusMetrics.IncOpsProcessedErrors()
		logger.Error("Failed to push image to queue", zap.String("image", imageName), zap.Error(err))
		errorHandler.Handle(err)
		return
	}

	// Increment Prometheus counter in a goroutine
	go prometheusMetrics.IncOpsProcessed()

	response := map[string]string{"image": imageName, "status": "queued"}
	json.NewEncoder(w).Encode(response)
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	// Set the content type and write the response
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	response := map[string]string{"result": "ok"}
	json.NewEncoder(w).Encode(response)
}

func handleScan(w http.ResponseWriter, r *http.Request) {
	imageName := r.URL.Query().Get("image")
	if imageName == "" {
		http.Error(w, "Image name is required", http.StatusBadRequest)
		go prometheusMetrics.IncOpsProcessedErrors()
		return
	}

	queueName := util.PullWorkerQueueMessage{
		ImageName:  imageName,
		NextAction: "scan",
	}

	messageJSON, err := json.Marshal(queueName)

	if err != nil {
		errorHandler.Handle(err)
		go prometheusMetrics.IncOpsProcessedErrors()
		logger.Error("Failed to marshal JSON", zap.String("image", imageName), zap.Error(err))
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Push the image name to Redis
	err = rdb.LPush(ctx, "topull", messageJSON).Err()

	if err != nil {
		errorHandler.Handle(err)
		go prometheusMetrics.IncOpsProcessedErrors()
		logger.Error("Failed to push image to queue", zap.String("image", imageName), zap.Error(err))
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Increment Prometheus counter in a goroutine
	go prometheusMetrics.IncOpsProcessed()

	response := map[string]string{"image": imageName, "status": "queued"}
	json.NewEncoder(w).Encode(response)
}
