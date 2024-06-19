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

func handleRequests(w http.ResponseWriter, r *http.Request, operation string) {
	imageName := r.URL.Query().Get("image")
	if imageName == "" {
		http.Error(w, "Image name is required", http.StatusBadRequest)
		go prometheusMetrics.IncOpsProcessedErrors()
		return
	}

	queueName := util.PullWorkerQueueMessage{
		ImageName:  imageName,
		NextAction: operation,
	}

	messageJSON, err := json.Marshal(queueName)

	if err != nil {
		errorHandler.Handle(err)
		go prometheusMetrics.IncOpsProcessedErrors()
		logger.Error("Failed to marshal JSON", zap.String("image", imageName), zap.String("operation", operation), zap.Error(err))
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var queue string
	switch operation {
	case "getsize":
		queue = "getsize"
	case "scan":
		queue = "topull"
	default:
		http.Error(w, "Invalid operation", http.StatusBadRequest)
		go prometheusMetrics.IncOpsProcessedErrors()
		return
	}

	err = rdb.LPush(ctx, queue, messageJSON).Err()
	if err != nil {
		errorHandler.Handle(err)
		go prometheusMetrics.IncOpsProcessedErrors()
		logger.Error("Failed to push image to queue", zap.String("image", imageName), zap.String("queue", queue), zap.Error(err))
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	go prometheusMetrics.IncOpsProcessed()

	response := map[string]string{"image": imageName, "status": "queued"}
	json.NewEncoder(w).Encode(response)
}

func handleGetUncompressedSize(w http.ResponseWriter, r *http.Request) {
	handleRequests(w, r, "getsize")
}

func handleScan(w http.ResponseWriter, r *http.Request) {
	handleRequests(w, r, "scan")
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	// Set the content type and write the response
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	response := map[string]string{"result": "ok"}
	json.NewEncoder(w).Encode(response)
}
