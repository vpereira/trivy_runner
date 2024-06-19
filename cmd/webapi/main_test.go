package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-redis/redismock/v9"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/vpereira/trivy_runner/internal/metrics"
	"github.com/vpereira/trivy_runner/internal/util"
)

func TestHandleScan(t *testing.T) {
	// Create a new instance of `redismock.ClientMock`
	db, mock := redismock.NewClientMock()

	queueName := util.PullWorkerQueueMessage{
		ImageName:  "testimage",
		NextAction: "scan",
	}

	messageJSON, _ := json.Marshal(queueName)

	mock.ExpectLPush("topull", messageJSON).SetVal(1)

	rdb = db

	req, err := http.NewRequest("GET", "/scan?image=testimage", nil)
	if err != nil {
		t.Fatal(err)
	}

	prometheusMetrics = metrics.NewMetrics(
		prometheus.CounterOpts{
			Name: "pullworker_processed_ops_total",
			Help: "Total number of processed operations by the pullworker.",
		},
		prometheus.CounterOpts{
			Name: "pullworker_processed_errors_total",
			Help: "Total number of processed errors by the pullworker.",
		},
	)

	prometheusMetrics.Register()

	// Ensure to unregister metrics to avoid pollution across tests
	defer prometheus.Unregister(prometheusMetrics.ProcessedOpsCounter)
	defer prometheus.Unregister(prometheusMetrics.ProcessedErrorsCounter)

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(handleScan)

	handler.ServeHTTP(rr, req)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("there were unfulfilled expectations: %s", err)
	}

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}
}

func TestHandleHealth(t *testing.T) {
	req, err := http.NewRequest("GET", "/health", nil)

	if err != nil {
		t.Fatal(err)
	}

	prometheusMetrics = metrics.NewMetrics(
		prometheus.CounterOpts{
			Name: "pullworker_processed_ops_total",
			Help: "Total number of processed operations by the pullworker.",
		},
		prometheus.CounterOpts{
			Name: "pullworker_processed_errors_total",
			Help: "Total number of processed errors by the pullworker.",
		},
	)

	prometheusMetrics.Register()

	// Ensure to unregister metrics to avoid pollution across tests
	defer prometheus.Unregister(prometheusMetrics.ProcessedOpsCounter)
	defer prometheus.Unregister(prometheusMetrics.ProcessedErrorsCounter)

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(handleHealth)
	handler.ServeHTTP(rr, req)

	response := rr.Result()
	headers := rr.Header()
	if response.StatusCode != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", response.StatusCode, http.StatusOK)
	}

	if content_type := headers.Get("content-type"); content_type != "application/json" {
		t.Errorf("handler returned wrong content-type: got '%v' want '%v'", content_type, "application/json")
	}
}
