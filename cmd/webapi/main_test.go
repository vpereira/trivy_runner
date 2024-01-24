package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-redis/redismock/v9"
)

func TestHandleScan(t *testing.T) {
	// Create a new instance of `redismock.ClientMock`
	db, mock := redismock.NewClientMock()

	mock.ExpectLPush("topull", "testimage").SetVal(1)

	rdb = db

	req, err := http.NewRequest("GET", "/scan?image=testimage", nil)
	if err != nil {
		t.Fatal(err)
	}

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
