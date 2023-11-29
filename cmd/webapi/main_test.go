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
