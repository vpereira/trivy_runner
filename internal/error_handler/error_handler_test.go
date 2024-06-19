package error_handler

import (
	"errors"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"go.uber.org/zap/zaptest"
)

type MockSentryNotifier struct {
	NotifyCallCount int
	Tags            map[string]string
}

func (m *MockSentryNotifier) NotifySentry(err error) {
	m.NotifyCallCount++
}

func (m *MockSentryNotifier) AddTag(key string, value string) {
	m.Tags[key] = value
}

func TestErrorHandler_Handle(t *testing.T) {
	logger := zaptest.NewLogger(t)
	errorsCounter := prometheus.NewCounter(prometheus.CounterOpts{})
	mockSentry := &MockSentryNotifier{}

	handler := NewErrorHandler(logger, errorsCounter, mockSentry)

	testError := errors.New("test error")
	handler.Handle(testError)

	if testutil.ToFloat64(errorsCounter) != 1 {
		t.Errorf("Expected counter to be incremented once, got %f", testutil.ToFloat64(errorsCounter))
	}

	if mockSentry.NotifyCallCount != 1 {
		t.Errorf("Expected Sentry to be notified once, got %d", mockSentry.NotifyCallCount)
	}
}
