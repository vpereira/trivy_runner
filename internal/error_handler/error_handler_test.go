package error_handler

import (
	"errors"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"go.uber.org/zap/zaptest"
)

type MockAirbrakeNotifier struct {
	NotifyCallCount int
}

func (m *MockAirbrakeNotifier) NotifyAirbrake(err error) {
	m.NotifyCallCount++
}

type MockSentryNotifier struct {
	NotifyCallCount int
}

func (m *MockSentryNotifier) NotifySentry(err error) {
	m.NotifyCallCount++
}

func TestErrorHandler_Handle(t *testing.T) {
	logger := zaptest.NewLogger(t)
	errorsCounter := prometheus.NewCounter(prometheus.CounterOpts{})
	mockAirbrake := &MockAirbrakeNotifier{}
	mockSentry := &MockSentryNotifier{}

	handler := NewErrorHandler(logger, errorsCounter, mockAirbrake, mockSentry)

	testError := errors.New("test error")
	handler.Handle(testError)

	if testutil.ToFloat64(errorsCounter) != 1 {
		t.Errorf("Expected counter to be incremented once, got %f", testutil.ToFloat64(errorsCounter))
	}

	if mockAirbrake.NotifyCallCount != 1 {
		t.Errorf("Expected Airbrake to be notified once, got %d", mockAirbrake.NotifyCallCount)
	}

	if mockSentry.NotifyCallCount != 1 {
		t.Errorf("Expected Sentry to be notified once, got %d", mockSentry.NotifyCallCount)
	}
}
