package error_handler

import (
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"

	"github.com/vpereira/trivy_runner/internal/airbrake"
)

// ErrorHandler encapsulates error handling logic.
type ErrorHandler struct {
	logger        *zap.Logger
	errorsCounter prometheus.Counter
	airbrake      airbrake.Notifier
}

func NewErrorHandler(logger *zap.Logger, errorsCounter prometheus.Counter, airbrake airbrake.Notifier) *ErrorHandler {
	return &ErrorHandler{
		logger:        logger,
		errorsCounter: errorsCounter,
		airbrake:      airbrake,
	}
}

func (e *ErrorHandler) Handle(err error) {
	if err != nil {
		e.logger.Error("An error occurred", zap.Error(err))
		e.errorsCounter.Inc()
		e.airbrake.NotifyAirbrake(err)
	}
}
