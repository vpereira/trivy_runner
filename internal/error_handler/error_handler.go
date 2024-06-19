package error_handler

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/vpereira/trivy_runner/internal/sentry"
	"go.uber.org/zap"
)

// ErrorHandler encapsulates error handling logic.
type ErrorHandler struct {
	logger        *zap.Logger
	errorsCounter prometheus.Counter
	sentry        sentry.Notifier
}

func NewErrorHandler(logger *zap.Logger, errorsCounter prometheus.Counter, sentry sentry.Notifier) *ErrorHandler {
	return &ErrorHandler{
		logger:        logger,
		errorsCounter: errorsCounter,
		sentry:        sentry,
	}
}

func (e *ErrorHandler) Handle(err error) {
	if err != nil {
		e.logger.Error("An error occurred", zap.Error(err))
		e.errorsCounter.Inc()
		e.sentry.NotifySentry(err)
	}
}
