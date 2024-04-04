package sentry

import (
	"log"
	"os"
	"time"

	"github.com/getsentry/sentry-go"
)

type SentryNotifier struct {
	Enabled bool
}

type Notifier interface {
	NotifySentry(err error)
}

// NewSentryNotifier initializes the Sentry client with the DSN from the environment variable.
func NewSentryNotifier() *SentryNotifier {
	dsn := os.Getenv("SENTRY_DSN")
	if dsn == "" {
		return &SentryNotifier{Enabled: false}
	}

	err := sentry.Init(sentry.ClientOptions{
		Dsn: dsn,
	})
	if err != nil {
		log.Fatalf("sentry.Init: %s", err)
		return &SentryNotifier{Enabled: false}
	}

	return &SentryNotifier{
		Enabled: true,
	}
}

func (s *SentryNotifier) NotifySentry(err error) {
	if s.Enabled && err != nil {
		sentry.WithScope(func(scope *sentry.Scope) {
			sentry.CaptureException(err)
		})
		sentry.Flush(5 * time.Second)
	}
}
