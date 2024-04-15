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
	AddTag(name string, value string)
}

// NewSentryNotifier initializes the Sentry client with the DSN from the environment variable.
func NewSentryNotifier() Notifier {
	dsn := os.Getenv("SENTRY_DSN")
	if dsn == "" {
		return &SentryNotifier{Enabled: false}
	}

	environment := os.Getenv("TRIVY_ENV")

	if environment == "" {
		environment = "development"
	}

	err := sentry.Init(sentry.ClientOptions{
		Dsn:         dsn,
		Environment: environment,
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
		log.Printf("Sending error to Sentry: %s", err)
		sentry.CaptureException(err)
		sentry.Flush(5 * time.Second)
	}
}

func (s *SentryNotifier) AddTag(name string, value string) {
	if s.Enabled {
		return
	}
	sentry.ConfigureScope(func(scope *sentry.Scope) {
		scope.SetTag(name, value)
	})
}
