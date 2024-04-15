package sentry

import (
	"os"
	"testing"
)

func TestNewSentryNotifier(t *testing.T) {
	// Test with no DSN set
	t.Run("without DSN", func(t *testing.T) {
		os.Unsetenv("SENTRY_DSN")
		notifier := NewSentryNotifier()

		if notifier.(*SentryNotifier).Enabled {
			t.Errorf("Expected SentryNotifier to be disabled when DSN is not set")
		}
	})

	t.Run("with DSN", func(t *testing.T) {
		os.Setenv("SENTRY_DSN", "https://example@o123456.ingest.sentry.io/123456")
		defer os.Unsetenv("SENTRY_DSN")

		notifier := NewSentryNotifier()
		if !notifier.(*SentryNotifier).Enabled {
			t.Errorf("Expected SentryNotifier to be enabled when DSN is set")
		}
	})
}
