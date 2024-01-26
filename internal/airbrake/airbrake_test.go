package airbrake

import (
	"os"
	"testing"
)

func TestNewAirbrakeNotifier(t *testing.T) {
	tests := []struct {
		name        string
		projectID   string
		projectKey  string
		wantEnabled bool
	}{
		{
			name:        "Valid configuration",
			projectID:   "12345",
			projectKey:  "validkey",
			wantEnabled: true,
		},
		{
			name:        "Missing project ID",
			projectKey:  "validkey",
			wantEnabled: false,
		},
		{
			name:        "Missing project key",
			projectID:   "12345",
			wantEnabled: false,
		},
		{
			name:        "Invalid project ID",
			projectID:   "invalid",
			projectKey:  "validkey",
			wantEnabled: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Setenv("AIRBRAKE_PROJECT_ID", tt.projectID)
			os.Setenv("AIRBRAKE_PROJECT_KEY", tt.projectKey)

			notifier := NewAirbrakeNotifier()
			if notifier.Enabled != tt.wantEnabled {
				t.Errorf("NewAirbrakeNotifier().Enabled = %v, want %v", notifier.Enabled, tt.wantEnabled)
			}

			os.Unsetenv("AIRBRAKE_PROJECT_ID")
			os.Unsetenv("AIRBRAKE_PROJECT_KEY")
		})
	}
}
