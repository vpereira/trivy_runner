package airbrake

import (
	"os"
	"strconv"

	"github.com/airbrake/gobrake/v5"
)

type AirbrakeNotifier struct {
	Notifier *gobrake.Notifier
	Enabled  bool
}

type Notifier interface {
	NotifyAirbrake(err error)
}

func NewAirbrakeNotifier() *AirbrakeNotifier {
	projectIDStr := os.Getenv("AIRBRAKE_PROJECT_ID")
	projectKey := os.Getenv("AIRBRAKE_PROJECT_KEY")
	projectEnvironment := os.Getenv("AIRBRAKE_ENVIRONMENT")
	errbitURL := os.Getenv("AIRBRAKE_ERRBIT_URL")

	if projectIDStr == "" || projectKey == "" || errbitURL == "" {
		return &AirbrakeNotifier{Enabled: false}
	}

	projectID, err := strconv.ParseInt(projectIDStr, 10, 64)
	if err != nil {
		return &AirbrakeNotifier{Enabled: false}
	}

	airbrake := gobrake.NewNotifierWithOptions(&gobrake.NotifierOptions{
		ProjectId:   projectID,
		ProjectKey:  projectKey,
		Environment: projectEnvironment,
		Host:        errbitURL, // Set custom Errbit URL if provided
	})

	return &AirbrakeNotifier{
		Notifier: airbrake,
		Enabled:  true,
	}
}

func (a *AirbrakeNotifier) NotifyAirbrake(err error) {
	if a.Enabled && err != nil {
		if notice := a.Notifier.Notice(err, nil, 3); notice != nil {
			a.Notifier.SendNoticeAsync(notice)
		}
	}
}
