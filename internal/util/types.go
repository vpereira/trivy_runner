package util

type PullWorkerQueueMessage struct {
	ImageName  string `json:"image"`
	NextAction string `json:"next_action"`
}
