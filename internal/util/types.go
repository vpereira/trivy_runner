package util

type PullWorkerQueueMessage struct {
	ImageName  string `json:"image"`
	NextAction string `json:"next_action"`
}

type ScanWorkerQueueMessage struct {
	ImageName  string `json:"image"`
	NextAction string `json:"next_action"`
	TarPath    string `json:"tar_path"`
}
