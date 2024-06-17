package skopeo_worker

type Config struct {
	QueueName       string
	OpsTotalName    string
	OpsTotalHelp    string
	ErrorsTotalName string
	ErrorsTotalHelp string
	ServerPort      string
	MultiArch       bool
}
