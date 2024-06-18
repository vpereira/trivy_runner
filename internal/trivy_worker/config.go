package trivy_worker

type Config struct {
	QueueName       string
	OpsTotalName    string
	OpsTotalHelp    string
	ErrorsTotalName string
	ErrorsTotalHelp string
	ServerPort      string
	RunSBOMOnly     bool
}
