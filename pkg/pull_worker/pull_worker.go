package pull_worker

import (
	"errors"
	"fmt"
	"github.com/vpereira/trivy_runner/pkg/exec_command"
	"os"
)

var (
	NoImageGiven = errors.New("PullWorker: No image given")
)

type PullWorker interface {
	Pull(target string, dir string) error
}

type pullWorker struct {
	execCommand exec_command.IShellCommand
}

func (p *pullWorker) Pull(imageName string, targetDir string) error {
	// bail early if no image is given
	if imageName == "" {
		return NoImageGiven
	}

	cmdArgs := GenerateSkopeoCmdArgs(imageName, targetDir)
	p.execCommand.NewCommand("skopeo", cmdArgs...)

	if _, err := p.execCommand.Output(); err != nil {
		return err
	}

	return nil
}

func NewPuller(ec exec_command.IShellCommand) PullWorker {
	return &pullWorker{ec}
}

// GenerateSkopeoCmdArgs generates the command line arguments for the skopeo
// command based on environment variables and input parameters.
func GenerateSkopeoCmdArgs(imageName, targetDir string) []string {
	cmdArgs := []string{"copy", "--remove-signatures"}

	// Check and add registry credentials if they are set
	registryUsername, usernameSet := os.LookupEnv("REGISTRY_USERNAME")
	registryPassword, passwordSet := os.LookupEnv("REGISTRY_PASSWORD")

	if usernameSet && passwordSet {
		cmdArgs = append(cmdArgs, "--dest-username", registryUsername, "--dest-password", registryPassword)
	}

	// Add the rest of the command
	cmdArgs = append(cmdArgs, fmt.Sprintf("docker://%s", imageName), "oci://"+targetDir)

	return cmdArgs
}
