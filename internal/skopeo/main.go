package skopeo

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/vpereira/trivy_runner/pkg/exec_command"
)

// GenerateSkopeoInspectCmdArgs generates the command line arguments for the skopeo inspect to fetch all supported architectures
func GenerateSkopeoInspectCmdArgs(imageName string) []string {
	return []string{"inspect", "--raw", fmt.Sprintf("docker://%s", imageName)}
}

func GenerateSkopeoCmdArgs(imageName, targetFilename, architecture string) []string {
	cmdArgs := []string{"copy", "--remove-signatures"}

	// Check and add registry credentials if they are set
	registryUsername, usernameSet := os.LookupEnv("REGISTRY_USERNAME")
	registryPassword, passwordSet := os.LookupEnv("REGISTRY_PASSWORD")

	if usernameSet && passwordSet {
		cmdArgs = append(cmdArgs, "--src-username", registryUsername, "--src-password", registryPassword)
	}

	// Add architecture override if specified
	if architecture != "" {
		cmdArgs = append(cmdArgs, "--override-arch", architecture)
	}

	// Add the rest of the command source image and destination tar
	cmdArgs = append(cmdArgs, fmt.Sprintf("docker://%s", imageName), fmt.Sprintf("docker-archive://%s", targetFilename))

	return cmdArgs
}

// getSupportedArchitectures gets the list of supported architectures for a Docker image.
func GetSupportedArchitectures(image string) ([]string, error) {
	cmdArgs := GenerateSkopeoInspectCmdArgs(image)
	cmd := exec_command.NewExecShellCommander("skopeo", cmdArgs...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("skopeo output: %s, error: %s", string(output), err.Error())
	}

	var manifest struct {
		Manifests []struct {
			Platform struct {
				Architecture string `json:"architecture"`
			} `json:"platform"`
		} `json:"manifests"`
	}
	if err := json.Unmarshal(output, &manifest); err != nil {
		return nil, err
	}

	var architectures []string
	for _, m := range manifest.Manifests {
		architectures = append(architectures, m.Platform.Architecture)
	}

	// Ensure at least "amd64" is included if no architectures were found
	if len(architectures) == 0 {
		architectures = []string{"amd64"}
	}

	return architectures, nil
}
