package skopeo

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/vpereira/trivy_runner/pkg/exec_command"
)

// GenerateSkopeoInspectCmdArgs generates the command line arguments for the skopeo inspect to fetch all supported architectures
func GenerateSkopeoInspectCmdArgs(imageName string) []string {
	cmdArgs := []string{"inspect", "--raw"}

	// Check and add registry credentials if they are set
	registryUsername, usernameSet := os.LookupEnv("REGISTRY_USERNAME")
	registryPassword, passwordSet := os.LookupEnv("REGISTRY_PASSWORD")

	if usernameSet && passwordSet {
		cmdArgs = append(cmdArgs, "--username", registryUsername, "--password", registryPassword)
	}

	cmdArgs = append(cmdArgs, fmt.Sprintf("docker://%s", imageName))

	return cmdArgs
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

func IsManifestList(mediaType string) bool {
	switch mediaType {
	case
		"application/vnd.docker.distribution.manifest.list.v2+json",
		"application/vnd.oci.image.index.v1+json":
		return true
	}
	return false
}

func IsContainerImage(mediaType string) bool {
	switch mediaType {
	case
		"application/vnd.docker.distribution.manifest.v2+json",
		"application/vnd.oci.image.manifest.v1+json":
		return true
	}
	return false
}

func IsUnknownArchitecture(arch string) bool {
	// Unknown / Empty architectures reflect content that should not be treated
	// as a "runnable" binary, they're there to provide metadata and the choice of value
	// "" or "unknown" is to sway the clients from matching the legit architecture (amd64, ppc64, etc.)
	// against these metadata stores.
	switch arch {
	case
		"",
		"unknown":
		return true
	}

	return false
}

// GetSupportedArchitectures gets the list of supported architectures for a Docker image.
func GetSupportedArchitectures(image string) ([]string, error) {
	cmdArgs := GenerateSkopeoInspectCmdArgs(image)
	cmd := exec_command.NewExecShellCommander("skopeo", cmdArgs...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("skopeo output: %s, error: %s", string(output), err.Error())
	}

	var manifest struct {
		MediaType string `json:"mediaType"`
		Manifests []struct {
			Platform struct {
				Architecture string `json:"architecture"`
			} `json:"platform"`
		} `json:"manifests"`
	}

	if err := json.Unmarshal(output, &manifest); err != nil {
		return nil, err
	}

	if IsManifestList(manifest.MediaType) {
		// Collect all architectures from a manifestlist
		var architectures []string
		for _, m := range manifest.Manifests {
			if IsUnknownArchitecture(m.Platform.Architecture) {
				continue
			}
			architectures = append(architectures, m.Platform.Architecture)
		}
		return architectures, nil
	} else if IsContainerImage(manifest.MediaType) {
		// Assume amd64 when a container is sent
		return []string{"amd64"}, nil
	}

	// Default case, if media type doesn't match known values
	return nil, fmt.Errorf("unsupported media type: %s", manifest.MediaType)
}
