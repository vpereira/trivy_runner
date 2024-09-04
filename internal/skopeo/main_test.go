package skopeo

import (
	"os"
	"reflect"
	"testing"
)

func TestGenerateSkopeoInspectCmdArgs(t *testing.T) {
	tests := []struct {
		imageName   string
		envUsername string
		envPassword string
		expected    []string
	}{
		{
			"example/image:latest",
			"",
			"",
			[]string{"inspect", "--raw", "docker://example/image:latest"},
		},
		{
			"example/image:latest",
			"user",
			"pass",
			[]string{"inspect", "--raw", "--username", "user", "--password", "pass", "docker://example/image:latest"},
		},
	}

	for _, tt := range tests {
		if tt.envUsername != "" {
			os.Setenv("REGISTRY_USERNAME", tt.envUsername)
		} else {
			os.Unsetenv("REGISTRY_USERNAME")
		}

		if tt.envPassword != "" {
			os.Setenv("REGISTRY_PASSWORD", tt.envPassword)
		} else {
			os.Unsetenv("REGISTRY_PASSWORD")
		}

		result := GenerateSkopeoInspectCmdArgs(tt.imageName)
		if !reflect.DeepEqual(result, tt.expected) {
			t.Errorf("GenerateSkopeoInspectCmdArgs(%s) = %v; expected %v", tt.imageName, result, tt.expected)
		}
	}
}

func TestGenerateSkopeoCmdArgs(t *testing.T) {
	tests := []struct {
		imageName      string
		targetFilename string
		architecture   string
		envUsername    string
		envPassword    string
		expected       []string
	}{
		{
			"example/image:latest",
			"image.tar",
			"amd64",
			"",
			"",
			[]string{"copy", "--remove-signatures", "--override-arch", "amd64", "docker://example/image:latest", "docker-archive://image.tar"},
		},
		{
			"example/image:latest",
			"image.tar",
			"",
			"",
			"",
			[]string{"copy", "--remove-signatures", "docker://example/image:latest", "docker-archive://image.tar"},
		},
		{
			"example/image:latest",
			"image.tar",
			"arm64",
			"user",
			"pass",
			[]string{"copy", "--remove-signatures", "--src-username", "user", "--src-password", "pass", "--override-arch", "arm64", "docker://example/image:latest", "docker-archive://image.tar"},
		},
	}

	for _, tt := range tests {
		if tt.envUsername != "" {
			os.Setenv("REGISTRY_USERNAME", tt.envUsername)
		} else {
			os.Unsetenv("REGISTRY_USERNAME")
		}

		if tt.envPassword != "" {
			os.Setenv("REGISTRY_PASSWORD", tt.envPassword)
		} else {
			os.Unsetenv("REGISTRY_PASSWORD")
		}

		result := GenerateSkopeoCmdArgs(tt.imageName, tt.targetFilename, tt.architecture)
		if !reflect.DeepEqual(result, tt.expected) {
			t.Errorf("GenerateSkopeoCmdArgs(%s, %s, %s) = %v; expected %v", tt.imageName, tt.targetFilename, tt.architecture, result, tt.expected)
		}
	}
}

func TestManifestListDetection(t *testing.T) {
	inputs := []struct {
		MediaType string
		Result    bool
	}{
		{
			MediaType: "application/vnd.docker.distribution.manifest.list.v2+json",
			Result:    true,
		},
		{
			MediaType: "application/vnd.oci.image.index.v1+json",
			Result:    true,
		},
		{
			MediaType: "application/vnd.docker.distribution.manifest.v2+json",
			Result:    false,
		},
		{
			MediaType: "application/vnd.oci.image.manifest.v1+json",
			Result:    false,
		},
	}

	for _, input := range inputs {
		expected := input.Result
		got := IsManifestList(input.MediaType)

		if got != expected {
			t.Errorf("Unexpected mismatch, got: %v; expected: %v for %v", got, expected, input.MediaType)
		}
	}
}

func TestIsContainerImageDetection(t *testing.T) {
	inputs := []struct {
		MediaType string
		Result    bool
	}{
		{
			MediaType: "application/vnd.docker.distribution.manifest.v2+json",
			Result:    true,
		},
		{
			MediaType: "application/vnd.oci.image.manifest.v1+json",
			Result:    true,
		},
		{
			MediaType: "application/vnd.docker.distribution.manifest.list.v2+json",
			Result:    false,
		},
		{
			MediaType: "application/vnd.oci.image.index.v1+json",
			Result:    false,
		},
	}

	for _, input := range inputs {
		expected := input.Result
		got := IsContainerImage(input.MediaType)

		if got != expected {
			t.Errorf("Unexpected mismatch, got: %v; expected: %v for %v", got, expected, input.MediaType)
		}
	}
}

func TestIsUnknownArchitectureDetection(t *testing.T) {
	inputs := []struct {
		Architecture string
		Result       bool
	}{
		{
			Architecture: "",
			Result:       true,
		},
		{
			Architecture: "unknown",
			Result:       true,
		},
		{
			Architecture: "amd64",
			Result:       false,
		},
		{
			Architecture: "arm64",
			Result:       false,
		},
	}

	for _, input := range inputs {
		expected := input.Result
		got := IsUnknownArchitecture(input.Architecture)

		if got != expected {
			t.Errorf("Unexpected mismatch, got: %v; expected: %v for %v", got, expected, input.Architecture)
		}
	}
}
