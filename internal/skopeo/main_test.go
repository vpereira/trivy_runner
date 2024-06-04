package skopeo

import (
	"os"
	"reflect"
	"testing"
)

func TestGenerateSkopeoInspectCmdArgs(t *testing.T) {
	imageName := "example/image:latest"
	expected := []string{"inspect", "--raw", "docker://example/image:latest"}

	result := GenerateSkopeoInspectCmdArgs(imageName)
	if !reflect.DeepEqual(result, expected) {
		t.Errorf("GenerateSkopeoInspectCmdArgs(%s) = %v; expected %v", imageName, result, expected)
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
