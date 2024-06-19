package util

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGetEnv(t *testing.T) {
	tests := []struct {
		key      string
		value    string
		fallback string
		expected string
	}{
		{"EXISTING_KEY", "value1", "default1", "value1"},
		{"NON_EXISTING_KEY", "", "default2", "default2"},
	}

	for _, tt := range tests {
		if tt.value != "" {
			os.Setenv(tt.key, tt.value)
		} else {
			os.Unsetenv(tt.key)
		}

		result := GetEnv(tt.key, tt.fallback)
		if result != tt.expected {
			t.Errorf("GetEnv(%s, %s) = %s; expected %s", tt.key, tt.fallback, result, tt.expected)
		}
	}
}

func TestGetEnvAsInt(t *testing.T) {
	tests := []struct {
		key      string
		value    string
		fallback int
		expected int
	}{
		{"EXISTING_INT_KEY", "123", 456, 123},
		{"INVALID_INT_KEY", "abc", 456, 456},
		{"NON_EXISTING_INT_KEY", "", 456, 456},
	}

	for _, tt := range tests {
		if tt.value != "" {
			os.Setenv(tt.key, tt.value)
		} else {
			os.Unsetenv(tt.key)
		}

		result := GetEnvAsInt(tt.key, tt.fallback)
		if result != tt.expected {
			t.Errorf("GetEnvAsInt(%s, %d) = %d; expected %d", tt.key, tt.fallback, result, tt.expected)
		}
	}
}

func TestCalculateResultName(t *testing.T) {
	tests := []struct {
		reportsAppDir string
		imageName     string
		wantResult    string
	}{
		{"/tmp", "registry.example.com/repo/image:tag", filepath.Join("/tmp", "registry.example.com_repo_image_tag.json")},
		{"/tmp/foo", "registry.example.com/repo/subrepo/image:tag", filepath.Join("/tmp/foo", "registry.example.com_repo_subrepo_image_tag.json")},
	}

	for _, tt := range tests {
		t.Run(tt.imageName, func(t *testing.T) {
			if gotResult := CalculateResultName(tt.imageName, tt.reportsAppDir); gotResult != tt.wantResult {
				t.Errorf("calculateResultName(%q) = %q, want %q", tt.imageName, gotResult, tt.wantResult)
			}
		})
	}
}

func TestSanitzedImageName(t *testing.T) {
	tests := []struct {
		imageName string
		want      string
	}{
		{"registry.example.com/repo/image:tag", "registry.example.com_repo_image_tag"},
		{"registry.example.com/repo/subrepo/image:tag", "registry.example.com_repo_subrepo_image_tag"},
	}

	for _, tt := range tests {
		t.Run(tt.imageName, func(t *testing.T) {
			if got := SanitizeImageName(tt.imageName); got != tt.want {
				t.Errorf("SanitizeImageName(%q) = %q, want %q", tt.imageName, got, tt.want)
			}
		})
	}
}

func TestImageToFilename(t *testing.T) {
	tests := []struct {
		name      string
		imageName string
		basePath  []string
		want      string
	}{
		{
			name:      "Default base path",
			imageName: "example/image:latest",
			want:      "/app/reports/example_image_latest.json",
		},
		{
			name:      "Custom base path",
			imageName: "example/image:latest",
			basePath:  []string{"/custom/path"},
			want:      "/custom/path/example_image_latest.json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ImageToFilename(tt.imageName, tt.basePath...)
			if got != tt.want {
				t.Errorf("ImageToFilename() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestImageToFilenameOnlyDefaultBasePath(t *testing.T) {
	got := ImageToFilename("example/image:latest")
	want := "/app/reports/example_image_latest.json"
	if got != want {
		t.Errorf("ImageToFilename() got = %v, want %v", got, want)
	}
}

func TestImageToFilename_Security(t *testing.T) {
	imageName := "../../../etc/passwd"
	got := ImageToFilename(imageName)
	if strings.Contains(got, "../") {
		t.Errorf("ImageToFilename() should sanitize path traversal attempts, got = %v", got)
	}
}
