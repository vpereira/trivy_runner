package utils

import (
	"strings"
	"testing"
)

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
