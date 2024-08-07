package trivy

import (
	"os"
	"testing"

	"github.com/vpereira/trivy_runner/internal/util"
)

func TestGenerateTrivyScanCmdArgs(t *testing.T) {
	tests := []struct {
		name           string
		setupEnv       func()
		cleanupEnv     func()
		resultFileName string
		targetDir      string
		wantArgs       []string
	}{
		{
			name: "Normal run",
			setupEnv: func() {
				os.Setenv("SLOW_RUN", "0")
			},
			cleanupEnv: func() {
				os.Unsetenv("SLOW_RUN")
			},
			resultFileName: "/tmp/results/result.json",
			targetDir:      "/tmp/images/image",
			wantArgs:       []string{"image", "--format", "json", "--output", "/tmp/results/result.json", "--input", "/tmp/images/image"},
		},
		{
			name: "Slow run",
			setupEnv: func() {
				os.Setenv("SLOW_RUN", "1")
			},
			cleanupEnv: func() {
				os.Unsetenv("SLOW_RUN")
			},
			resultFileName: "/tmp/results/result.json",
			targetDir:      "/tmp/images/image",
			wantArgs:       []string{"image", "--parallel", "1", "--format", "json", "--output", "/tmp/results/result.json", "--input", "/tmp/images/image"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup environment for the test case
			tt.setupEnv()

			// Ensure environment is cleaned up after the test
			defer tt.cleanupEnv()

			gotArgs := GenerateTrivyScanCmdArgs(tt.resultFileName, tt.targetDir)
			if !util.EqualSlice(gotArgs, tt.wantArgs) {
				t.Errorf("generateTrivyScanCmdArgs() got %v, want %v", gotArgs, tt.wantArgs)
			}
		})
	}
}

func TestGenerateTrivySBOMCmdArgs(t *testing.T) {
	tests := []struct {
		name           string
		resultFileName string
		targetDir      string
		wantArgs       []string
	}{
		{
			name:           "Normal run",
			resultFileName: "/tmp/results/result.cyclonedx",
			targetDir:      "/tmp/images/image",
			wantArgs:       []string{"image", "--format", "cyclonedx", "--output", "/tmp/results/result.cyclonedx", "--input", "/tmp/images/image"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotArgs := GenerateTrivySBOMCmdArgs(tt.resultFileName, tt.targetDir)
			if !util.EqualSlice(gotArgs, tt.wantArgs) {
				t.Errorf("generateTrivySBOMCmdArgs() got %v, want %v", gotArgs, tt.wantArgs)
			}
		})
	}
}
