package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCalculateResultName(t *testing.T) {
	tests := []struct {
		imageName  string
		wantResult string
	}{
		{"registry.example.com/repo/image:tag", filepath.Join(reportsAppDir, "registry.example.com_repo_image_tag.json")},
		{"registry.example.com/repo/subrepo/image:tag", filepath.Join(reportsAppDir, "registry.example.com_repo_subrepo_image_tag.json")},
	}

	for _, tt := range tests {
		t.Run(tt.imageName, func(t *testing.T) {
			if gotResult := calculateResultName(tt.imageName); gotResult != tt.wantResult {
				t.Errorf("calculateResultName(%q) = %q, want %q", tt.imageName, gotResult, tt.wantResult)
			}
		})
	}
}

func TestGenerateTrivyCmdArgs(t *testing.T) {
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
			wantArgs:       []string{"image", "--slow", "--format", "json", "--output", "/tmp/results/result.json", "--input", "/tmp/images/image"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup environment for the test case
			tt.setupEnv()

			// Ensure environment is cleaned up after the test
			defer tt.cleanupEnv()

			gotArgs := generateTrivyCmdArgs(tt.resultFileName, tt.targetDir)
			if !equalSlice(gotArgs, tt.wantArgs) {
				t.Errorf("generateTrivyCmdArgs() got %v, want %v", gotArgs, tt.wantArgs)
			}
		})
	}
}

// Helper function to compare slices as reflect.DeepEqual can be overkill for simple string slices
func equalSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}
