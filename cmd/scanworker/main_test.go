package main

import (
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
		resultFileName string
		targetDir      string
		wantArgs       []string
	}{
		{"/tmp/results/result.json", "/tmp/images/image", []string{"image", "--format", "json", "--output", "/tmp/results/result.json", "--input", "/tmp/images/image"}},
	}

	for _, tt := range tests {
		t.Run(tt.resultFileName, func(t *testing.T) {
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
