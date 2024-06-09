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
