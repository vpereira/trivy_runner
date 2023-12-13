package utils

import (
	"testing"
)

func TestImageToFilename(t *testing.T) {
    testCases := []struct {
        imageName    string
        expectedPath string
    }{
        {"registry.example.com/repo/image:tag", "/app/reports/registry.example.com_repo_image_tag.json"},
        {"image:latest", "/app/reports/image_latest.json"},
        {"image", "/app/reports/image.json"},
        // Add more test cases as needed
    }

    for _, tc := range testCases {
        t.Run(tc.imageName, func(t *testing.T) {
            result := ImageToFilename(tc.imageName)
            if result != tc.expectedPath {
                t.Errorf("ImageToFilename(%s) = %s; want %s", tc.imageName, result, tc.expectedPath)
            }
        })
    }
}

