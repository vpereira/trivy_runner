package util

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// GetEnv retrieves an environment variable or returns a default value.
func GetEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}

// GetEnvAsInt gets an environment variable as an integer, with a fallback default value.
func GetEnvAsInt(key string, fallback int) int {
	valueStr := os.Getenv(key)
	if value, err := strconv.Atoi(valueStr); err == nil {
		return value
	}
	return fallback
}

// contains checks if a string is in a slice.
func Contains(slice []string, item string) bool {
	for _, a := range slice {
		if a == item {
			return true
		}
	}
	return false
}

// Helper function to compare slices as reflect.DeepEqual can be overkill for simple string slices
func EqualSlice(a, b []string) bool {
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

// Calculate the name of the result file for a given image name.
func CalculateResultName(imageName string, reportsAppDir string) string {
	safeImageName := SanitizeImageName(imageName)
	return filepath.Join(reportsAppDir, safeImageName+".json")
}

// SanitizeImageName replaces slashes and colons in the image name with underscores.
func SanitizeImageName(image string) string {
	return strings.NewReplacer("/", "_", ":", "_").Replace(image)
}

// ImageToFilename transforms a Docker image name into a file system-friendly filename.
// If basePath is provided, it uses that as the base path; otherwise, it defaults to "/app/reports".
func ImageToFilename(imageName string, basePath ...string) string {
	defaultBasePath := "/app/reports"

	if len(basePath) > 0 {
		defaultBasePath = basePath[0]
	}

	return CalculateResultName(imageName, defaultBasePath)
}
