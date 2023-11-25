package utils

import (
	"strings"
)

// ImageToFilename transforms a Docker image name into a file system-friendly filename.
func ImageToFilename(imageName string) string {
	safeImageName := strings.ReplaceAll(imageName, "/", "_")
	safeImageName = strings.ReplaceAll(safeImageName, ":", "_")
	return "/app/reports/" + safeImageName + ".json"
}
