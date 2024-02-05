package utils

import (
	"strings"
)

// ImageToFilename transforms a Docker image name into a file system-friendly filename.
// If basePath is provided, it uses that as the base path; otherwise, it defaults to "/app/reports".
func ImageToFilename(imageName string, basePath ...string) string {
	defaultBasePath := "/app/reports"

	if len(basePath) > 0 {
		defaultBasePath = basePath[0]
	}

	safeImageName := strings.ReplaceAll(imageName, "/", "_")
	safeImageName = strings.ReplaceAll(safeImageName, ":", "_")
	return defaultBasePath + "/" + safeImageName + ".json"
}
