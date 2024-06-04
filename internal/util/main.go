package util

import (
	"os"
	"strconv"
)

// GetEnv retrieves an environment variable or returns a default value.
// TODO move this to a common package
func GetEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}

// GetEnvAsInt gets an environment variable as an integer, with a fallback default value.
// TODO move this to a common package
func GetEnvAsInt(key string, fallback int) int {
	valueStr := os.Getenv(key)
	if value, err := strconv.Atoi(valueStr); err == nil {
		return value
	}
	return fallback
}
