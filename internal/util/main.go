package util

import (
	"os"
	"strconv"
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
