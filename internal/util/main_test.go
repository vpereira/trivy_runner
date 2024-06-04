package util

import (
	"os"
	"testing"
)

func TestGetEnv(t *testing.T) {
	tests := []struct {
		key      string
		value    string
		fallback string
		expected string
	}{
		{"EXISTING_KEY", "value1", "default1", "value1"},
		{"NON_EXISTING_KEY", "", "default2", "default2"},
	}

	for _, tt := range tests {
		if tt.value != "" {
			os.Setenv(tt.key, tt.value)
		} else {
			os.Unsetenv(tt.key)
		}

		result := GetEnv(tt.key, tt.fallback)
		if result != tt.expected {
			t.Errorf("GetEnv(%s, %s) = %s; expected %s", tt.key, tt.fallback, result, tt.expected)
		}
	}
}

func TestGetEnvAsInt(t *testing.T) {
	tests := []struct {
		key      string
		value    string
		fallback int
		expected int
	}{
		{"EXISTING_INT_KEY", "123", 456, 123},
		{"INVALID_INT_KEY", "abc", 456, 456},
		{"NON_EXISTING_INT_KEY", "", 456, 456},
	}

	for _, tt := range tests {
		if tt.value != "" {
			os.Setenv(tt.key, tt.value)
		} else {
			os.Unsetenv(tt.key)
		}

		result := GetEnvAsInt(tt.key, tt.fallback)
		if result != tt.expected {
			t.Errorf("GetEnvAsInt(%s, %d) = %d; expected %d", tt.key, tt.fallback, result, tt.expected)
		}
	}
}
