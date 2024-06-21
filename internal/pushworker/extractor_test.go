package pushworker

import (
	"encoding/json"
	"fmt"
	"testing"
)

func TestExtractor_Extract(t *testing.T) {

	sbomData := []byte(`{"ran_at":"2024-06-18T14:33:20+00:00","results":{"example":"scan result"},"uncompressed_sizes":{"amd64":12345},"components":{"example":"sbom result"},"image":"test_image","operation":"test_operation"}`)
	scanData := []byte(`{"ran_at":"2024-06-18T14:33:20+00:00","results":{"example":"scan result"},"uncompressed_sizes":{"amd64":12345},"components":{"example":"sbom result"},"image":"test_image","operation":"test_operation"}`)

	tests := []struct {
		name      string
		operation string
		data      []byte
		want      json.RawMessage
		wantErr   bool
	}{
		{
			name:      "SBOM extraction",
			operation: "sbom",
			data:      sbomData,
			want:      json.RawMessage(`{"example":"sbom result"}`),
			wantErr:   false,
		},
		{
			name:      "Scan extraction",
			operation: "scan",
			data:      scanData,
			want:      json.RawMessage(`{"example":"scan result"}`),
			wantErr:   false,
		},
		{
			name:      "Unsupported operation",
			operation: "unsupported",
			data:      scanData,
			want:      nil,
			wantErr:   true,
		},
		{
			name:      "Invalid JSON for SBOM",
			operation: "sbom",
			data:      []byte(`invalid json`),
			want:      nil,
			wantErr:   true,
		},
		{
			name:      "Invalid JSON for Scan",
			operation: "scan",
			data:      []byte(`invalid json`),
			want:      nil,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			extractor := NewExtractor(tt.operation, tt.data)
			got, err := extractor.Extract()
			fmt.Println(got, err)
			if err != nil && !tt.wantErr {
				t.Errorf("Extractor.Extract() error = %v, wantErr %v", err, tt.wantErr)
				return
			} else if err == nil && tt.wantErr {
				if !jsonEqual(got, tt.want) {
					t.Errorf("Extractor.Extract() = %s, want %s", got, tt.want)
				}
			}
		})
	}
}

func jsonEqual(a, b json.RawMessage) bool {
	var j1, j2 interface{}
	if err := json.Unmarshal(a, &j1); err != nil {
		return false
	}
	if err := json.Unmarshal(b, &j2); err != nil {
		return false
	}

	j1Bytes, err := json.Marshal(j1)
	if err != nil {
		return false
	}
	j2Bytes, err := json.Marshal(j2)
	if err != nil {
		return false
	}

	return string(j1Bytes) == string(j2Bytes)
}
