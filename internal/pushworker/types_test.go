package pushworker

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestDTO_ToJSON(t *testing.T) {
	dto := DTO{
		GetSizeResult: GetSizeResult{Sizes: map[string]int64{"amd64": 12345}},
		ScanResult:    ScanResult{ResultFilePath: "/path/to/result"},
		Operation:     "test_operation",
		Image:         "test_image",
	}

	expectedJSON := `{"uncompressed_sizes":{"amd64":12345},"ResultFilePath":"/path/to/result","Operation":"test_operation","Image":"test_image"}`

	jsonData, err := dto.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON() error = %v", err)
	}

	if string(jsonData) != expectedJSON {
		t.Errorf("ToJSON() = %s; expected %s", string(jsonData), expectedJSON)
	}
}

func TestNewScanDTO(t *testing.T) {
	dto := NewScanDTO()
	if dto.Operation != "scan" {
		t.Errorf("NewScanDTO() = %s; expected %s", dto.Operation, "scan")
	}
}

func TestNewGetSizeDTO(t *testing.T) {
	dto := NewGetSizeDTO()
	if dto.Operation != "get-uncompressed-size" {
		t.Errorf("NewGetSizeDTO() = %s; expected %s", dto.Operation, "get-uncompressed-size")
	}
	if dto.GetSizeResult.Sizes == nil {
		t.Error("NewGetSizeDTO() Sizes map is nil; expected initialized map")
	}
}

func TestNewSBOMDTO(t *testing.T) {
	dto := NewSBOMDTO()
	if dto.Operation != "sbom" {
		t.Errorf("NewSBOMDTO() = %s; expected %s", dto.Operation, "sbom")
	}
}

func TestNewPayload(t *testing.T) {
	payload := NewPayload()
	if payload.GetSizePayload.Sizes == nil {
		t.Error("NewPayload() Sizes map is nil; expected initialized map")
	}
}

func TestPayloadSerialization(t *testing.T) {
	payload := Payload{
		ScanPayload: ScanPayload{
			RanAt:   "2024-06-18T14:33:20+00:00",
			Results: json.RawMessage(`{"example": "scan result"}`),
		},
		GetSizePayload: GetSizePayload{
			Sizes: map[string]int64{"amd64": 12345},
		},
		SBOMPayload: SBOMPayload{
			RanSBOMAt:   "2024-06-18T14:33:20+00:00",
			SBOMResults: json.RawMessage(`{"example": "sbom result"}`),
		},
		Image:     "test_image",
		Operation: "test_operation",
	}

	expectedJSON := `{"ran_at":"2024-06-18T14:33:20+00:00","results":{"example":"scan result"},"uncompressed_sizes":{"amd64":12345},"sbom_ran_at":"2024-06-18T14:33:20+00:00","sbom_results":{"example":"sbom result"},"image":"test_image","operation":"test_operation"}`

	jsonData, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	if string(jsonData) != expectedJSON {
		t.Errorf("json.Marshal() = %s; expected %s", string(jsonData), expectedJSON)
	}
}

func TestDTOEquality(t *testing.T) {
	dto1 := NewScanDTO()
	dto1.Image = "test_image"

	dto2 := NewScanDTO()
	dto2.Image = "test_image"

	if !reflect.DeepEqual(dto1, dto2) {
		t.Errorf("DTOs are not equal: dto1 = %v, dto2 = %v", dto1, dto2)
	}
}
