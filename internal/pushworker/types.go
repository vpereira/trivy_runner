package pushworker

import (
	"encoding/json"
)

// DTO's to be used internally through the redis queue

type GetSizeResult struct {
	Sizes map[string]int64 `json:"uncompressed_sizes"`
}

type ScanResult struct {
	ResultFilePath string
}

type DTO struct {
	GetSizeResult
	ScanResult
	Operation string
	Image     string
}

func (dto *DTO) ToJSON() ([]byte, error) {
	return json.Marshal(dto)
}

func NewScanDTO() DTO {
	return DTO{
		Operation: "scan",
	}
}

func NewGetSizeDTO() DTO {
	return DTO{
		Operation:     "get-uncompressed-size",
		GetSizeResult: GetSizeResult{Sizes: make(map[string]int64)},
	}
}

func NewSBOMDTO() DTO {
	return DTO{
		Operation: "sbom",
	}
}

// Final structs to be used for pushing results out of trivy

type GetSizePayload = GetSizeResult

type ScanPayload struct {
	RanAt   string          `json:"ran_at"`
	Results json.RawMessage `json:"results"`
}

type SBOMPayload struct {
	RanSBOMAt   string          `json:"sbom_ran_at"`
	SBOMResults json.RawMessage `json:"sbom_results"`
}

type Payload struct {
	ScanPayload
	GetSizePayload
	SBOMPayload
	Image     string `json:"image"`
	Operation string `json:"operation"`
}

func NewPayload() Payload {
	return Payload{
		GetSizePayload: GetSizePayload{Sizes: make(map[string]int64)},
	}
}
