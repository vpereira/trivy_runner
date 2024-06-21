package pushworker

import (
	"encoding/json"
	"fmt"
)

type Extractor struct {
	Operation string
	Data      []byte
}

// Constructor for Extractor
func NewExtractor(operation string, data []byte) *Extractor {
	return &Extractor{
		Operation: operation,
		Data:      data,
	}
}

// Define a method type for extraction functions
type extractFunc func(data []byte) (json.RawMessage, error)

// Define the extraction functions
func extractSBOM(data []byte) (json.RawMessage, error) {
	var result SBOMPayload
	err := json.Unmarshal(data, &result)
	if err != nil {
		return nil, err
	}
	return result.Components, nil
}

func extractScan(data []byte) (json.RawMessage, error) {
	var result ScanPayload
	err := json.Unmarshal(data, &result)
	if err != nil {
		return nil, err
	}
	return result.Results, nil
}

var extractFuncs = map[string]extractFunc{
	"sbom": extractSBOM,
	"scan": extractScan,
}

// Method to perform the extraction
func (e *Extractor) Extract() (json.RawMessage, error) {
	extractFunc, ok := extractFuncs[e.Operation]
	if !ok {
		return nil, fmt.Errorf("unsupported operation: %s", e.Operation)
	}
	return extractFunc(e.Data)
}
