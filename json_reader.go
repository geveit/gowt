package gowt

import (
	"encoding/json"
	"io"
)

type jsonReader interface {
	Read(jsonBody io.ReadCloser) (map[string]any, error)
}

type stdJsonReader struct{}

func NewJsonReader() jsonReader {
	return &stdJsonReader{}
}

func (r *stdJsonReader) Read(jsonBody io.ReadCloser) (map[string]any, error) {
	resultBytes, err := io.ReadAll(jsonBody)
	if err != nil {
		return nil, err
	}

	var result map[string]any
	if err := json.Unmarshal(resultBytes, &result); err != nil {
		return nil, err
	}

	return result, nil
}
