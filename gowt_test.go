package gowt

import (
	"bytes"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"testing"
)

// Mock HttpClient
type mockHttpClient struct {
	getResponse *http.Response
	getError    error
}

func (mock *mockHttpClient) Get(url string) (resp *http.Response, err error) {
	return mock.getResponse, mock.getError
}

// Mock JsonReader
type mockJsonReader struct {
	readResult map[string]any
	readError  error
}

func (mock *mockJsonReader) Read(jsonBody io.ReadCloser) (map[string]any, error) {
	return mock.readResult, mock.readError
}

// Mock Converter
type mockConverter struct {
	conversionResult *big.Int
	conversionError  error
}

func (mock *mockConverter) base64ToBigInt(encoded string) (*big.Int, error) {
	return mock.conversionResult, mock.conversionError
}

// Util Funcs
func buildResponseBody(data map[string]any) io.ReadCloser {
	jsonData, err := json.Marshal(data)
	if err != nil {
		panic(err)
	}

	return io.NopCloser(bytes.NewBuffer(jsonData))
}

func compareRSAKeys(key1, key2 *rsa.PublicKey) bool {
	if (key1 == nil && key2 != nil) || (key1 != nil && key2 == nil) {
		return false
	}

	if key1 == nil && key2 == nil {
		return true
	}

	if key1.E != key2.E {
		return false
	}

	return key1.N.Cmp(key2.N) == 0
}

func assertCorrectError(t *testing.T, expectedError error, err error) {
	if expectedError == nil && err != nil {
		t.Errorf("expected nil error, got %v", err)
	} else {
		if expectedError != nil && err == nil {
			t.Errorf("expected error %v, got nil", expectedError)
		} else if expectedError != nil && err.Error() != expectedError.Error() {
			t.Errorf("expected error %v, got %v", expectedError, err)
		}
	}
}

func TestFetchPublicKeyFromServer(t *testing.T) {
	subtests := []struct {
		name          string
		httpClient    httpClient
		jsonReader    jsonReader
		converter     converter
		expectedError error
		expectedKey   *rsa.PublicKey
	}{
		{
			name: "happy path returns correct public key and no error",
			httpClient: &mockHttpClient{
				getResponse: &http.Response{
					StatusCode: http.StatusOK,
					Body: buildResponseBody(map[string]any{
						"keys": []any{
							map[string]any{
								"kid": "kid",
								"e":   "base_64_encoded",
								"n":   "base_64_encoded",
							},
						},
					}),
				},
				getError: nil,
			},
			jsonReader: &mockJsonReader{
				readResult: map[string]any{
					"keys": []any{
						map[string]any{
							"kid": "kid",
							"e":   "base_64_encoded",
							"n":   "base_64_encoded",
						},
					},
				},
				readError: nil,
			},
			converter: &mockConverter{
				conversionResult: big.NewInt(2048),
				conversionError:  nil,
			},
			expectedKey:   &rsa.PublicKey{N: big.NewInt(2048), E: 2048},
			expectedError: nil,
		},
		{
			name: "get request returns error",
			httpClient: &mockHttpClient{
				getResponse: &http.Response{},
				getError:    fmt.Errorf("error on get request"),
			},
			jsonReader:    &mockJsonReader{},
			converter:     &mockConverter{},
			expectedKey:   nil,
			expectedError: fmt.Errorf("error on get request"),
		},
		{
			name: "error reading json body",
			httpClient: &mockHttpClient{
				getResponse: &http.Response{
					StatusCode: http.StatusOK,
					Body: buildResponseBody(map[string]any{
						"keys": []any{
							map[string]any{
								"kid": "kid",
								"e":   "base_64_encoded",
								"n":   "base_64_encoded",
							},
						},
					}),
				},
				getError: nil,
			},
			jsonReader: &mockJsonReader{
				readResult: nil,
				readError:  fmt.Errorf("error reading json body"),
			},
			converter:     &mockConverter{},
			expectedKey:   nil,
			expectedError: fmt.Errorf("error reading json body"),
		},
		{
			name: "provided kid is not found",
			httpClient: &mockHttpClient{
				getResponse: &http.Response{
					StatusCode: http.StatusOK,
					Body: buildResponseBody(map[string]any{
						"keys": []any{
							map[string]any{
								"kid": "some other kid",
							},
						},
					}),
				},
				getError: nil,
			},
			jsonReader: &mockJsonReader{
				readResult: map[string]any{
					"keys": []any{
						map[string]any{
							"kid": "some other kid",
						},
					},
				},
				readError: nil,
			},
			converter:     &mockConverter{},
			expectedKey:   nil,
			expectedError: fmt.Errorf("key not found for kid kid"),
		},
		{
			name: "converter error",
			httpClient: &mockHttpClient{
				getResponse: &http.Response{
					StatusCode: http.StatusOK,
					Body: buildResponseBody(map[string]any{
						"keys": []any{
							map[string]any{
								"kid": "kid",
								"e":   "base_64_encoded",
								"n":   "base_64_encoded",
							},
						},
					}),
				},
				getError: nil,
			},
			jsonReader: &mockJsonReader{
				readResult: map[string]any{
					"keys": []any{
						map[string]any{
							"kid": "kid",
							"e":   "base_64_encoded",
							"n":   "base_64_encoded",
						},
					},
				},
				readError: nil,
			},
			converter: &mockConverter{
				conversionResult: nil,
				conversionError:  fmt.Errorf("converter error"),
			},
			expectedKey:   nil,
			expectedError: fmt.Errorf("converter error"),
		},
	}

	for _, tc := range subtests {
		t.Run(tc.name, func(t *testing.T) {
			gowt := &stdGowt{
				config: &gowtConfig{
					certsUrl: "certs_url",
				},
				httpClient: tc.httpClient,
				jsonReader: tc.jsonReader,
				converter:  tc.converter,
			}

			publicKey, err := gowt.fetchPublicKeyFromServer("kid")

			if !compareRSAKeys(publicKey, tc.expectedKey) {
				t.Errorf("result key and expected key are not the same")
			}

			assertCorrectError(t, tc.expectedError, err)
		})
	}
}
