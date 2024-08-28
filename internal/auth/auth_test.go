package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name          string
		headers       http.Header
		expectedKey   string
		expectedError error
	}{
		{
			name:          "Valid API Key",
			headers:       http.Header{"Authorization": {"ApiKey my-secret-key"}},
			expectedKey:   "my-secret-key",
			expectedError: nil,
		},
		{
			name:          "Missing Authorization Header",
			headers:       http.Header{},
			expectedKey:   "",
			expectedError: ErrNoAuthHeaderIncluded,
		},
		{
			name:          "Malformed Authorization Header",
			headers:       http.Header{"Authorization": {"Bearer my-secret-key"}},
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
		{
			name:          "Empty API Key",
			headers:       http.Header{"Authorization": {"ApiKey "}},
			expectedKey:   "",
			expectedError: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKey, gotErr := GetAPIKey(tt.headers)

			if gotKey != tt.expectedKey {
				t.Fatalf("expected key: %v, got: %v", tt.expectedKey, gotKey)
			}

			if tt.expectedError != nil {
				if gotErr == nil || gotErr.Error() != tt.expectedError.Error() {
					t.Fatalf("expected error: %v, got: %v", tt.expectedError, gotErr)
				}
			} else if gotErr != nil {
				t.Fatalf("expected no error, got: %v", gotErr)
			}
		})
	}
}
