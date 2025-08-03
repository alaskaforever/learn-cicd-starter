package auth

import (
	"net/http"
//	"strings"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name            string
		authHeader      string
		expectedKey     string
		expectedErrText string
	}{
		{
			name:            "No Authorization Header",
			authHeader:      "",
			expectedKey:     "",
			expectedErrText: "no authorization header included",
		},
		{
			name:            "Malformed Header - Missing ApiKey prefix",
			authHeader:      "Bearer somekey",
			expectedKey:     "",
			expectedErrText: "malformed authorization header",
		},
		{
			name:            "Malformed Header - Only ApiKey",
			authHeader:      "ApiKey",
			expectedKey:     "",
			expectedErrText: "malformed authorization header",
		},
		{
			name:            "Correct Header",
			authHeader:      "ApiKey abc123",
			expectedKey:     "abc123",
			expectedErrText: "",
		},
		{
			name:            "Excessive spaces between scheme and key",
			authHeader:      "ApiKey    abc123",
			expectedKey:     "abc123",
			expectedErrText: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := http.Header{}
			if tt.authHeader != "" {
				headers.Set("Authorization", tt.authHeader)
			}

			key, err := GetAPIKey(headers)

			if key != tt.expectedKey {
				t.Errorf("expected key %q, got %q", tt.expectedKey, key)
			}

			if tt.expectedErrText == "" && err != nil {
				t.Errorf("expected no error, got %v", err)
			}
			if tt.expectedErrText != "" {
				if err == nil {
					t.Errorf("expected error %q, got nil", tt.expectedErrText)
				} else if err.Error() != tt.expectedErrText {
					t.Errorf("expected error %q, got %q", tt.expectedErrText, err.Error())
				}
			}
		})
	}
}

