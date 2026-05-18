package auth

import (
	"net/http"
	"testing"
)

func TestGetBearerToken(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "Bearer abc123")

	token, err := GetBearerToken(headers)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if token != "abc123" {
		t.Fatalf("expected abc123, got %s", token)
	}
}

func TestGetBearerTokenMissingHeader(t *testing.T) {
	headers := http.Header{}

	_, err := GetBearerToken(headers)
	if err == nil {
		t.Fatal("expected error for missing Authorization header")
	}
}

func TestGetBearerTokenMalformedHeader(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "NotBearer abc123")

	_, err := GetBearerToken(headers)
	if err == nil {
		t.Fatal("expected error for malformed Authorization header")
	}
}
