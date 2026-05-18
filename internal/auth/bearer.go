package auth

import (
	"errors"
	"net/http"
	"strings"
)

func GetBearerToken(headers http.Header) (string, error) {
	authHeader := headers.Get("Authorization")
	if authHeader == "" {
		return "", errors.New("authorization header missing")
	}

	tokenString, found := strings.CutPrefix(authHeader, "Bearer ")
	if !found {
		return "", errors.New("authorization header malformed")
	}

	tokenString = strings.TrimSpace(tokenString)
	if tokenString == "" {
		return "", errors.New("token missing")
	}

	return tokenString, nil
}
