package auth

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"strings"
)

func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	return string(hash), nil
}

func CheckPasswordHash(password, hash string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}
func MakeRefreshToken() (string, error) {
	bytes := make([]byte, 32)

	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(bytes), nil
}
func GetAPIKey(headers http.Header) (string, error) {
	authHeader := headers.Get("Authorization")
	if authHeader == "" {
		return "", errors.New("no authorization header included")
	}

	key, found := strings.CutPrefix(authHeader, "ApiKey ")
	if !found {
		return "", errors.New("malformed authorization header")
	}

	return key, nil
}
