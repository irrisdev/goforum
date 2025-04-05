package utils

import (
	"errors"

	"golang.org/x/crypto/bcrypt"
)

// HashPassword takes a plaintext password and returns a bcrypt hash
func HashPassword(password string) (string, error) {
	if password == "" {
		return "", errors.New("password cannot be empty")
	}

	// generate the hash
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost+3)
	if err != nil {
		return "", err
	}

	// convert to string and return
	return string(bytes), nil
}

// CheckPasswordHash compares a plaintext password with a hash
func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}
