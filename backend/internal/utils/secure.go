package utils

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"

	"golang.org/x/crypto/bcrypt"
)

// GenerateRandomSecret creates a secure random string for JWT signing
func GenerateRandomSecret(length int) ([]byte, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return nil, err
	}
	return bytes, nil
}

// GenerateSecureFgp creates a secure fingerprint for CSRF protection
func GenerateSecureFgp() (rawEncoded string, hashEncoded string, err error) {
	// Generate 16 random bytes - 128 bit entropy
	raw, err := GenerateRandomSecret(16)
	if err != nil {
		return "", "", err
	}
	// Create hash for raw fingerprint
	hash := sha256.Sum256(raw)

	// Encode raw and hashed fingerpints
	rawEncoded = base64.StdEncoding.EncodeToString(raw)
	hashEncoded = base64.StdEncoding.EncodeToString(hash[:])

	return rawEncoded, hashEncoded, nil
}

// GenerateSecureStr creates a secure string for refresh tokens
func GenerateSecureStr() (string, error) {
	// Generate 32 random bytes - 256 bit entropy
	raw, err := GenerateRandomSecret(32)
	if err != nil {
		return "", err
	}

	// Encode raw bytes
	encoded := base64.StdEncoding.EncodeToString(raw[:])

	return encoded, nil
}

// VerifySecureFgp verifies a fingerprint against its expected hash
func VerifySecureFgp(encodedFgp string, encodedHash string) (bool, error) {

	// Decode the stored hash from base64
	rawFgp, err := base64.StdEncoding.DecodeString(encodedFgp)
	if err != nil {
		return false, nil
	}
	recievedHash, err := base64.StdEncoding.DecodeString(encodedHash)
	if err != nil {
		return false, nil
	}

	// Hash provided raw fingerprint
	expectedHash := sha256.Sum256(rawFgp)

	// Compare using constant-time comparison to prevent timing attacks
	match := subtle.ConstantTimeCompare(recievedHash, expectedHash[:]) == 1

	return match, nil
}

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
	// Uses constant time comparison to mitigate side channel attack
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}
