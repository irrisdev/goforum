package utils

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
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

// VerifySecureFgp verifies a fingerprint against its expected hash
func VerifySecureFgp(encodedFgp string, encodedHash string) (bool, error){

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