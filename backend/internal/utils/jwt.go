package utils

import (
	"crypto/rand"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
	"github.com/sirupsen/logrus"
)

// jwtSecret holds the key used to create the signature for JWT tokens
var jwtSecret []byte

// GenerateToken created a new JWT token for a user
func GenerateToken(id uint, username string) (string, error) {
	// Create token with claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":      id,
		"username": username,
		"exp":      time.Now().Add(time.Hour * 8).Unix(),
		"iat":      time.Now().Unix(),
	})

	// Sign token with secret key
	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

// ValidateToken checks if a token is valid and returns the claims
func ValidateToken(tokenString string) (jwt.MapClaims, error) {
	// Parse and validate the token, extra security to add ValidMethods
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Validate signing algortihim
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.ErrSignatureInvalid
		}
		return jwtSecret, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}))

	if err != nil {
		return nil, err
	}

	// Check token validity
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, jwt.ErrTokenInvalidClaims

}

// generateRandomSecret creates a secure random string for JWT signing
func generateRandomSecret() ([]byte, error) {
	bytes := make([]byte, 32) // 256 bits
	if _, err := rand.Read(bytes); err != nil {
		return nil, err
	}
	return bytes, nil
}

// openssl rand -hex 32 to generate a secret key
func init() {

	// Try load .env file, continue if fail
	_ = godotenv.Load()

	// Try load JWT_SECRET from environment
	secretKey := os.Getenv("JWT_SECRET")

	if secretKey == "" {

		// Generate random key if none is found, Do not use in Prod
		randomSecret, err := generateRandomSecret()
		if err != nil {
			logrus.Fatal("failed to generate random JWT secret")
		}

		jwtSecret = randomSecret
		logrus.Warn("generated random JWT secret - tokens will be invalidated on restart")
	}

	jwtSecret = []byte(secretKey)
	logrus.Info("JWT secret loaded successfully")

}
