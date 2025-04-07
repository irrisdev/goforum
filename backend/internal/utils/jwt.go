package utils

import (
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/irrisdev/goforum/internal/config"
	"github.com/irrisdev/goforum/internal/models"
	"github.com/joho/godotenv"
	"github.com/sirupsen/logrus"
)

// jwtSecret holds the key used to create the signature for JWT tokens
var jwtSecret []byte

// TokenClaims extends jwt.RegisteredClaims
type TokenClaims struct {
	UserID   uint   `json:"userID"`
	Username string `json:"username"`
	jwt.RegisteredClaims
}

// GenerateJWT created a new JWT token for a user
func GenerateJWT(user *models.User) (string, error) {

	id := user.ID
	username := user.Username

	// Create token with claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, TokenClaims{
		UserID:   id,
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			// ID:        fgp,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(config.JWTMaxAge)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	})

	// Sign token with secret key
	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

// ValidateJWT checks if a token is valid and returns the claims
func ValidateJWT(tokenString string) (*TokenClaims, error) {
	// Parse and validate the token, extra security to add ValidMethods
	token, err := jwt.ParseWithClaims(tokenString, &TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
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
	if claims, ok := token.Claims.(*TokenClaims); ok && token.Valid {
		return claims, nil
	}

	// validFgp, err := VerifySecureFgp(rawFgp, claims.ID)
	// if err != nil {
	// 	return nil, err
	// }

	// if validFgp && token.Valid {
	// 	return claims, nil
	// }

	return nil, jwt.ErrTokenUnverifiable

}

// openssl rand -hex 32 to generate a secret key
func init() {

	// Try load .env file, continue if fail
	_ = godotenv.Load()

	// Try load JWT_SECRET from environment
	secretKey := os.Getenv("JWT_SECRET")

	if secretKey == "" {

		// Generate random key if none is found, Do not use in Prod
		randomSecret, err := GenerateRandomSecret(32)
		if err != nil {
			logrus.Fatal("failed to generate random JWT secret")
		}

		secretKey = string(randomSecret)
		logrus.Warn("generated random JWT secret - tokens will be invalidated on restart")
	}

	jwtSecret = []byte(secretKey)
	logrus.Info("JWT secret loaded successfully")

}
