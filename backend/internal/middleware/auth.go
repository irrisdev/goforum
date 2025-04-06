package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/irrisdev/goforum/internal/models"
	"github.com/irrisdev/goforum/internal/utils"
	"github.com/sirupsen/logrus"
)

// AuthMiddlware verifies JWT tokens and sets user info from token claims
func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {

		// Extract token from cookies
		token, err := getTokenFromRequest(c)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
			c.Abort()
			return
		}

		// Extract secure fingerprint from cookies
		fgp, err := getRawFgpFromRequest(c)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
			c.Abort()
			return
		}

		// Validate JWT token
		claims, err := utils.ValidateToken(token, fgp)
		if err != nil {
			logrus.WithError(err).Info("invalid token")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired token"})
			c.Abort()
			return
		}

		c.Set(models.UserIDKey, claims.UserID)
		c.Next()

	}
}

// getTokenFromRequest extracts models.JWTTokenKey from cookie
func getTokenFromRequest(c *gin.Context) (string, error) {
	token, err := c.Cookie(models.JWTTokenKey)
	if err == nil && token != "" {
		return token, nil
	}
	return "", err
}

// getSecureFgpFromRequest extracts models.SecureFgp from cookie
func getRawFgpFromRequest(c *gin.Context) (string, error) {
	fgp, err := c.Cookie(models.SecureFgp)
	if err == nil && fgp != "" {
		return fgp, nil
	}
	return "", err
}
