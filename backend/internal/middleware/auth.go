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

		// Validate JWT token
		claims, err := utils.ValidateToken(token)
		if err != nil {
			logrus.WithError(err).Info("invalid token")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired token"})
			c.Abort()
			return
		}

		// Extract userID from claims
		userId, ok := claims["sub"].(float64)
		if !ok {
			logrus.Error("invalid userId in token")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			c.Abort()
			return
		}

		c.Set(models.UserIdKey, userId)
		c.Next()

	}
}

// getTokenFromRequest extracts token from cookie or Authorization header
func getTokenFromRequest(c *gin.Context) (string, error) {
	token, err := c.Cookie("token")
	if err == nil && token != "" {
		return token, nil
	}

	return "", err
}
