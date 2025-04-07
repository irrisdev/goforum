package middleware

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/irrisdev/goforum/internal/config"
	"github.com/irrisdev/goforum/internal/utils"
)

// AuthRequired ensures the user is authenticated
func AuthRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Extract token from request
		token, err := getTokenFromRequest(c)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "authentication required",
				"code":  "token_missing",
			})
			c.Abort()
			return
		}

		// Validate token
		claims, err := utils.ValidateJWT(token)
		if err != nil {
			if errors.Is(err, jwt.ErrTokenExpired) {
				c.JSON(http.StatusUnauthorized, gin.H{
					"error":   "token expired",
					"code":    "token_expired",
					"message": "please refresh your token",
				})
			} else {
				c.JSON(http.StatusUnauthorized, gin.H{
					"error": "invalid token",
					"code":  "token_invalid",
				})
			}
			c.Abort()
			return
		}

		c.Set(config.UserIDKey, claims.UserID)
		c.Set(config.UsernameKey, claims.Username)
		c.Next()
	}
}

// NoAuth ensures the user is NOT authenticated
func NoAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Check if user is already authenticated
		authHeader := c.GetHeader("Authorization")
		if authHeader != "" && len(authHeader) > 7 && authHeader[:7] == "Bearer " {
			token := authHeader[7:]
			claims, err := utils.ValidateJWT(token)
			if err == nil && claims != nil {
				// User is already authenticated
				c.JSON(http.StatusBadRequest, gin.H{
					"error":   "you are already logged in",
					"message": "please logout first",
				})
				c.Abort()
				return
			}
		}

		c.Next()
	}
}

// getTokenFromRequest extracts Authorization Bearer
func getTokenFromRequest(c *gin.Context) (string, error) {
	authHeader := c.GetHeader("Authorization")
	if authHeader != "" {
		// Check if it's a Bearer token
		if len(authHeader) > 7 && authHeader[:7] == "Bearer " {
			return authHeader[7:], nil
		}
	}
	// No valid token found
	return "", http.ErrNoCookie
}
