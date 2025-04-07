package handlers

import (
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/irrisdev/goforum/internal/config"
	"github.com/irrisdev/goforum/internal/models"
	"github.com/irrisdev/goforum/internal/utils"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

type AuthHandler struct {
	db *gorm.DB
}

func NewAuthHandler(db *gorm.DB) *AuthHandler {
	return &AuthHandler{
		db: db,
	}
}

// Registration logic including validation
func (a *AuthHandler) Register(c *gin.Context) {

	var input models.RegisterRequest
	// Validate input
	if err := c.ShouldBind(&input); err != nil {
		logrus.WithFields(logrus.Fields{
			"error": err.Error(),
			"ip":    c.ClientIP(),
			"path":  c.Request.URL.Path,
		}).Error("registration binding error")

		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid registration format"})
		return
	}

	// Validate username
	if valid, message := utils.ValidateUsername(input.Username); !valid {
		logrus.WithFields(logrus.Fields{
			"username": input.Username,
			"reason":   message,
			"ip":       c.ClientIP(),
		}).Debug("username validation failed")

		c.JSON(http.StatusBadRequest, gin.H{"error": message})
		return
	}

	// Check if username already exists
	var existingUser models.User
	result := a.db.Where("username = ?", input.Username).First(&existingUser)
	if result.Error == nil {
		// User exists
		logrus.WithFields(logrus.Fields{
			"username": input.Username,
			"ip":       c.ClientIP(),
		}).Debug("registration attempt with existing username")

		c.JSON(http.StatusConflict, gin.H{"error": "username already taken"})
		return
	} else if result.Error != gorm.ErrRecordNotFound {
		// some other database error occurred
		logrus.WithError(result.Error).Error("database error when checking username")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "registration failed"})
		return
	}

	// Check if email already exists
	if input.Email != "" {
		var existingEmail models.User
		result := a.db.Where("email = ?", input.Email).First(&existingEmail)
		if result.Error == nil {
			// Email exists
			logrus.WithFields(logrus.Fields{
				"email": input.Email,
				"ip":    c.ClientIP(),
			}).Debug("registration attempt with existing email")

			c.JSON(http.StatusConflict, gin.H{"error": "email already registered"})
			return
		} else if result.Error != gorm.ErrRecordNotFound {
			// Database error
			logrus.WithError(result.Error).Error("database error when checking email")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "registration failed"})
			return
		}

		// Validate email format
		if valid, message := utils.ValidateEmail(input.Email); !valid {
			logrus.WithFields(logrus.Fields{
				"email":  input.Email,
				"reason": message,
				"ip":     c.ClientIP(),
			}).Debug("email validation failed")

			c.JSON(http.StatusBadRequest, gin.H{"error": message})
			return
		}
	}

	// Validate password
	if valid, message := utils.ValidatePassword(input.Password); !valid {
		logrus.WithFields(logrus.Fields{
			"username": input.Username,
			"reason":   message,
			"ip":       c.ClientIP(),
		}).Debug("password validation failed")

		c.JSON(http.StatusBadRequest, gin.H{"error": message})
		return
	}

	// Hash the password
	hashedPassword, err := utils.HashPassword(input.Password)
	if err != nil {
		logrus.WithError(err).Error("failed to hash password")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "registration failed"})
		return
	}

	// Create user with hashed password
	user := &models.User{
		Username: input.Username,
		Email:    input.Email,
		Password: hashedPassword,
	}

	// Save user to database
	if err := a.db.Create(user).Error; err != nil {
		logrus.WithError(err).Error("failed to create user")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "registration failed"})
		return
	}

	// Return success
	c.JSON(http.StatusCreated, gin.H{"message": "user registered successfully"})

}

// Login logic with validation
func (a *AuthHandler) Login(c *gin.Context) {

	var input models.LoginRequest
	// Validate input
	if err := c.ShouldBind(&input); err != nil {
		logrus.WithFields(logrus.Fields{
			"error": err.Error(),
			"ip":    c.ClientIP(),
			"path":  c.Request.URL.Path,
		}).Error("login binding error")

		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid login format"})
		return
	}

	// Validate username
	if valid, message := utils.ValidateUsername(input.Username); !valid {
		logrus.WithFields(logrus.Fields{
			"username": input.Username,
			"reason":   message,
			"ip":       c.ClientIP(),
		}).Debug("username validation failed")

		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid username format"})
		return
	}

	// Find user by username
	var user models.User
	if err := a.db.Where("username = ?", input.Username).First(&user).Error; err != nil {
		logrus.WithFields(logrus.Fields{
			"username": input.Username,
			"error":    err.Error(),
		}).Debug("login attempt with invalid username")

		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	// Check password
	if !utils.CheckPasswordHash(input.Password, user.Password) {
		logrus.WithFields(logrus.Fields{
			"username": input.Username,
		}).Info("login attempt with invalid password")

		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	// raw, fgp, err := utils.GenerateSecureFgp()
	// if err != nil {
	// 	logrus.WithFields(logrus.Fields{
	// 		"username": input.Username,
	// 		"reason":   err.Error(),
	// 		"ip":       c.ClientIP(),
	// 	}).Error("failed to generate fingerprint for JWT")

	// 	c.JSON(http.StatusInternalServerError, gin.H{"error": "login failed"})
	// 	return
	// }

	jwt, err := utils.GenerateJWT(&user)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"username": input.Username,
			"reason":   err.Error(),
			"ip":       c.ClientIP(),
		}).Error("failed to generate jwt")

		c.JSON(http.StatusInternalServerError, gin.H{"error": "login failed"})
		return
	}

	refreshToken, err := utils.GenerateSecureStr()
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"username": input.Username,
			"reason":   err.Error(),
			"ip":       c.ClientIP(),
		}).Error("failed to generate refresh token")

		c.JSON(http.StatusInternalServerError, gin.H{"error": "login failed"})
		return
	}

	// Store the refresh token in database
	refreshTokenRecord := models.RefreshToken{
		Token:     refreshToken,
		UserID:    user.ID,
		ExpiresAt: time.Now().Add(config.RefreshTokenDuration),
		IssuedAt:  time.Now(),
	}

	if err := a.db.Create(&refreshTokenRecord).Error; err != nil {
		logrus.WithError(err).Error("failed to store refresh token")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "login failed"})
		return
	}

	// Log successful login
	logrus.WithFields(logrus.Fields{
		"username": user.Username,
		"id":       user.ID,
		"ip":       c.ClientIP(),
	}).Debug("successful login")

	// c.SetCookie(models.SecureFgp, raw, 3600, "/", "localhost", false, true)
	// c.SetCookie(models.JWTTokenKey, token, 3600, "/", "localhost", false, true)
	c.SetCookie(config.RefreshTokenKey, refreshToken, int(config.RefreshTokenDuration.Seconds()), "/api/auth/refresh", "localhost", false, true)
	c.JSON(http.StatusOK, gin.H{
		"message":          "login successful",
		config.JWTTokenKey: jwt,
	})

}
func (a *AuthHandler) Refresh(c *gin.Context) {
	// Get refresh token from cookie
	refreshTokenString, err := c.Cookie(config.RefreshTokenKey)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"reason": err.Error(),
			"ip":     c.ClientIP(),
		}).Debug("refresh token missing")

		c.JSON(http.StatusUnauthorized, gin.H{"error": "refresh token required"})
		return
	}

	// Find refresh token in database
	var refreshToken models.RefreshToken
	if err := a.db.Where("token = ? AND expires_at > ? AND is_revoked = ?", refreshTokenString, time.Now().UTC(), false).First(&refreshToken).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			logrus.WithError(err).Debug("refresh attempt with invalid or expired token")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired refresh token"})
		} else {
			logrus.WithError(err).Error("database error when validating refresh token")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to refresh token"})
		}
		return
	}

	// Find associated user
	var user models.User
	if err := a.db.First(&user, refreshToken.UserID).Error; err != nil {
		logrus.WithError(err).Error("user not found for refresh token")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to refresh token"})
		return
	}

	// Start a transaction for token operations
	tx := a.db.Begin()
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	// Revoke the old refresh token
	if err := tx.Model(&refreshToken).Update("is_revoked", true).Error; err != nil {
		tx.Rollback()
		logrus.WithError(err).Error("failed to revoke used refresh token")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to refresh token"})
		return
	}

	// Generate new refresh token
	newRefreshToken, err := utils.GenerateSecureStr()
	if err != nil {
		tx.Rollback()
		logrus.WithFields(logrus.Fields{
			"username": user.Username,
			"reason":   err.Error(),
			"ip":       c.ClientIP(),
		}).Error("failed to generate refresh token")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to refresh token"})
		return
	}

	// Generate new JWT
	newToken, err := utils.GenerateJWT(&user)
	if err != nil {
		tx.Rollback()
		logrus.WithFields(logrus.Fields{
			"username": user.Username,
			"reason":   err.Error(),
			"ip":       c.ClientIP(),
		}).Error("failed to generate jwt")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to refresh token"})
		return
	}

	// Store the new refresh token in database
	refreshTokenRecord := models.RefreshToken{
		Token:     newRefreshToken,
		UserID:    user.ID,
		ExpiresAt: time.Now().UTC().Add(config.RefreshTokenDuration),
		IssuedAt:  time.Now().UTC(),
	}

	if err := tx.Create(&refreshTokenRecord).Error; err != nil {
		tx.Rollback()
		logrus.WithError(err).Error("failed to store refresh token")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to refresh token"})
		return
	}

	// Commit the transaction
	if err := tx.Commit().Error; err != nil {
		logrus.WithError(err).Error("failed to commit refresh token transaction")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to refresh token"})
		return
	}

	// Set the new refresh token as cookie
	// Convert duration to seconds for cookie
	maxAge := int(config.RefreshTokenDuration.Seconds())
	c.SetCookie(config.RefreshTokenKey, newRefreshToken, maxAge, "/api/auth/refresh", "localhost", false, true)

	c.JSON(http.StatusOK, gin.H{
		"message":          "token refreshed",
		config.JWTTokenKey: newToken,
	})
}

func (a *AuthHandler) Logout(c *gin.Context) {
	// Get refresh token
	refreshTokenString, err := c.Cookie(config.RefreshTokenKey)
	if err == nil && refreshTokenString != "" {
		// Revoke existing token
		a.db.Model(&models.RefreshToken{}).Where("token = ?", refreshTokenString).Update("is_revoked", true)

		// Clear the cookie
		c.SetCookie(config.RefreshTokenKey, "", -1, "/api/auth/refresh", "localhost", false, true)
	}

	c.JSON(http.StatusOK, gin.H{"message": "logged out successfully"})
}
