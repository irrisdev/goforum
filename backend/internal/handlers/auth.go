package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
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
		}).Info("username validation failed")

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
		}).Info("registration attempt with existing username")

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
			}).Info("registration attempt with existing email")

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
			}).Info("email validation failed")

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
		}).Info("password validation failed")

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
		}).Info("username validation failed")

		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid username format"})
		return
	}

	// Find user by username
	var user models.User
	if err := a.db.Where("username = ?", input.Username).First(&user).Error; err != nil {
		logrus.WithFields(logrus.Fields{
			"username": input.Username,
			"error":    err.Error(),
		}).Info("login attempt with invalid username")

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

	raw, fgp, err := utils.GenerateSecureFgp()
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"username": input.Username,
			"reason":   err.Error(),
			"ip":       c.ClientIP(),
		}).Error("failed to generate fingerprint for JWT")

		c.JSON(http.StatusInternalServerError, gin.H{"error": "login failed"})
		return
	}

	token, err := utils.GenerateJWT(user.ID, user.Username, fgp)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"username": input.Username,
			"reason":   err.Error(),
			"ip":       c.ClientIP(),
		}).Error("failed to generate jwt")

		c.JSON(http.StatusInternalServerError, gin.H{"error": "login failed"})
		return
	}

	// Log successful login
	logrus.WithFields(logrus.Fields{
		"username": user.Username,
		"id":       user.ID,
		"ip":       c.ClientIP(),
	}).Info("successful login")

	c.SetCookie(models.SecureFgp, raw, 3600, "/", "localhost", false, true)
	c.SetCookie(models.JWTTokenKey, token, 3600, "/", "localhost", false, true)
	c.JSON(http.StatusOK, gin.H{
		"message": "login successful"})

}
