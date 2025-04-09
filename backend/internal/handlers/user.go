package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/irrisdev/goforum/internal/config"
	"github.com/irrisdev/goforum/internal/models"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

type UserHandler struct {
	db *gorm.DB
}

func NewUserHandler(db *gorm.DB) *UserHandler {
	return &UserHandler{
		db: db,
	}
}

func (u *UserHandler) GetMe(c *gin.Context) {

	userID, exists := c.Get(config.UserIDKey)
	if !exists {
		logrus.Error("user not found in context despite passing auth middleware")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error occured"})
		return
	}

	id, ok := userID.(uint)
	if !ok {
		logrus.Error("invalid user ID in context")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error occured"})
		return
	}

	var user models.User
	if err := u.db.First(&user, id).Error; err != nil {
		logrus.WithFields(logrus.Fields{
			config.UserIDKey: id,
			"error":          err.Error(),
		}).Error("user from ID not found")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error occured"})
		return
	}

	c.JSON(http.StatusOK, models.ToUserResponse(user))

}

func (u *UserHandler) UpdateMe(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, "not implemented")
}
