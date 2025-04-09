package handlers

import (
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type CategoryHandler struct {
	db *gorm.DB
}

func NewCategoryHandler(db *gorm.DB) *CategoryHandler {
	return &CategoryHandler{
		db: db,
	}
}

// CategoryDTO represents the Category model for API responses
type CategoryDTO struct {
	ID uint `json:"id"`
	Name string `json:"name"`
	ThreadCount int64 `json:"threads"`
}
// CategoryDTO represents the Category model for API responses
type CategoryResponse struct {
	Categories []CategoryDTO `json:"categories"`
	Total int64 `json:"total"`
}



func (h *CategoryHandler) GetCategories(c *gin.Context) {



}

func (h *CategoryHandler) CreateCategory(c *gin.Context) {
}