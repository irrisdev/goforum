package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/irrisdev/goforum/internal/models"
	"github.com/sirupsen/logrus"
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
	ID          uint   `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description" binding:"max=200"`
	ThreadCount int64  `json:"threads"`
}

// CategoryListResponse represents a list of categories
type CategoryListResponse struct {
	Categories []CategoryDTO `json:"categories"`
	Total      int64         `json:"total"`
}

// CategoryCreateRequest represents the data needed to create a category
type CategoryCreateRequest struct {
	Name        string `json:"name" binding:"required,min=3,max=50"`
	Description string `json:"description" binding:"max=200"`
}

func (h *CategoryHandler) GetCategories(c *gin.Context) {

	var categories []models.Category
	var total int64

	// Count all categories
	h.db.Model(&models.Category{}).Count(&total)

	if err := h.db.Find(&categories).Error; err != nil {
		logrus.WithError(err).Error("failed to fetch categories")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch categories"})
		return
	}

	// Transfer all category models into CategoryDTO
	categoryDTOs := make([]CategoryDTO, len(categories))
	for _, category := range categories {

		// Retrieve thread count for category
		var threadCount int64
		h.db.Model(&models.Thread{}).Where("category_id = ?", category.ID).Count(&threadCount)

		categoryDTOs = append(categoryDTOs, CategoryDTO{
			ID:          category.ID,
			Name:        category.Name,
			Description: category.Description,
			ThreadCount: threadCount})
	}

	response := CategoryListResponse{
		Categories: categoryDTOs,
		Total:      total,
	}

	c.JSON(http.StatusOK, response)

}

func (h *CategoryHandler) CreateCategory(c *gin.Context) {

	// Parse request
	var categoryRequest CategoryCreateRequest
	if err := c.ShouldBindJSON(&categoryRequest); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "category create request malformed"})
		return
	}

	// Check if category name already exists
	var count int64
	h.db.Model(&models.Category{}).Where("name = ?", categoryRequest.Name).Count(&count)
	if count > 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "category name already exists"})
		return
	}

	category := models.Category{
		Name:        categoryRequest.Name,
		Description: categoryRequest.Description,
	}

	if err := h.db.Create(&category).Error; err != nil {
		logrus.WithError(err).Error("failed to create category")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create category"})
		return
	}

	// Return created category
	c.JSON(http.StatusCreated, CategoryDTO{
		ID:          category.ID,
		Name:        category.Name,
		Description: category.Description,
		ThreadCount: 0,
	})

}
