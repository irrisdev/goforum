package handlers

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/irrisdev/goforum/internal/config"
	"github.com/irrisdev/goforum/internal/models"
	"gorm.io/gorm"
)

type ThreadHandler struct {
	db *gorm.DB
}

func NewThreadHandler(db *gorm.DB) *ThreadHandler {
	return &ThreadHandler{
		db: db,
	}
}

// ThreadDTO represents the Thread model for API responses
type ThreadDTO struct {
	ID           uint      `json:"id"`
	Title        string    `json:"title"`
	Username     string    `json:"username"`
	CategoryName string    `json:"category_name"`
	CreatedAt    time.Time `json:"created_at"`
	Excerpt      string    `json:"excerpt"`
	Content      string    `json:"-"`
}

// ThreadDetailDTO represents a single thread view with full content
type ThreadDetailDTO struct {
	ID           uint      `json:"id"`
	Title        string    `json:"title"`
	Content      string    `json:"content"`
	UserID       uint      `json:"user_id"`
	Username     string    `json:"username"`
	CategoryID   uint      `json:"category_id"`
	CategoryName string    `json:"category_name"`
	CreatedAt    time.Time `json:"created_at"`
	Replies      []ReplyDTO
}

// ThreadListResponse represents a list of threads in a category
type ThreadListResponse struct {
	Threads []ThreadDTO `json:"threads"`
	Total   int64       `json:"total"`
	Page    int         `json:"page"`
	Limit   int         `json:"limit"`
}

// ThreadCreateRequest represents the data needed to create a thread
type ThreadCreateRequest struct {
	Title      string `json:"title" binding:"required,min=5,max=100"`
	Content    string `json:"content" binding:"required,min=20"`
	CategoryID uint   `json:"category_id" binding:"required"`
}

// ReplyDTO represents a reply to a thread
type ReplyDTO struct {
	ID        uint      `json:"id"`
	Content   string    `json:"content"`
	UserID    uint      `json:"user_id"`
	Username  string    `json:"username"`
	ThreadID  uint      `json:"thread_id"`
	CreatedAt time.Time `json:"created_at"`
}

// ReplyCreateRequest represents the data needed to create a reply
type ReplyCreateRequest struct {
	Content string `json:"content" binding:"required,min=5"`
}

// GetThreads retrieves a paginated list of threads with optional category filtering
func (t *ThreadHandler) GetThreads(c *gin.Context) {

	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	if page < 1 {
		page = 1
	}

	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))
	if limit < 1 || limit > 100 {
		limit = 20
	}

	offset := (page - 1) * limit

	query := t.db.Model(&models.Thread{})
	// Apply category filter if provided (but make it optional)
	if categoryIDStr := c.Query("category_id"); categoryIDStr != "" {
		categoryID, err := strconv.Atoi(categoryIDStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid category ID format"})
			return
		}

		// Check if category exists
		var category models.Category
		if err := t.db.First(&category, categoryID).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				c.JSON(http.StatusNotFound, gin.H{"error": "category not found"})
			} else {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to verify category"})
			}
			return
		}

		query = query.Where("category_id = ?", categoryID)
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to count threads"})
		return
	}

	var threads []models.Thread
	if err := query.Order("created_at DESC").Limit(limit).Offset(offset).Find(&threads).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch threads"})
		return
	}

	threadDTOs := make([]ThreadDTO, 0, len(threads))
	for _, thread := range threads {
		var user models.User
		if err := t.db.Select("username").First(&user, thread.UserID).Error; err != nil {
			continue
		}

		var category models.Category
		if err := t.db.Select("name").First(&category, thread.CategoryID).Error; err != nil {
			continue
		}

		var excerpt string
		if len(thread.Content) > 150 {
			excerpt = thread.Content[:150] + "..."
		} else {
			excerpt = thread.Content
		}

		threadDTOs = append(threadDTOs, ThreadDTO{
			ID:           thread.ID,
			Title:        thread.Title,
			Username:     user.Username,
			CategoryName: category.Name,
			CreatedAt:    thread.CreatedAt,
			Excerpt:      excerpt,
			Content:      thread.Content,
		})
	}

	c.JSON(http.StatusOK, ThreadListResponse{
		Threads: threadDTOs,
		Total:   total,
		Page:    page,
		Limit:   limit,
	})

}

func (t *ThreadHandler) GetThread(c *gin.Context) {

}

func (t *ThreadHandler) CreateThread(c *gin.Context) {

	var threadRequest ThreadCreateRequest
	if err := c.ShouldBindJSON(&threadRequest); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "thread create request malformed", "details": err.Error()})
		return
	}

	userIDValue, exists := c.Get(config.UserIDKey)
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
		return
	}
	userID, ok := userIDValue.(uint)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "invalid user ID format in token"})
		return
	}

	var category models.Category
	if err := t.db.First(&category, threadRequest.CategoryID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "category not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to verify category"})
		}
		return
	}

	thread := models.Thread{
		Title:      threadRequest.Title,
		Content:    threadRequest.Content,
		UserID:     userID,
		CategoryID: threadRequest.CategoryID,
	}

	if err := t.db.Create(&thread).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create thread"})
		return
	}

	var user models.User
	if err := t.db.Select("username").First(&user, userID).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch user details"})
		return
	}

	var excerpt string
	if len(thread.Content) > 150 {
		excerpt = thread.Content[:150] + "..."
	} else {
		excerpt = thread.Content
	}

	// Return the created thread
	c.JSON(http.StatusCreated, ThreadDTO{
		ID:           thread.ID,
		Title:        thread.Title,
		Username:     user.Username,
		CategoryName: category.Name,
		CreatedAt:    thread.CreatedAt,
		Excerpt:      excerpt,
		Content:      thread.Content,
	})

}
