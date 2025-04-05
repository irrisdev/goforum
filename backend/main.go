package main

import (
	"os"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/irrisdev/goforum/internal/handlers"
	"github.com/irrisdev/goforum/internal/middleware"
	"github.com/irrisdev/goforum/internal/models"
	"github.com/sirupsen/logrus"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func main() {

	// Initialise the database connection
	db, err := gorm.Open(sqlite.Open("forum.db"), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		logrus.Fatal("failed to connect to database")
	}

	// Migrate the schema
	db.AutoMigrate(&models.User{}, &models.Category{}, &models.Thread{}, &models.Reply{})

	// Initialise handlers
	authHandler := handlers.NewAuthHandler(db)
	userHandler := handlers.NewUserHandler(db)
	// categoryHandler := handlers.NewCategoryHandler(db)
	// threadService := handlers.NewThreadHandler(db)

	// Start the server
	router := gin.Default()

	// router.Use(gin.Recovery())

	// router.Use(middleware.LoggerMiddleware())

	v1 := router.Group("/api")
	{

		// Auth endpoints
		auth := v1.Group("/auth")
		{
			auth.POST("/register", authHandler.Register)
			auth.POST("/login", authHandler.Login)
		}

		// Public category endpoints
		categories := v1.Group("/categories")
		{
			categories.GET("")
		}

		// Public thread endpoints
		threads := v1.Group("/threads")
		{
			// threads?category_id={id} - List threads in a category
			threads.GET("")

			// Get a single thread
			threads.GET("/:id")

			// Get replies for a thread
			threads.GET("/:id/replies")

		}

		// Protected Routes
		protected := v1.Group("")
		protected.Use(middleware.AuthMiddleware())
		{

			// User management
			users := protected.Group("/users")
			{
				users.GET("/me", userHandler.GetMe)
				users.PUT("/me")
			}

			// Protected category endpoints
			categories := protected.Group("/categories")
			{
				categories.POST("")
				categories.PUT("/:id")
				categories.DELETE("/:id")

			}

			// Protected thread endpoints
			threads := protected.Group("/threads")
			{

				// threads?category_id={id} - Post a thread to category, if category doesn't exist, create it
				threads.POST("")

				// Update a thread
				threads.PUT("/:id")

				// Delete a thread
				threads.DELETE("/:id")

				// Post a reply to a thread
				threads.POST("/:id/replies")

				// Update/Delete replies
				threads.PUT("/:id/replies/:replyId")
				threads.DELETE("/:id/replies/:replyId")
			}

		}

	}

	router.Run(":8080")
	logrus.Info("Server started on :8080")

}

func init() {
	lvl, ok := os.LookupEnv("LOG_LEVEL")
	// LOG_LEVEL not set, set to debug by default
	if !ok {
		lvl = "debug"
	}
	// parse string
	ll, err := logrus.ParseLevel(lvl)
	if err != nil {
		ll = logrus.DebugLevel
	}
	// set global log level
	logrus.SetLevel(ll)

	logrus.Info("log level set to ", strings.ToUpper(logrus.DebugLevel.String()))
}
