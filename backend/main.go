package main

import (
	"context"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/irrisdev/goforum/internal/handlers"
	"github.com/irrisdev/goforum/internal/middleware"
	"github.com/irrisdev/goforum/internal/models"
	"github.com/irrisdev/goforum/internal/workers"
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
	db.AutoMigrate(&models.User{}, &models.Category{}, &models.Thread{}, &models.Reply{}, &models.RefreshToken{})

	// Initialise workers
	tokenCleanupWorker := workers.NewTokenCleanupWorker(db)

	// Create cancelable context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())

	// Start workers
	go tokenCleanupWorker.Start(ctx)

	// Initialise handlers
	authHandler := handlers.NewAuthHandler(db)
	userHandler := handlers.NewUserHandler(db)
	// categoryHandler := handlers.NewCategoryHandler(db)
	// threadService := handlers.NewThreadHandler(db)

	// Start the server
	router := gin.Default()
	// router.Use(gin.Recovery())

	// router.Use(middleware.LoggerMiddleware())

	// Public routes
	publicRoutes := router.Group("/api")
	{
		// Auth endpoints that require NO authentication
		auth := publicRoutes.Group("/auth")
		auth.Use(middleware.NoAuth()) // Ensure user is NOT logged in
		{
			auth.POST("/register", authHandler.Register)
			auth.POST("/login", authHandler.Login)
		}

		publicRoutes.POST("/auth/refresh", authHandler.Refresh)

		// Public read-only endpoints
		// publicRoutes.GET("/categories", categoryHandler.GetCategories)
		// publicRoutes.GET("/threads", threadHandler.GetThreads)
		// publicRoutes.GET("/threads/:id", threadHandler.GetThread)
	}

	// Protected routes
	protectedRoutes := router.Group("/api")
	protectedRoutes.Use(middleware.AuthRequired()) // Ensure user is authenticated
	{
		// Auth endpoints that require authentication
		protectedRoutes.POST("/auth/logout", authHandler.Logout)

		// // User management
		protectedRoutes.GET("/users/me", userHandler.GetMe)
		// protectedRoutes.PUT("/users/me", userHandler.UpdateCurrentUser)

		// // Protected category endpoints
		// protectedRoutes.POST("/categories", categoryHandler.CreateCategory)
		// protectedRoutes.PUT("/categories/:id", categoryHandler.UpdateCategory)
		// protectedRoutes.DELETE("/categories/:id", categoryHandler.DeleteCategory)

		// // Protected thread endpoints
		// protectedRoutes.POST("/threads", threadHandler.CreateThread)
		// protectedRoutes.PUT("/threads/:id", threadHandler.UpdateThread)
		// protectedRoutes.DELETE("/threads/:id", threadHandler.DeleteThread)

		// // Protected reply endpoints
		// protectedRoutes.POST("/threads/:id/replies", threadHandler.CreateReply)
		// protectedRoutes.PUT("/replies/:id", threadHandler.UpdateReply)
		// protectedRoutes.DELETE("/replies/:id", threadHandler.DeleteReply)
	}

	// Start server in a goroutine
	go func() {
		if err := router.Run(":8080"); err != nil {
			logrus.Fatalf("Failed to start server: %v", err)
		}
	}()

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	// Trigger cleanup for all background workers
	cancel()

	time.Sleep(2 * time.Second)

	logrus.Info("Server stopped")
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
