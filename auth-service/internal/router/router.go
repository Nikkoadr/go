package router

import (
	"auth-service/internal/handler"
	"auth-service/internal/middleware"
	"auth-service/internal/repository"
	"auth-service/internal/service"
	"database/sql"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

// SetupRouter mengkonfigurasi semua route aplikasi
func SetupRouter(db *sql.DB, jwtSecret, jwtIssuer string, jwtExpiry time.Duration) *gin.Engine {
	// Inisialisasi repository
	userRepo := repository.NewUserRepository(db)

	// Jalankan migration
	err := userRepo.Migrate()
	if err != nil {
		panic("Failed to migrate database: " + err.Error())
	}

	// Inisialisasi service
	authService := service.NewAuthService(userRepo, jwtSecret, jwtIssuer, jwtExpiry)

	// Inisialisasi handler
	authHandler := handler.NewAuthHandler(authService, jwtSecret, jwtExpiry)

	// Inisialisasi middleware
	jwtAuthMiddleware := middleware.NewJWTAuthMiddleware(authService)

	// Buat router
	router := gin.Default()
	if err := router.SetTrustedProxies(nil); err != nil {
		panic("Failed to set trusted proxies: " + err.Error())
	}

	// Setup CORS middleware - IMPORTANT!
	router.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"http://localhost:3000", "http://localhost:3001"}, // Port Next.js
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Length", "Content-Type", "Authorization", "Accept"},
		AllowCredentials: true, // Penting untuk cookie HttpOnly
		MaxAge:           12 * time.Hour,
	}))

	// Route untuk health check
	router.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "OK"})
	})

	// Handle OPTIONS requests untuk semua route (fallback)
	router.OPTIONS("/*any", func(c *gin.Context) {
		c.Status(200)
	})

	// Grup route API
	api := router.Group("/api")
	{
		// Public routes
		api.POST("/register", authHandler.Register)
		api.POST("/login", authHandler.Login)

		// Protected routes (memerlukan JWT)
		protected := api.Group("")
		protected.Use(jwtAuthMiddleware.Middleware())
		{
			protected.POST("/logout", authHandler.Logout)
			protected.GET("/validate", authHandler.Validate)
		}
	}

	return router
}