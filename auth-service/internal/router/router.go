package router

import (
    "auth-service/internal/config"
    "auth-service/internal/handler"
    "auth-service/internal/middleware"
    "auth-service/internal/repository"
    "auth-service/internal/service"
    "database/sql"
    "time"

    "github.com/gin-contrib/cors"
    "github.com/gin-gonic/gin"
    "github.com/golang-jwt/jwt/v5"
)

type ValidateResponse struct {
    ID        int64  `json:"id"`
    Name      string `json:"name"`
    Email     string `json:"email"`
    Issuer    string `json:"issuer"`
    IssuedAt  string `json:"issued_at"`
    ExpiresAt string `json:"expires_at"`
}

func SetupRouter(cfg *config.Config, db *sql.DB) *gin.Engine {
    r := gin.Default()

    // Pasang middleware CORS global (untuk cross-platform)
    r.Use(cors.New(cors.Config{
        AllowOrigins:     []string{"*"}, // ganti nanti ke domain produksi
        AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
        AllowHeaders:     []string{"Origin", "Content-Type", "Authorization"},
        ExposeHeaders:    []string{"Content-Length"},
        AllowCredentials: true,
        MaxAge:           12 * time.Hour,
    }))

    repo := repository.New(db)
    svc := service.New(repo, cfg)
    h := handler.New(svc)

    // Group API biar rapi
    api := r.Group("/api")
    {
        api.POST("/register", h.Register)
        api.POST("/login", h.Login)

        // Endpoint validasi token
        api.GET("/validate", middleware.JWTAuth(cfg.JWTSecret), func(c *gin.Context) {
            claims := c.MustGet("claims").(jwt.MapClaims)

            // Ambil nilai dari token
            id := int64(claims["sub"].(float64))
            name := claims["name"].(string)
            email := claims["email"].(string)
            iss := claims["iss"].(string)
            iat := int64(claims["iat"].(float64))
            exp := int64(claims["exp"].(float64))

            // Format waktu
            issuedAt := time.Unix(iat, 0).Format("2006-01-02 15:04:05")
            expiresAt := time.Unix(exp, 0).Format("2006-01-02 15:04:05")

            resp := ValidateResponse{
                ID:        id,
                Name:      name,
                Email:     email,
                Issuer:    iss,
                IssuedAt:  issuedAt,
                ExpiresAt: expiresAt,
            }
            c.JSON(200, resp)
        })
    }

    return r
}
