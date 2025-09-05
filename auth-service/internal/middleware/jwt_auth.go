package middleware

import (
    "auth-service/internal/service"
    "net/http"
    "strings"

    "github.com/gin-gonic/gin"
)

// JWTAuthMiddleware middleware untuk autentikasi JWT
type JWTAuthMiddleware struct {
    authService service.AuthService
}

// NewJWTAuthMiddleware membuat instance baru JWTAuthMiddleware
func NewJWTAuthMiddleware(authService service.AuthService) *JWTAuthMiddleware {
    return &JWTAuthMiddleware{authService: authService}
}

// Middleware function untuk memeriksa dan memvalidasi JWT token
func (m *JWTAuthMiddleware) Middleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        // Dapatkan token dari cookie atau header
        var tokenString string
        
        // Coba dapatkan dari cookie terlebih dahulu
        tokenString, err := c.Cookie("jwt")
        if err != nil {
            // Jika tidak ada di cookie, coba dari header Authorization
            authHeader := c.GetHeader("Authorization")
            if authHeader == "" {
                c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header or cookie required"})
                c.Abort()
                return
            }
            
            // Format: Bearer <token>
            parts := strings.Split(authHeader, " ")
            if len(parts) != 2 || parts[0] != "Bearer" {
                c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header format must be Bearer {token}"})
                c.Abort()
                return
            }
            
            tokenString = parts[1]
        }

        // Validasi token
        claims, err := m.authService.ValidateToken(tokenString)
        if err != nil {
            c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
            c.Abort()
            return
        }

        // Set claims ke context untuk digunakan di handler
        c.Set("jwtClaims", claims)
        c.Next()
    }
}