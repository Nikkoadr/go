package middleware

import (
    "auth-service/internal/model"
    "net/http"

    "github.com/gin-gonic/gin"
)

// RoleAuthMiddleware middleware untuk autorisasi berdasarkan role
type RoleAuthMiddleware struct {
    allowedRoles []string
}

// NewRoleAuthMiddleware membuat instance baru RoleAuthMiddleware
func NewRoleAuthMiddleware(allowedRoles []string) *RoleAuthMiddleware {
    return &RoleAuthMiddleware{allowedRoles: allowedRoles}
}

// Middleware function untuk memeriksa role pengguna
func (m *RoleAuthMiddleware) Middleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        // Dapatkan claims dari context
        claims, exists := c.Get("jwtClaims")
        if !exists {
            c.JSON(http.StatusUnauthorized, gin.H{"error": "JWT claims not found"})
            c.Abort()
            return
        }

        jwtClaims, ok := claims.(*model.JWTClaims)
        if !ok {
            c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid JWT claims format"})
            c.Abort()
            return
        }

        // Periksa apakah role pengguna diizinkan
        hasAccess := false
        for _, role := range m.allowedRoles {
            if jwtClaims.Role == role {
                hasAccess = true
                break
            }
        }

        if !hasAccess {
            c.JSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions"})
            c.Abort()
            return
        }

        c.Next()
    }
}