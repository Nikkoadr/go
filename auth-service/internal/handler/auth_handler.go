package handler

import (
	"auth-service/internal/model"
	"auth-service/internal/service"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// AuthHandler menangani request HTTP untuk autentikasi
type AuthHandler struct {
    authService service.AuthService
    jwtSecret   string
    jwtExpiry   time.Duration
}

// NewAuthHandler membuat instance baru AuthHandler
func NewAuthHandler(authService service.AuthService, jwtSecret string, jwtExpiry time.Duration) *AuthHandler {
    return &AuthHandler{
        authService: authService,
        jwtSecret:   jwtSecret,
        jwtExpiry:   jwtExpiry,
    }
}

// Register menangani request registrasi pengguna dan langsung membuat JWT
func (h *AuthHandler) Register(c *gin.Context) {
    var req model.UserRegisterRequest

    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }

    // Panggil service register yang sekarang mengembalikan token
    user, token, err := h.authService.Register(&req)
    if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }

    // Set HttpOnly cookie
    c.SetCookie("jwt", token, int(h.jwtExpiry.Seconds()), "/", "localhost", false, true)

    c.JSON(http.StatusCreated, gin.H{
        "message": "User registered successfully",
        "user":    user,
    })
}

// Login menangani request login pengguna
func (h *AuthHandler) Login(c *gin.Context) {
    var req model.UserLoginRequest

    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }

    token, user, err := h.authService.Login(req.Email, req.Password)
    if err != nil {
        c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
        return
    }

    // Set HttpOnly cookie
    c.SetCookie("jwt", token, int(h.jwtExpiry.Seconds()), "/", "localhost", false, true)

    c.JSON(http.StatusOK, gin.H{
        "message": "Login successful",
        "user":    user,
    })
}

// Logout menangani request logout pengguna
func (h *AuthHandler) Logout(c *gin.Context) {
    token, err := c.Cookie("jwt")
    if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "No token provided"})
        return
    }

    // Logout service -> masukkan token ke blacklist
    if err := h.authService.Logout(token); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }

    // Hapus cookie dengan expiry ke waktu lampau
    c.SetCookie("jwt", "", -1, "/", "localhost", false, true)

    c.JSON(http.StatusOK, gin.H{
        "message": "Logout successful",
    })
}

// Validate menangani request validasi token
func (h *AuthHandler) Validate(c *gin.Context) {
    claimsRaw, exists := c.Get("jwtClaims")
    if !exists {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "JWT claims not found"})
        return
    }

    jwtClaims, ok := claimsRaw.(*model.JWTClaims)
    if !ok {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid JWT claims format"})
        return
    }

    user, err := h.authService.GetUserProfile(jwtClaims.UserID)
    if err != nil {
        c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
        return
    }

    c.JSON(http.StatusOK, gin.H{
        "valid":     true,
        "user":      user,
        "issuer":    jwtClaims.Issuer,
        "issuedAt":  jwtClaims.IssuedAt,
        "expiresAt": jwtClaims.ExpiresAt,
    })
}
