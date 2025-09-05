package model

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// User merepresentasikan struktur data pengguna
type User struct {
    ID           int64     `json:"id"`
    Name         string    `json:"name"`
    Email        string    `json:"email"`
    PasswordHash string    `json:"-"`
    Role         string    `json:"role"`
    CreatedAt    time.Time `json:"created_at"`
}

// UserRegisterRequest struct untuk request registrasi
type UserRegisterRequest struct {
    Name     string `json:"name" binding:"required"`
    Email    string `json:"email" binding:"required,email"`
    Password string `json:"password" binding:"required,min=6"`
    Role     string `json:"role,omitempty"`
}

// UserLoginRequest struct untuk request login
type UserLoginRequest struct {
    Email    string `json:"email" binding:"required,email"`
    Password string `json:"password" binding:"required"`
}

// UserResponse struct untuk response pengguna
type UserResponse struct {
    ID        int64     `json:"id"`
    Name      string    `json:"name"`
    Email     string    `json:"email"`
    Role      string    `json:"role"`
    CreatedAt time.Time `json:"created_at"`
}

// JWTClaims struct untuk claims JWT
type JWTClaims struct {
    UserID int64  `json:"sub"`
    Email  string `json:"email"`
    Name   string `json:"name"`
    Role   string `json:"role"`
    jwt.RegisteredClaims
}