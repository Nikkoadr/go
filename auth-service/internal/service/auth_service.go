package service

import (
	"auth-service/internal/model"
	"auth-service/internal/repository"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// AuthService interface untuk layanan autentikasi
type AuthService interface {
    Register(userReq *model.UserRegisterRequest) (*model.UserResponse, string, error)
    Login(email, password string) (string, *model.UserResponse, error)
    ValidateToken(tokenString string) (*model.JWTClaims, error)
    Logout(tokenString string) error
    GetUserProfile(userID int64) (*model.UserResponse, error)
}

type authService struct {
    userRepo       repository.UserRepository
    jwtSecret      string
    jwtIssuer      string
    jwtExpiry      time.Duration
    tokenBlacklist map[string]time.Time
}

// NewAuthService membuat instance baru AuthService
func NewAuthService(
    userRepo repository.UserRepository,
    jwtSecret string,
    jwtIssuer string,
    jwtExpiry time.Duration,
) AuthService {
    return &authService{
        userRepo:       userRepo,
        jwtSecret:      jwtSecret,
        jwtIssuer:      jwtIssuer,
        jwtExpiry:      jwtExpiry,
        tokenBlacklist: make(map[string]time.Time),
    }
}

// Register mendaftarkan pengguna baru dan langsung membuat JWT
func (s *authService) Register(userReq *model.UserRegisterRequest) (*model.UserResponse, string, error) {
    // Set default role
    role := userReq.Role
    if role == "" {
        role = "user"
    }
    if role != "user" && role != "admin" {
        return nil, "", errors.New("invalid role, must be 'user' or 'admin'")
    }

    // Hash password
    hashedPassword, err := repository.HashPassword(userReq.Password)
    if err != nil {
        return nil, "", fmt.Errorf("failed to hash password: %v", err)
    }

    // Buat user object
    user := &model.User{
        Name:         userReq.Name,
        Email:        userReq.Email,
        PasswordHash: hashedPassword,
        Role:         role,
        CreatedAt:    time.Now(),
    }

    // Simpan ke database
    if err := s.userRepo.CreateUser(user); err != nil {
        return nil, "", fmt.Errorf("failed to create user: %v", err)
    }

    // Buat JWT token
    claims := &model.JWTClaims{
        UserID: user.ID,
        Email:  user.Email,
        Name:   user.Name,
        Role:   user.Role,
        RegisteredClaims: jwt.RegisteredClaims{
            ExpiresAt: jwt.NewNumericDate(time.Now().Add(s.jwtExpiry)),
            IssuedAt:  jwt.NewNumericDate(time.Now()),
            Issuer:    s.jwtIssuer,
            Subject:   fmt.Sprintf("%d", user.ID),
        },
    }

    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    tokenString, err := token.SignedString([]byte(s.jwtSecret))
    if err != nil {
        return nil, "", fmt.Errorf("failed to generate token: %v", err)
    }

    // Return user response + token
    userResp := &model.UserResponse{
        ID:        user.ID,
        Name:      user.Name,
        Email:     user.Email,
        Role:      user.Role,
        CreatedAt: user.CreatedAt,
    }

    return userResp, tokenString, nil
}

// Login melakukan autentikasi pengguna dan menghasilkan JWT token
func (s *authService) Login(email, password string) (string, *model.UserResponse, error) {
    user, err := s.userRepo.FindByEmail(email)
    if err != nil {
        return "", nil, errors.New("invalid email or password")
    }

    // Verifikasi password
    if err := repository.CheckPassword(password, user.PasswordHash); err != nil {
        return "", nil, errors.New("invalid email or password")
    }

    // Buat JWT token
    claims := &model.JWTClaims{
        UserID: user.ID,
        Email:  user.Email,
        Name:   user.Name,
        Role:   user.Role,
        RegisteredClaims: jwt.RegisteredClaims{
            ExpiresAt: jwt.NewNumericDate(time.Now().Add(s.jwtExpiry)),
            IssuedAt:  jwt.NewNumericDate(time.Now()),
            Issuer:    s.jwtIssuer,
            Subject:   fmt.Sprintf("%d", user.ID),
        },
    }

    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    tokenString, err := token.SignedString([]byte(s.jwtSecret))
    if err != nil {
        return "", nil, fmt.Errorf("failed to generate token: %v", err)
    }

    userResp := &model.UserResponse{
        ID:        user.ID,
        Name:      user.Name,
        Email:     user.Email,
        Role:      user.Role,
        CreatedAt: user.CreatedAt,
    }

    return tokenString, userResp, nil
}

// ValidateToken memvalidasi JWT token dan mengembalikan claims
func (s *authService) ValidateToken(tokenString string) (*model.JWTClaims, error) {
    // Cek blacklist
    if expiry, exists := s.tokenBlacklist[tokenString]; exists && time.Now().Before(expiry) {
        return nil, errors.New("token has been revoked")
    }

    token, err := jwt.ParseWithClaims(tokenString, &model.JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
        if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
        }
        return []byte(s.jwtSecret), nil
    })
    if err != nil {
        return nil, fmt.Errorf("invalid token: %v", err)
    }

    claims, ok := token.Claims.(*model.JWTClaims)
    if !ok || !token.Valid {
        return nil, errors.New("invalid token claims")
    }
    if claims.Issuer != s.jwtIssuer {
        return nil, errors.New("invalid token issuer")
    }

    return claims, nil
}

// Logout menambahkan token ke blacklist
func (s *authService) Logout(tokenString string) error {
    claims, err := s.ValidateToken(tokenString)
    if err != nil {
        return err
    }

    s.tokenBlacklist[tokenString] = claims.ExpiresAt.Time
    return nil
}

// GetUserProfile mengambil profil pengguna berdasarkan ID
func (s *authService) GetUserProfile(userID int64) (*model.UserResponse, error) {
    user, err := s.userRepo.FindByID(userID)
    if err != nil {
        return nil, fmt.Errorf("user not found: %v", err)
    }

    return &model.UserResponse{
        ID:        user.ID,
        Name:      user.Name,
        Email:     user.Email,
        Role:      user.Role,
        CreatedAt: user.CreatedAt,
    }, nil
}
