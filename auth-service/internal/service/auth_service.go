package service

import (
    "auth-service/internal/config"
    "auth-service/internal/model"
    "auth-service/internal/repository"
    "context"
    "errors"
    "time"

    "github.com/golang-jwt/jwt/v5"
    "golang.org/x/crypto/bcrypt"
)

type Service struct {
    repo *repository.AuthRepository
    cfg  *config.Config
}

func New(repo *repository.AuthRepository, cfg *config.Config) *Service {
    return &Service{repo: repo, cfg: cfg}
}

func (s *Service) Register(ctx context.Context, name, email, password string) (*model.User, error) {
    exists, _ := s.repo.GetByEmail(ctx, email)
    if exists != nil {
        return nil, errors.New("email already registered")
    }
    hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
    if err != nil {
        return nil, err
    }
    u := &model.User{Name: name, Email: email, PasswordHash: string(hash)}
    if err := s.repo.CreateUser(ctx, u); err != nil {
        return nil, err
    }
    return u, nil
}

func (s *Service) Login(ctx context.Context, email, password string) (string, *model.User, error) {
    u, err := s.repo.GetByEmail(ctx, email)
    if err != nil || u == nil {
        return "", nil, errors.New("invalid credentials")
    }
    if err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)); err != nil {
        return "", nil, errors.New("invalid credentials")
    }

    claims := jwt.MapClaims{
        "sub":   u.ID,
        "email": u.Email,
        "name":  u.Name,
        "iss":   s.cfg.JWTIssuer,
        "iat":   time.Now().Unix(),
        "exp":   time.Now().Add(time.Minute * time.Duration(s.cfg.JWTTTLMinutes)).Unix(),
    }

    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    signed, err := token.SignedString([]byte(s.cfg.JWTSecret))
    if err != nil {
        return "", nil, err
    }
    return signed, u, nil
}
