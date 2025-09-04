package handler

import (
    "auth-service/internal/service"
    "context"
    "net/http"

    "github.com/gin-gonic/gin"
)

type Handler struct {
    svc *service.Service
}

func New(s *service.Service) *Handler {
    return &Handler{svc: s}
}

type registerReq struct {
    Name     string `json:"name" binding:"required"`
    Email    string `json:"email" binding:"required,email"`
    Password string `json:"password" binding:"required,min=6"`
}

type loginReq struct {
    Email    string `json:"email" binding:"required,email"`
    Password string `json:"password" binding:"required"`
}

type userResp struct {
    ID    int64  `json:"id"`
    Name  string `json:"name"`
    Email string `json:"email"`
}

type loginResp struct {
    Token string   `json:"token"`
    User  userResp `json:"user"`
}

func (h *Handler) Register(c *gin.Context) {
    var req registerReq
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }
    u, err := h.svc.Register(context.Background(), req.Name, req.Email, req.Password)
    if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }

    c.JSON(http.StatusCreated, userResp{ID: u.ID, Name: u.Name, Email: u.Email})
}

func (h *Handler) Login(c *gin.Context) {
    var req loginReq
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }
    token, u, err := h.svc.Login(context.Background(), req.Email, req.Password)
    if err != nil {
        c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
        return
    }

    resp := loginResp{
        Token: token,
        User:  userResp{ID: u.ID, Name: u.Name, Email: u.Email},
    }
    c.JSON(http.StatusOK, resp)
}
