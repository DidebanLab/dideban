package auth

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"dideban/internal/api/types"
	"dideban/internal/storage"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// Handler handles authentication-related HTTP requests
type Handler struct {
	storage      *storage.Storage
	tokenManager *TokenManager
}

// NewHandler creates a new authentication handler
func NewHandler(storage *storage.Storage, jwtSecret []byte, tokenTTL time.Duration) *Handler {
	return &Handler{
		storage:      storage,
		tokenManager: NewTokenManager(jwtSecret, tokenTTL),
	}
}

// Stop stops the handler and cleans up resources
func (h *Handler) Stop() {
	if h.tokenManager != nil {
		h.tokenManager.Stop()
	}
}

// GetTokenManager returns the token manager instance for use by middleware
func (h *Handler) GetTokenManager() *TokenManager {
	return h.tokenManager
}

// LoginRequest represents the login request payload
type LoginRequest struct {
	Username string `json:"username" binding:"required,min=1,max=50"`
	Password string `json:"password" binding:"required,min=4"`
}

// LoginResponse represents the login response payload
type LoginResponse struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
	User      UserInfo  `json:"user"`
}

// UserInfo represents user information in responses
type UserInfo struct {
	ID       int64  `json:"id"`
	Username string `json:"username"`
	FullName string `json:"full_name"`
}

// Login handles user authentication
func (h *Handler) Login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, types.ValidationErrorResponse(err.Error()))
		return
	}

	// Find admin by username
	var admin storage.Admin
	if err := h.storage.DB().Where("username = ?", req.Username).First(&admin).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.JSON(http.StatusNotFound, types.NotFoundErrorResponse("Admin not found"))
		} else {
			c.JSON(http.StatusInternalServerError, types.InternalErrorResponse("Failed to get user details"))
		}
		return
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(admin.Password), []byte(req.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, types.AuthenticationErrorResponse("Invalid credentials"))
		return
	}

	// Generate JWT token
	token, expiresAt, err := h.tokenManager.GenerateToken(admin.ID, admin.Username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, types.InternalErrorResponse("Failed to generate token"))
		return
	}

	response := LoginResponse{
		Token:     token,
		ExpiresAt: expiresAt,
		User: UserInfo{
			ID:       admin.ID,
			Username: admin.Username,
			FullName: admin.FullName,
		},
	}

	c.JSON(http.StatusOK, types.SuccessResponse(response))
}

// Logout handles user logout by blacklisting the token
func (h *Handler) Logout(c *gin.Context) {
	// Extract token from Authorization header
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		c.JSON(http.StatusBadRequest, types.ValidationErrorResponse("Authorization header required"))
		return
	}

	// Check Bearer prefix
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || parts[0] != "Bearer" {
		c.JSON(http.StatusBadRequest, types.ValidationErrorResponse("Invalid authorization header format"))
		return
	}

	token := parts[1]

	// Blacklist the token
	if err := h.tokenManager.BlacklistToken(token); err != nil {
		c.JSON(http.StatusBadRequest, types.ValidationErrorResponse("Invalid token"))
		return
	}

	c.JSON(http.StatusOK, types.SuccessResponse(gin.H{"message": "Logged out successfully"}))
}

// Me returns current user information
func (h *Handler) Me(c *gin.Context) {
	// Extract token from Authorization header
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		c.JSON(http.StatusUnauthorized, types.AuthenticationErrorResponse("Authorization header required"))
		return
	}

	// Check Bearer prefix
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || parts[0] != "Bearer" {
		c.JSON(http.StatusUnauthorized, types.AuthenticationErrorResponse("Invalid authorization header format"))
		return
	}

	token := parts[1]

	// Validate token and get claims
	claims, err := h.tokenManager.ValidateToken(token)
	if err != nil {
		c.JSON(http.StatusUnauthorized, types.AuthenticationErrorResponse("Invalid or expired token"))
		return
	}

	// Get admin details from database
	var admin storage.Admin
	if err := h.storage.DB().Where("id = ?", claims.UserID).First(&admin).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.JSON(http.StatusNotFound, types.NotFoundErrorResponse("Admin not found"))
		} else {
			c.JSON(http.StatusInternalServerError, types.InternalErrorResponse("Failed to get user details"))
		}
		return
	}

	userInfo := UserInfo{
		ID:       admin.ID,
		Username: admin.Username,
		FullName: admin.FullName,
	}

	c.JSON(http.StatusOK, types.SuccessResponse(userInfo))
}

// Refresh handles token refresh
func (h *Handler) Refresh(c *gin.Context) {
	// Extract token from Authorization header
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		c.JSON(http.StatusUnauthorized, types.AuthenticationErrorResponse("Authorization header required"))
		return
	}

	// Check Bearer prefix
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || parts[0] != "Bearer" {
		c.JSON(http.StatusUnauthorized, types.AuthenticationErrorResponse("Invalid authorization header format"))
		return
	}

	token := parts[1]

	// Refresh the token
	newToken, expiresAt, err := h.tokenManager.RefreshToken(token)
	if err != nil {
		c.JSON(http.StatusUnauthorized, types.AuthenticationErrorResponse("Cannot refresh token"))
		return
	}

	// Get user info from the old token claims
	claims, err := h.tokenManager.ValidateToken(newToken)
	if err != nil {
		c.JSON(http.StatusInternalServerError, types.InternalErrorResponse("Failed to validate new token"))
		return
	}

	// Get admin details from database
	var admin storage.Admin
	if err := h.storage.DB().Where("id = ?", claims.UserID).First(&admin).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.JSON(http.StatusNotFound, types.NotFoundErrorResponse("Admin not found"))
		} else {
			c.JSON(http.StatusInternalServerError, types.InternalErrorResponse("Failed to get user details"))
		}
		return
	}

	response := LoginResponse{
		Token:     newToken,
		ExpiresAt: expiresAt,
		User: UserInfo{
			ID:       admin.ID,
			Username: admin.Username,
			FullName: admin.FullName,
		},
	}

	c.JSON(http.StatusOK, types.SuccessResponse(response))
}
