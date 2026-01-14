package auth

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Claims represents the JWT claims structure
type Claims struct {
	UserID   int64  `json:"user_id"`
	Username string `json:"username"`
	jwt.RegisteredClaims
}

// TokenManager handles JWT token operations
type TokenManager struct {
	secret      []byte
	tokenTTL    time.Duration
	blacklist   map[string]time.Time // token ID -> expiration time
	blacklistMu sync.RWMutex
	stopCleanup chan struct{}
}

// NewTokenManager creates a new token manager instance
func NewTokenManager(secret []byte, tokenTTL time.Duration) *TokenManager {
	tm := &TokenManager{
		secret:      secret,
		tokenTTL:    tokenTTL,
		blacklist:   make(map[string]time.Time),
		stopCleanup: make(chan struct{}),
	}

	// Start cleanup goroutine for expired blacklisted tokens
	go tm.cleanupBlacklist()

	return tm
}

// GenerateToken creates a new JWT token for the given user
func (tm *TokenManager) GenerateToken(userID int64, username string) (string, time.Time, error) {
	now := time.Now()
	expiresAt := now.Add(tm.tokenTTL)

	claims := &Claims{
		UserID:   userID,
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        fmt.Sprintf("%d_%d", userID, now.UnixNano()),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    "dideban",
			Subject:   username,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(tm.secret)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to sign token: %w", err)
	}

	return tokenString, expiresAt, nil
}

// ValidateToken validates a JWT token and returns the claims
func (tm *TokenManager) ValidateToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		// Verify signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return tm.secret, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token claims")
	}

	// Check if token is blacklisted
	if tm.isBlacklisted(claims.ID) {
		return nil, errors.New("token has been revoked")
	}

	return claims, nil
}

// BlacklistToken adds a token to the blacklist (for logout)
func (tm *TokenManager) BlacklistToken(tokenString string) error {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return tm.secret, nil
	})

	if err != nil {
		return fmt.Errorf("failed to parse token for blacklisting: %w", err)
	}

	claims, ok := token.Claims.(*Claims)
	if !ok {
		return errors.New("invalid token claims")
	}

	tm.blacklistMu.Lock()
	defer tm.blacklistMu.Unlock()

	// Add token to blacklist with its expiration time
	tm.blacklist[claims.ID] = claims.ExpiresAt.Time

	return nil
}

// isBlacklisted checks if a token ID is in the blacklist
func (tm *TokenManager) isBlacklisted(tokenID string) bool {
	tm.blacklistMu.RLock()
	defer tm.blacklistMu.RUnlock()

	_, exists := tm.blacklist[tokenID]
	return exists
}

// cleanupBlacklist removes expired tokens from the blacklist
func (tm *TokenManager) cleanupBlacklist() {
	ticker := time.NewTicker(1 * time.Hour) // Cleanup every hour
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			now := time.Now()
			tm.blacklistMu.Lock()

			for tokenID, expiresAt := range tm.blacklist {
				if now.After(expiresAt) {
					delete(tm.blacklist, tokenID)
				}
			}

			tm.blacklistMu.Unlock()
		case <-tm.stopCleanup:
			return
		}
	}
}

// Stop stops the cleanup goroutine
func (tm *TokenManager) Stop() {
	close(tm.stopCleanup)
}

// RefreshToken creates a new token from an existing valid token
func (tm *TokenManager) RefreshToken(tokenString string) (string, time.Time, error) {
	claims, err := tm.ValidateToken(tokenString)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("cannot refresh invalid token: %w", err)
	}

	// Blacklist the old token
	if err := tm.BlacklistToken(tokenString); err != nil {
		return "", time.Time{}, fmt.Errorf("failed to blacklist old token: %w", err)
	}

	// Generate new token with same user info
	return tm.GenerateToken(claims.UserID, claims.Username)
}
