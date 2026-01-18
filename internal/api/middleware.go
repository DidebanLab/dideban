package api

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"dideban/internal/api/types"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/rs/zerolog/log"
)

// ErrorWithContext represents a structured error with context
type ErrorWithContext struct {
	Type       string
	Message    string
	Details    string
	StatusCode int
	Cause      error
}

func (e *ErrorWithContext) Error() string {
	return fmt.Sprintf("%s: %s", e.Type, e.Message)
}

// ErrorHandler middleware handles errors and converts them to consistent API responses
func ErrorHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()

		if len(c.Errors) > 0 {
			err := c.Errors.Last()
			handleError(c, err.Err)
		}
	}
}

// handleError converts different error types to appropriate HTTP responses
func handleError(c *gin.Context, err error) {
	// Skip if response already written
	if c.Writer.Written() {
		return
	}

	// Log the error with context
	logError(c, err)

	// Handle custom API errors
	var apiErr *ErrorWithContext
	if errors.As(err, &apiErr) {
		c.JSON(apiErr.StatusCode, types.ErrorResponse(apiErr.Type, apiErr.Message, apiErr.Details))
		return
	}

	// Handle validation errors from gin binding
	var validationErrors validator.ValidationErrors
	if errors.As(err, &validationErrors) {
		details := formatValidationErrors(validationErrors)
		c.JSON(http.StatusBadRequest, types.ValidationErrorResponse(details))
		return
	}

	// Handle database errors
	if isDatabaseError(err) {
		handleDatabaseError(c, err)
		return
	}

	// Handle gin binding errors
	if strings.Contains(err.Error(), "bind") || strings.Contains(err.Error(), "unmarshal") {
		c.JSON(http.StatusBadRequest, types.ValidationErrorResponse("Invalid request format"))
		return
	}

	// Handle context cancellation
	if errors.Is(err, c.Request.Context().Err()) {
		c.JSON(http.StatusRequestTimeout, types.TimeoutErrorResponse("Request took too long to process"))
		return
	}

	// Default to internal server error
	c.JSON(http.StatusInternalServerError, types.InternalErrorResponse("An unexpected error occurred"))
}

// logError logs the error with appropriate context and level
func logError(c *gin.Context, err error) {
	logEvent := log.With().
		Err(err).
		Str("method", c.Request.Method).
		Str("path", c.Request.URL.Path).
		Str("ip", c.ClientIP()).
		Str("user_agent", c.Request.UserAgent())

	// Add user context if available
	if userID, exists := c.Get("user_id"); exists {
		logEvent = logEvent.Interface("user_id", userID)
	}

	// Add request ID if available
	if requestID := c.GetHeader("X-Request-ID"); requestID != "" {
		logEvent = logEvent.Str("request_id", requestID)
	}

	logger := logEvent.Logger()

	// Log at appropriate level based on error type
	var apiErr *ErrorWithContext
	if errors.As(err, &apiErr) {
		if apiErr.StatusCode >= 500 {
			logger.Error().Msg("API error occurred")
		} else if apiErr.StatusCode >= 400 {
			logger.Warn().Msg("API client error")
		} else {
			logger.Info().Msg("API error handled")
		}
	}
}

// formatValidationErrors formats validator.ValidationErrors into a readable string
func formatValidationErrors(validationErrors validator.ValidationErrors) string {
	var details []string
	for _, fieldError := range validationErrors {
		var message string
		switch fieldError.Tag() {
		case "required":
			message = fmt.Sprintf("Field '%s' is required", fieldError.Field())
		case "min":
			message = fmt.Sprintf("Field '%s' must be at least %s", fieldError.Field(), fieldError.Param())
		case "max":
			message = fmt.Sprintf("Field '%s' must be at most %s", fieldError.Field(), fieldError.Param())
		case "email":
			message = fmt.Sprintf("Field '%s' must be a valid email", fieldError.Field())
		case "oneof":
			message = fmt.Sprintf("Field '%s' must be one of: %s", fieldError.Field(), fieldError.Param())
		default:
			message = fmt.Sprintf("Field '%s' failed validation: %s", fieldError.Field(), fieldError.Tag())
		}
		details = append(details, message)
	}
	return strings.Join(details, "; ")
}

// isDatabaseError checks if an error is database-related
func isDatabaseError(err error) bool {
	if err == nil {
		return false
	}

	// Check for types database errors
	if errors.Is(err, sql.ErrNoRows) {
		return true
	}

	errStr := err.Error()
	dbErrorKeywords := []string{
		"database",
		"sql:",
		"connection",
		"constraint",
		"foreign key",
		"unique",
		"duplicate",
		"deadlock",
		"timeout",
	}

	for _, keyword := range dbErrorKeywords {
		if strings.Contains(strings.ToLower(errStr), keyword) {
			return true
		}
	}

	return false
}

// handleDatabaseError handles database-specific errors
func handleDatabaseError(c *gin.Context, err error) {
	if errors.Is(err, sql.ErrNoRows) {
		c.JSON(http.StatusNotFound, types.NotFoundErrorResponse("resource"))
		return
	}

	errStr := strings.ToLower(err.Error())

	// Handle constraint violations
	if strings.Contains(errStr, "unique") || strings.Contains(errStr, "duplicate") {
		c.JSON(http.StatusConflict, types.ConflictErrorResponse("Resource already exists"))
		return
	}

	if strings.Contains(errStr, "foreign key") {
		c.JSON(http.StatusBadRequest, types.ValidationErrorResponse("Invalid reference to related resource"))
		return
	}

	if strings.Contains(errStr, "constraint") {
		c.JSON(http.StatusBadRequest, types.ValidationErrorResponse("Data constraint violation"))
		return
	}

	// Handle connection issues
	if strings.Contains(errStr, "connection") || strings.Contains(errStr, "timeout") {
		c.JSON(http.StatusServiceUnavailable, types.ErrorResponse(
			"SERVICE_UNAVAILABLE",
			"Database temporarily unavailable",
			"Please try again later",
		))
		return
	}

	// Generic database error
	c.JSON(http.StatusInternalServerError, types.InternalErrorResponse("Database operation failed"))
}

// SecurityHeaders middleware adds security headers
func SecurityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("X-XSS-Protection", "1; mode=block")
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
		c.Next()
	}
}

// RateLimit middleware implements basic rate limiting per IP address
func RateLimit() gin.HandlerFunc {
	// Simple in-memory rate limiter
	type rateLimiter struct {
		requests map[string][]int64
		limit    int
		window   int64 // in seconds
	}

	limiter := &rateLimiter{
		requests: make(map[string][]int64),
		limit:    100, // 100 requests per window
		window:   60,  // 60 seconds
	}

	return func(c *gin.Context) {
		ip := c.ClientIP()
		now := time.Now().Unix()

		// Clean old requests
		if requests, exists := limiter.requests[ip]; exists {
			var validRequests []int64
			for _, timestamp := range requests {
				if now-timestamp < limiter.window {
					validRequests = append(validRequests, timestamp)
				}
			}
			limiter.requests[ip] = validRequests
		}

		// Check rate limit
		if len(limiter.requests[ip]) >= limiter.limit {
			c.JSON(http.StatusTooManyRequests, types.ErrorResponse(
				"RATE_LIMIT_EXCEEDED",
				"Too many requests",
				fmt.Sprintf("Rate limit of %d requests per %d seconds exceeded", limiter.limit, limiter.window),
			))
			c.Abort()
			return
		}

		// Add current request
		limiter.requests[ip] = append(limiter.requests[ip], now)
		c.Next()
	}
}

// ContentType middleware ensures proper content type handling
func ContentType() gin.HandlerFunc {
	return func(c *gin.Context) {
		// For POST and PUT requests, ensure JSON content type
		if c.Request.Method == "POST" || c.Request.Method == "PUT" {
			contentType := c.GetHeader("Content-Type")
			if contentType != "" && contentType != "application/json" {
				c.JSON(http.StatusUnsupportedMediaType, types.ErrorResponse(
					"UNSUPPORTED_MEDIA_TYPE",
					"Content-Type must be application/json",
					"Received: "+contentType,
				))
				c.Abort()
				return
			}
		}

		// Set response content type
		c.Header("Content-Type", "application/json")
		c.Next()
	}
}

// RequestID middleware adds a unique request ID to each request
func RequestID() gin.HandlerFunc {
	return func(c *gin.Context) {
		requestID := c.GetHeader("X-Request-ID")
		if requestID == "" {
			// Generate a simple request ID (in production, use UUID)
			requestID = fmt.Sprintf("%d-%s", time.Now().UnixNano(), c.ClientIP())
		}

		c.Header("X-Request-ID", requestID)
		c.Set("request_id", requestID)
		c.Next()
	}
}

// PanicRecovery provides custom panic recovery with structured error response
func PanicRecovery() gin.HandlerFunc {
	return gin.CustomRecovery(func(c *gin.Context, recovered interface{}) {
		if err, ok := recovered.(string); ok {
			c.JSON(http.StatusInternalServerError, types.ErrorResponse(
				"PANIC_RECOVERY",
				"Internal server error",
				"An unexpected error occurred",
			))
			// Log the panic
			fmt.Printf("Panic recovered: %s\n", err)
		} else {
			c.JSON(http.StatusInternalServerError, types.ErrorResponse(
				"PANIC_RECOVERY",
				"Internal server error",
				"An unexpected error occurred",
			))
			// Log the panic
			fmt.Printf("Panic recovered: %v\n", recovered)
		}
		c.Abort()
	})
}

// LoggerMiddleware creates a custom logging middleware.
//
// Returns:
//   - gin.HandlerFunc: Gin middleware function
func LoggerMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		raw := c.Request.URL.RawQuery

		// Process request
		c.Next()

		// Calculate latency
		latency := time.Since(start)

		// Build log fields
		fields := []interface{}{
			"method", c.Request.Method,
			"path", path,
			"status", c.Writer.Status(),
			"latency", latency,
			"ip", c.ClientIP(),
			"user_agent", c.Request.UserAgent(),
		}

		if raw != "" {
			fields = append(fields, "query", raw)
		}

		// Log based on status code
		status := c.Writer.Status()
		logEvent := log.With().
			Str("method", c.Request.Method).
			Str("path", path).
			Int("status", status).
			Dur("latency", latency).
			Str("ip", c.ClientIP()).
			Str("user_agent", c.Request.UserAgent())

		if raw != "" {
			logEvent = logEvent.Str("query", raw)
		}

		logger := logEvent.Logger()
		if status >= 500 {
			logger.Error().Msg("HTTP request")
		} else if status >= 400 {
			logger.Warn().Msg("HTTP request")
		} else {
			logger.Info().Msg("HTTP request")
		}
	}
}

// TimeoutMiddleware creates a request timeout middleware.
//
// Parameters:
//   - timeout: Request timeout duration
//
// Returns:
//   - gin.HandlerFunc: Gin middleware function
func TimeoutMiddleware(timeout time.Duration) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(c.Request.Context(), timeout)
		defer cancel()

		c.Request = c.Request.WithContext(ctx)
		c.Next()
	}
}
