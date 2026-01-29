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
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// ErrorHandler is a top-level Gin middleware responsible for catching
// errors accumulated during request processing and converting them
// into a unified, client-friendly HTTP response.
//
// This middleware should be registered after all other middlewares
// that may produce errors via c.Error(err).
func ErrorHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Execute remaining handlers in the chain
		c.Next()

		// If no errors were recorded during the request lifecycle,
		// there is nothing to handle.
		if len(c.Errors) == 0 {
			return
		}

		// Handle the last error added to the context.
		// Gin preserves error order, with the most recent error last.
		handleError(c, c.Errors.Last().Err)
	}
}

// handleError inspects the given error and maps it to an appropriate
// HTTP status code and response body based on its type and context.
//
// It centralizes error-to-response translation to keep handlers clean
// and enforce consistent API behavior.
func handleError(c *gin.Context, err error) {
	// If the response has already been written, do not attempt
	// to modify headers or body.
	if c.Writer.Written() {
		return
	}

	// Log the error with request-scoped metadata before responding.
	logError(c, err)

	// Handle domain-level API errors with structured context.
	var apiErr *types.ErrorWithContext
	if errors.As(err, &apiErr) {
		status, resp := types.ToLegacyResponse(apiErr)
		c.JSON(status, resp)
		c.Abort()
		return
	}

	// Handle validation errors produced by Gin's binding mechanism.
	var validationErrors validator.ValidationErrors
	if errors.As(err, &validationErrors) {
		details := formatValidationErrors(validationErrors)
		c.JSON(http.StatusBadRequest, types.ValidationErrorResponse(details))
		return
	}

	// Handle database-related errors in a dedicated flow.
	if isDatabaseError(err) {
		handleDatabaseError(c, err)
		return
	}

	// Handle malformed request payloads or binding failures.
	if strings.Contains(err.Error(), "bind") || strings.Contains(err.Error(), "unmarshal") {
		c.JSON(http.StatusBadRequest, types.ValidationErrorResponse("Invalid request format"))
		return
	}

	// Handle request context cancellation (timeouts, client disconnects).
	if errors.Is(err, c.Request.Context().Err()) {
		c.JSON(http.StatusRequestTimeout, types.TimeoutErrorResponse("Request took too long to process"))
		return
	}

	// Fallback for any unclassified error.
	c.Set("error_message", "unexpected internal error")
	c.JSON(http.StatusInternalServerError, types.InternalErrorResponse("An unexpected error occurred"))
}

// logError logs the given error using structured logging and enriches
// the log entry with request metadata such as IP, method, path,
// user identity, and request ID when available.
//
// Logging level is determined dynamically based on error severity.
func logError(c *gin.Context, err error) {
	// Mark this request as already logged to avoid duplicate logs.
	c.Set("error_logged", true)

	// Initialize a structured log event with request context.
	logEvent := log.With().
		Err(err).
		Str("ip", c.ClientIP()).
		Str("method", c.Request.Method).
		Str("path", c.Request.URL.Path).
		Str("user_agent", c.Request.UserAgent())

	// Attach authenticated user identifier if present in context.
	if userID, exists := c.Get("user_id"); exists {
		logEvent = logEvent.Interface("user_id", userID)
	}

	// Attach request ID for traceability across services.
	if requestID := c.GetHeader("X-Request-ID"); requestID != "" {
		logEvent = logEvent.Str("request_id", requestID)
	}

	logger := logEvent.Logger()

	// Apply severity level based on API error classification.
	var apiErr *types.ErrorWithContext
	if errors.As(err, &apiErr) {
		def := types.ErrorDefinitions[apiErr.Type]

		var evt *zerolog.Event

		if def.StatusCode >= 500 {
			evt = logger.Error()
		} else if def.StatusCode >= 400 {
			evt = logger.Warn()
		} else {
			evt = logger.Info()
		}

		// Log the underlying cause if present.
		if apiErr.Cause != nil {
			evt = evt.Err(apiErr.Cause)
		}

		// Include additional error details when available.
		if apiErr.Details != "" {
			evt = evt.Str("details", apiErr.Details)
		}

		evt.
			Str("error_type", string(apiErr.Type)).
			Int("status", def.StatusCode).
			Msg("API error")
	}
}

// formatValidationErrors converts validator.ValidationErrors into a
// concise, human-readable string suitable for API responses.
//
// Each field error is mapped to a descriptive message based on
// its validation tag.
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

// isDatabaseError determines whether the given error is likely related
// to a database operation by checking known error types and keywords.
//
// This function is intentionally heuristic-based to support multiple
// database drivers without tight coupling.
func isDatabaseError(err error) bool {
	if err == nil {
		return false
	}

	// Explicitly check for common sentinel database errors.
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

// handleDatabaseError maps database-specific errors to appropriate
// HTTP responses while preserving abstraction boundaries between
// the persistence layer and API layer.
func handleDatabaseError(c *gin.Context, err error) {
	// Handle missing records explicitly.
	if errors.Is(err, sql.ErrNoRows) {
		c.JSON(http.StatusNotFound, types.NotFoundErrorResponse("resource"))
		return
	}

	errStr := strings.ToLower(err.Error())

	// Handle unique constraint violations.
	if strings.Contains(errStr, "unique") || strings.Contains(errStr, "duplicate") {
		c.JSON(http.StatusConflict, types.ConflictErrorResponse("Resource already exists"))
		return
	}

	// Handle invalid foreign key references.
	if strings.Contains(errStr, "foreign key") {
		c.JSON(http.StatusBadRequest, types.ValidationErrorResponse("Invalid reference to related resource"))
		return
	}

	// Handle generic constraint violations.
	if strings.Contains(errStr, "constraint") {
		c.JSON(http.StatusBadRequest, types.ValidationErrorResponse("Data constraint violation"))
		return
	}

	// Handle database connectivity or availability issues.
	if strings.Contains(errStr, "connection") || strings.Contains(errStr, "timeout") {
		c.JSON(http.StatusServiceUnavailable, types.ErrorResponse(
			"SERVICE_UNAVAILABLE",
			"Database temporarily unavailable",
			"Please try again later",
		))
		return
	}

	// Fallback for uncategorized database errors.
	c.JSON(http.StatusInternalServerError, types.InternalErrorResponse("Database operation failed"))
}

// SecurityHeaders is a middleware that injects common HTTP security
// headers to reduce exposure to common web vulnerabilities.
func SecurityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("X-XSS-Protection", "1; mode=block")
		//c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
		c.Next()
	}
}

// RateLimit implements a simple, in-memory, IP-based rate limiting
// mechanism to protect the API from abuse.
//
// This implementation is intentionally minimal and not suitable
// for distributed or high-throughput environments.
func RateLimit() gin.HandlerFunc {
	// Internal rate limiter state container.
	type rateLimiter struct {
		requests map[string][]int64
		limit    int
		window   int64 // window duration in seconds
	}

	limiter := &rateLimiter{
		requests: make(map[string][]int64),
		limit:    100, // maximum requests per window
		window:   60,  // time window in seconds
	}

	return func(c *gin.Context) {
		ip := c.ClientIP()
		now := time.Now().Unix()

		// Remove expired request timestamps.
		if requests, exists := limiter.requests[ip]; exists {
			var validRequests []int64
			for _, timestamp := range requests {
				if now-timestamp < limiter.window {
					validRequests = append(validRequests, timestamp)
				}
			}
			limiter.requests[ip] = validRequests
		}

		// Enforce rate limit.
		if len(limiter.requests[ip]) >= limiter.limit {
			c.JSON(http.StatusTooManyRequests, types.ErrorResponse(
				"RATE_LIMIT_EXCEEDED",
				"Too many requests",
				fmt.Sprintf("Rate limit of %d requests per %d seconds exceeded", limiter.limit, limiter.window),
			))
			c.Abort()
			return
		}

		// Record current request timestamp.
		limiter.requests[ip] = append(limiter.requests[ip], now)
		c.Next()
	}
}

// ContentType enforces JSON request payloads for write operations
// and ensures that all responses declare application/json.
func ContentType() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Validate Content-Type for request bodies.
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

		// Enforce JSON responses.
		c.Header("Content-Type", "application/json")
		c.Next()
	}
}

// RequestID ensures that every request has a unique identifier,
// either propagated from the client or generated locally.
//
// The request ID is attached to both the request context and response.
func RequestID() gin.HandlerFunc {
	return func(c *gin.Context) {
		requestID := c.GetHeader("X-Request-ID")
		if requestID == "" {
			// Lightweight request ID generation.
			// For production systems, a UUID is recommended.
			requestID = fmt.Sprintf("%d-%s", time.Now().UnixNano(), c.ClientIP())
		}

		c.Header("X-Request-ID", requestID)
		c.Set("request_id", requestID)
		c.Next()
	}
}

// PanicRecovery provides a custom panic recovery middleware that
// converts panics into structured JSON error responses and prevents
// the server from crashing.
func PanicRecovery() gin.HandlerFunc {
	return gin.CustomRecovery(func(c *gin.Context, recovered interface{}) {
		if err, ok := recovered.(string); ok {
			c.JSON(http.StatusInternalServerError, types.ErrorResponse(
				"PANIC_RECOVERY",
				"Internal server error",
				"An unexpected error occurred",
			))
			// Log recovered panic message.
			fmt.Printf("Panic recovered: %s\n", err)
		} else {
			c.JSON(http.StatusInternalServerError, types.ErrorResponse(
				"PANIC_RECOVERY",
				"Internal server error",
				"An unexpected error occurred",
			))
			// Log recovered panic payload.
			fmt.Printf("Panic recovered: %v\n", recovered)
		}
		c.Abort()
	})
}

// LoggerMiddleware provides structured request logging with latency,
// status code, and request metadata.
//
// Logging level is derived from the final HTTP status code.
func LoggerMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		raw := c.Request.URL.RawQuery

		// Execute downstream handlers.
		c.Next()

		// Skip logging if the error has already been logged.
		if _, exists := c.Get("error_logged"); exists {
			return
		}

		// Measure request latency.
		latency := time.Since(start)

		// Prepare structured log context.
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

		// Initialize logger with common request fields.
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

		// Attach aggregated Gin errors if present.
		if len(c.Errors) > 0 {
			logEvent = logEvent.Str("error", c.Errors.String())
		}

		// Emit log entry with appropriate severity.
		if status >= 500 {
			logger.Error().Msg("request failed")
		} else if status >= 400 {
			logger.Warn().Msg("client error")
		} else {
			logger.Info().Msg("request completed")
		}
	}
}

// TimeoutMiddleware applies a request-scoped context timeout,
// ensuring that long-running handlers are canceled gracefully.
//
// Any downstream operation observing the request context
// should respect the timeout signal.
func TimeoutMiddleware(timeout time.Duration) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(c.Request.Context(), timeout)
		defer cancel()

		c.Request = c.Request.WithContext(ctx)
		c.Next()
	}
}
