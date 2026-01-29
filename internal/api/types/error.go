package types

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// ErrorType represents a machine-readable classification of application errors.
// It is intended to be stable, enumerable, and suitable for programmatic handling
// on both server and client sides.
type ErrorType string

const (
	// ErrorValidation indicates invalid or malformed input provided by the client.
	ErrorValidation ErrorType = "VALIDATION_ERROR"

	// ErrorAuthentication indicates failure to authenticate the request.
	ErrorAuthentication ErrorType = "AUTHENTICATION_ERROR"

	// ErrorAuthorization indicates the authenticated user lacks required permissions.
	ErrorAuthorization ErrorType = "AUTHORIZATION_ERROR"

	// ErrorNotFound indicates the requested resource does not exist.
	ErrorNotFound ErrorType = "NOT_FOUND"

	// ErrorConflict indicates a state conflict, such as duplicate resources.
	ErrorConflict ErrorType = "CONFLICT"

	// ErrorInternal represents an unexpected server-side failure.
	ErrorInternal ErrorType = "INTERNAL_ERROR"

	// ErrorTimeout indicates the request exceeded its allowed processing time.
	ErrorTimeout ErrorType = "TIMEOUT"
)

// ErrorDefinitions maps each ErrorType to its default HTTP status code
// and human-readable message. This centralizes error semantics and
// ensures consistent behavior across the API.
var ErrorDefinitions = map[ErrorType]struct {
	Message    string
	StatusCode int
}{
	ErrorValidation: {
		Message:    "Invalid input data",
		StatusCode: http.StatusBadRequest,
	},
	ErrorAuthentication: {
		Message:    "Authentication failed",
		StatusCode: http.StatusUnauthorized,
	},
	ErrorAuthorization: {
		Message:    "Access denied",
		StatusCode: http.StatusForbidden,
	},
	ErrorNotFound: {
		Message:    "Resource not found",
		StatusCode: http.StatusNotFound,
	},
	ErrorConflict: {
		Message:    "Resource conflict",
		StatusCode: http.StatusConflict,
	},
	ErrorInternal: {
		Message:    "Internal server error",
		StatusCode: http.StatusInternalServerError,
	},
	ErrorTimeout: {
		Message:    "Request timeout",
		StatusCode: http.StatusRequestTimeout,
	},
}

// ErrorWithContext represents a structured, application-level error
// that carries both semantic meaning (Type) and contextual information
// (Details and optional Cause).
//
// This type is intended to be propagated through the application layers
// and translated into HTTP responses at the API boundary.
type ErrorWithContext struct {
	// Type categorizes the error in a machine-readable form.
	Type ErrorType

	// Details provides additional context intended for clients or logs.
	Details string

	// Cause holds the underlying error, if any, for debugging or logging purposes.
	Cause error
}

// Error implements the error interface.
// It returns the default message associated with the error type.
func (e *ErrorWithContext) Error() string {
	def := ErrorDefinitions[e.Type]
	return def.Message
}

// NewError constructs a new ErrorWithContext with the given type,
// details, and underlying cause.
func NewError(t ErrorType, details string, cause error) *ErrorWithContext {
	return &ErrorWithContext{
		Type:    t,
		Details: details,
		Cause:   cause,
	}
}

// ValidationError creates a validation-related ErrorWithContext.
func ValidationError(details string) *ErrorWithContext {
	return NewError(ErrorValidation, details, nil)
}

// ConflictError creates a conflict-related ErrorWithContext.
func ConflictError(details string) *ErrorWithContext {
	return NewError(ErrorConflict, details, nil)
}

// NotFoundError creates a not-found ErrorWithContext for a given resource.
func NotFoundError(resource string) *ErrorWithContext {
	return NewError(ErrorNotFound, resource+" not found", nil)
}

// AuthorizationError creates an authorization-related ErrorWithContext.
func AuthorizationError(details string) *ErrorWithContext {
	return NewError(ErrorAuthorization, details, nil)
}

// InternalError creates an internal error with an underlying cause.
func InternalError(details string, cause error) *ErrorWithContext {
	return NewError(ErrorInternal, details, cause)
}

// ToLegacyResponse converts an ErrorWithContext into the existing
// API response format used by the application.
//
// This function acts as a compatibility layer between structured
// domain errors and HTTP JSON responses.
func ToLegacyResponse(err *ErrorWithContext) (int, Response) {
	def := ErrorDefinitions[err.Type]

	return def.StatusCode, ErrorResponse(
		string(err.Type),
		def.Message,
		err.Details,
	)
}

// AbortWithError attaches the given error to the Gin context and
// immediately aborts further request processing.
//
// This is a convenience helper for handlers and middlewares.
func AbortWithError(c *gin.Context, err error) {
	_ = c.Error(err)
	c.Abort()
}

// Error represents the error object returned in API responses.
type Error struct {
	// Code is a machine-readable error identifier.
	Code string `json:"code"`

	// Message is a human-readable summary of the error.
	Message string `json:"message"`

	// Details provides optional, additional context.
	Details string `json:"details,omitempty"`
}

// ErrorResponse constructs a standardized error response payload.
func ErrorResponse(code, message, details string) Response {
	return Response{
		Success: false,
		Error: &Error{
			Code:    code,
			Message: message,
			Details: details,
		},
	}
}

// ValidationErrorResponse constructs a validation error response.
func ValidationErrorResponse(details string) Response {
	return ErrorResponse("VALIDATION_ERROR", "Invalid input data", details)
}

// AuthenticationErrorResponse constructs an authentication error response.
func AuthenticationErrorResponse(details string) Response {
	return ErrorResponse("AUTHENTICATION_ERROR", "Authentication failed", details)
}

// AuthorizationErrorResponse constructs an authorization error response.
func AuthorizationErrorResponse(details string) Response {
	return ErrorResponse("AUTHORIZATION_ERROR", "Access denied", details)
}

// NotFoundErrorResponse constructs a not-found error response.
func NotFoundErrorResponse(resource string) Response {
	return ErrorResponse("NOT_FOUND", "Resource not found", resource+" not found")
}

// ConflictErrorResponse constructs a conflict error response.
func ConflictErrorResponse(details string) Response {
	return ErrorResponse("CONFLICT", "Resource conflict", details)
}

// InternalErrorResponse constructs an internal server error response.
func InternalErrorResponse(details string) Response {
	return ErrorResponse("INTERNAL_ERROR", "Internal server error", details)
}

// TimeoutErrorResponse constructs a timeout error response.
func TimeoutErrorResponse(details string) Response {
	return ErrorResponse("TIMEOUT", "Request timeout", details)
}
