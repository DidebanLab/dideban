// Package checks provides HTTP/HTTPS monitoring functionality.
package checks

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"dideban/internal/config"
	"dideban/internal/storage"
)

// HTTPConfig represents HTTP check configuration.
type HTTPConfig struct {
	Method          string            `json:"method"`           // HTTP method (default: GET)
	Headers         map[string]string `json:"headers"`          // Custom headers
	Body            string            `json:"body"`             // Request body
	ExpectedStatus  int               `json:"expected_status"`  // Expected status code (default: 200)
	ExpectedContent string            `json:"expected_content"` // Expected content in response
	FollowRedirects bool              `json:"follow_redirects"` // Follow redirects (default: true)
	VerifySSL       bool              `json:"verify_ssl"`       // Verify SSL certificates (default: true)
	TimeoutSeconds  int               `json:"timeout_seconds"`  // Request timeout (default: 30)
}

// HTTPChecker implements HTTP/HTTPS monitoring checks.
type HTTPChecker struct {
	*BaseChecker
	client   *http.Client
	defaults *config.HTTPDefaultsConfig
}

// NewHTTPChecker creates a new HTTP checker instance.
//
// Parameters:
//   - cfg: Application configuration for defaults
//
// Returns:
//   - *HTTPChecker: Initialized HTTP checker
func NewHTTPChecker(cfg *config.Config) *HTTPChecker {
	return &HTTPChecker{
		BaseChecker: NewBaseChecker(),
		client:      &http.Client{}, // Client will be configured per request
		defaults:    &cfg.Checks.HTTP,
	}
}

// Type returns the checker type identifier.
//
// Returns:
//   - string: Type identifier "http"
func (h *HTTPChecker) Type() string {
	return "http"
}

// Check executes an HTTP/HTTPS monitoring check.
//
// Parameters:
//   - ctx: Context for cancellation and timeout
//   - check: Check configuration containing target URL and settings
//
// Returns:
//   - *storage.CheckHistory: Result of the HTTP check
//   - error: Any error that occurred during the check
func (h *HTTPChecker) Check(ctx context.Context, check *storage.Check) (*storage.CheckHistory, error) {
	startTime := time.Now()

	// Parse and validate configuration
	cfg, err := h.parseConfig(check.Config)
	if err != nil {
		responseTime := time.Since(startTime).Milliseconds()
		status := h.DetermineErrorStatus(err)
		return h.CreateErrorResult(check.ID, status, fmt.Errorf("invalid config: %w", err), responseTime, nil), err
	}

	// Configure HTTP client with timeout
	h.configureClient(cfg)

	// Create HTTP request
	req, err := h.createRequest(ctx, check.Target, cfg)
	if err != nil {
		responseTime := time.Since(startTime).Milliseconds()
		status := h.DetermineErrorStatus(err)
		return h.CreateErrorResult(check.ID, status, fmt.Errorf("failed to create request: %w", err), responseTime, nil), err
	}

	// Execute request
	resp, err := h.client.Do(req)
	responseTime := time.Since(startTime).Milliseconds()

	if err != nil {
		status := h.DetermineErrorStatus(err)
		return h.CreateErrorResult(check.ID, status, fmt.Errorf("request failed: %w", err), responseTime, nil), err
	}
	defer resp.Body.Close()

	// Validate response
	result, err := h.validateResponse(check.ID, resp, cfg, responseTime)
	if err != nil {
		return result, err
	}

	return result, nil
}

// parseConfig parses the HTTP check configuration.
// Config is already validated by storage layer, so we just parse and apply defaults.
// However, we do basic validation for direct checker usage (like in tests).
//
// Parameters:
//   - configStr: JSON configuration string from the check (already validated)
//
// Returns:
//   - *HTTPConfig: Parsed configuration with defaults applied
//   - error: Any error that occurred during parsing
func (h *HTTPChecker) parseConfig(configStr string) (*HTTPConfig, error) {
	// Start with defaults from application config
	cfg := &HTTPConfig{
		Method:          h.defaults.Method,
		Headers:         make(map[string]string),
		Body:            h.defaults.Body,
		ExpectedStatus:  h.defaults.ExpectedStatus,
		ExpectedContent: h.defaults.ExpectedContent,
		FollowRedirects: h.defaults.FollowRedirects,
		VerifySSL:       h.defaults.VerifySSL,
		TimeoutSeconds:  h.defaults.TimeoutSeconds,
	}

	// Copy default headers
	for k, v := range h.defaults.Headers {
		cfg.Headers[k] = v
	}

	// Parse JSON config if provided (config is already validated by storage)
	if configStr != "" && configStr != "{}" {
		// Parse into storage format first
		var storageConfig storage.HTTPCheckConfig
		if err := json.Unmarshal([]byte(configStr), &storageConfig); err != nil {
			return nil, fmt.Errorf("failed to parse config: %w", err)
		}

		// Apply values from config, keeping defaults for unspecified fields
		if storageConfig.Method != "" {
			cfg.Method = strings.ToUpper(storageConfig.Method)
		}
		if storageConfig.Body != "" {
			cfg.Body = storageConfig.Body
		}
		if storageConfig.ExpectedStatus != 0 {
			cfg.ExpectedStatus = storageConfig.ExpectedStatus
		}
		if storageConfig.ExpectedContent != "" {
			cfg.ExpectedContent = storageConfig.ExpectedContent
		}
		cfg.FollowRedirects = storageConfig.FollowRedirects
		cfg.VerifySSL = storageConfig.VerifySSL

		// Merge headers (config headers override defaults)
		for k, v := range storageConfig.Headers {
			cfg.Headers[k] = v
		}
	}

	// Basic validation for direct checker usage (like in tests)
	// This is a safety net when checker is used without storage validation
	validMethods := map[string]bool{
		"GET": true, "POST": true, "PUT": true, "DELETE": true,
		"HEAD": true, "OPTIONS": true, "PATCH": true,
	}
	if !validMethods[cfg.Method] {
		return nil, fmt.Errorf("invalid HTTP method: %s", cfg.Method)
	}
	if cfg.ExpectedStatus < 100 || cfg.ExpectedStatus > 599 {
		return nil, fmt.Errorf("invalid expected status code: %d (must be between 100-599)", cfg.ExpectedStatus)
	}

	return cfg, nil
}

// configureClient configures the HTTP client based on the configuration.
func (h *HTTPChecker) configureClient(cfg *HTTPConfig) {
	h.client.Timeout = time.Duration(cfg.TimeoutSeconds) * time.Second

	h.client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if !cfg.FollowRedirects {
			return http.ErrUseLastResponse
		}
		// Limit redirects to prevent infinite loops
		if len(via) >= 10 {
			return fmt.Errorf("too many redirects")
		}
		return nil
	}
}

// createRequest creates an HTTP request based on the configuration.
//
// Parameters:
//   - ctx: Context for cancellation
//   - target: Target URL
//   - cfg: HTTP configuration
//
// Returns:
//   - *http.Request: Configured HTTP request
//   - error: Any error that occurred during request creation
func (h *HTTPChecker) createRequest(ctx context.Context, target string, cfg *HTTPConfig) (*http.Request, error) {
	// Ensure URL has scheme
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "https://" + target
	}

	// Create request body
	var body strings.Reader
	if cfg.Body != "" {
		body = *strings.NewReader(cfg.Body)
	}

	// Create request
	req, err := http.NewRequestWithContext(ctx, cfg.Method, target, &body)
	if err != nil {
		return nil, err
	}

	// Set headers
	for key, value := range cfg.Headers {
		req.Header.Set(key, value)
	}

	// Set default User-Agent if not provided
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", "Dideban-Monitor/1.0")
	}

	return req, nil
}

// validateResponse validates the HTTP response against expected criteria.
//
// Parameters:
//   - checkID: Check ID for result creation
//   - resp: HTTP response to validate
//   - cfg: HTTP configuration with validation criteria
//   - responseTime: Response time in milliseconds
//
// Returns:
//   - *storage.CheckHistory: Validation result
//   - error: Only returned if an internal I/O error occurs (e.g., reading body fails)
func (h *HTTPChecker) validateResponse(checkID int64, resp *http.Response, cfg *HTTPConfig, responseTime int64) (*storage.CheckHistory, error) {
	// Case 1: Status code mismatch → DOWN (not an execution error!)
	if resp.StatusCode != cfg.ExpectedStatus {
		statusCode := resp.StatusCode
		errMsg := fmt.Sprintf("unexpected status code: got %d, expected %d", statusCode, cfg.ExpectedStatus)
		// Use CreateErrorResult but with explicit CheckStatusDown
		return h.CreateErrorResult(checkID, storage.CheckStatusDown, errors.New(errMsg), responseTime, &statusCode), nil
	}

	// Case 2: Expected content missing → DOWN
	if cfg.ExpectedContent != "" {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			// This IS a real execution error (e.g., network dropped mid-response)
			statusCode := resp.StatusCode
			return h.CreateErrorResult(checkID, storage.CheckStatusError, fmt.Errorf("failed to read response body: %w", err), responseTime, &statusCode), nil
		}

		if !strings.Contains(string(body), cfg.ExpectedContent) {
			statusCode := resp.StatusCode
			errMsg := fmt.Sprintf("expected content not found: %s", cfg.ExpectedContent)
			return h.CreateErrorResult(checkID, storage.CheckStatusDown, errors.New(errMsg), responseTime, &statusCode), nil
		}
	}

	// Case 3: Success → UP
	statusCode := resp.StatusCode
	return h.CreateSuccessResult(checkID, responseTime, &statusCode, ""), nil
}
