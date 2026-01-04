// Package storage provides validation functions for database entities.
package storage

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// HTTPDefaultsConfig represents default HTTP check configuration.
type HTTPDefaultsConfig struct {
	Method          string            `mapstructure:"method" yaml:"method"`
	Headers         map[string]string `mapstructure:"headers" yaml:"headers"`
	Body            string            `mapstructure:"body" yaml:"body"`
	TimeoutSeconds  int               `mapstructure:"timeout_seconds" yaml:"timeout_seconds"`
	ExpectedStatus  int               `mapstructure:"expected_status" yaml:"expected_status"`
	ExpectedContent string            `mapstructure:"expected_content" yaml:"expected_content"`
	FollowRedirects bool              `mapstructure:"follow_redirects" yaml:"follow_redirects"`
	VerifySSL       bool              `mapstructure:"verify_ssl" yaml:"verify_ssl"`
}

// PingDefaultsConfig represents default ping check configuration.
type PingDefaultsConfig struct {
	Count          int `mapstructure:"count" yaml:"count"`
	IntervalMs     int `mapstructure:"interval_ms" yaml:"interval_ms"`
	PacketSize     int `mapstructure:"packet_size" yaml:"packet_size"`
	TimeoutSeconds int `mapstructure:"timeout_seconds" yaml:"timeout_seconds"`
}

// Global defaults for validation - set by application initialization
var (
	globalHTTPDefaults *HTTPDefaultsConfig
	globalPingDefaults *PingDefaultsConfig
)

// SetValidationDefaults sets the global defaults used by validation functions.
// This should be called during application initialization with config values.
func SetValidationDefaults(httpDefaults *HTTPDefaultsConfig, pingDefaults *PingDefaultsConfig) {
	globalHTTPDefaults = httpDefaults
	globalPingDefaults = pingDefaults
}

// ValidateCheck validates a complete Check entity before database operations.
func ValidateCheck(check *Check) error {
	// Validate required fields
	if check.Name == "" {
		return fmt.Errorf("check name cannot be empty")
	}

	if len(check.Name) > 100 {
		return fmt.Errorf("check name too long (max 100 chars)")
	}

	// Validate name format (alphanumeric, spaces, hyphens, underscores only)
	for _, char := range check.Name {
		if !((char >= 'a' && char <= 'z') ||
			(char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') ||
			char == ' ' || char == '-' || char == '_') {
			return fmt.Errorf("check name contains invalid characters (only alphanumeric, spaces, hyphens, underscores allowed)")
		}
	}

	// Validate check type
	if !IsValidCheckType(check.Type) {
		return fmt.Errorf("unsupported check type: %s", check.Type)
	}

	// Validate target
	if check.Target == "" {
		return fmt.Errorf("check target cannot be empty")
	}

	if err := validateCheckTarget(check.Type, check.Target); err != nil {
		return fmt.Errorf("invalid target: %w", err)
	}

	// Validate intervals
	if check.IntervalSeconds < 5 {
		return fmt.Errorf("check interval too short (minimum 5 seconds)")
	}

	if check.IntervalSeconds > 86400 { // 24 hours
		return fmt.Errorf("check interval too long (maximum 24 hours)")
	}

	if check.TimeoutSeconds < 1 {
		return fmt.Errorf("check timeout too short (minimum 1 second)")
	}

	if check.TimeoutSeconds > 300 { // 5 minutes
		return fmt.Errorf("check timeout too long (maximum 5 minutes)")
	}

	if check.TimeoutSeconds >= check.IntervalSeconds {
		return fmt.Errorf("check timeout must be less than interval")
	}

	// Validate and normalize configuration
	validatedConfig, err := validateCheckConfig(check.Type, check.Config)
	if err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	// Update check with validated config
	check.Config = validatedConfig

	// Set timestamps if not set
	if check.CreatedAt.IsZero() {
		check.CreatedAt = time.Now()
	}
	check.UpdatedAt = time.Now()

	return nil
}

// ValidateAgent validates a complete Agent entity before database operations.
func ValidateAgent(agent *Agent) error {
	// Validate required fields
	if agent.Name == "" {
		return fmt.Errorf("agent name cannot be empty")
	}

	if len(agent.Name) > 100 {
		return fmt.Errorf("agent name too long (max 100 chars)")
	}

	// Validate name format (alphanumeric, spaces, hyphens, underscores only)
	for _, char := range agent.Name {
		if !((char >= 'a' && char <= 'z') ||
			(char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') ||
			char == ' ' || char == '-' || char == '_') {
			return fmt.Errorf("agent name contains invalid characters (only alphanumeric, spaces, hyphens, underscores allowed)")
		}
	}

	// Validate interval
	if agent.IntervalSeconds < 10 {
		return fmt.Errorf("agent interval too short (minimum 10 seconds)")
	}

	if agent.IntervalSeconds > 3600 { // 1 hour
		return fmt.Errorf("agent interval too long (maximum 1 hour)")
	}

	// Generate auth token if not provided
	if agent.AuthToken == "" {
		token, err := generateAuthToken()
		if err != nil {
			return fmt.Errorf("failed to generate auth token: %w", err)
		}
		agent.AuthToken = token
	}

	// Validate auth token format
	if len(agent.AuthToken) < 32 {
		return fmt.Errorf("auth token too short (minimum 32 chars)")
	}

	if len(agent.AuthToken) > 128 {
		return fmt.Errorf("auth token too long (maximum 128 chars)")
	}

	// Set timestamps if not set
	if agent.CreatedAt.IsZero() {
		agent.CreatedAt = time.Now()
	}
	agent.UpdatedAt = time.Now()

	return nil
}

// ValidateAlert validates a complete Alert entity before database operations.
func ValidateAlert(alert *Alert) error {
	// Validate that either CheckID or AgentID is provided, but not both
	if alert.CheckID == nil && alert.AgentID == nil {
		return fmt.Errorf("alert must be associated with either a check or an agent")
	}

	if alert.CheckID != nil && alert.AgentID != nil {
		return fmt.Errorf("alert cannot be associated with both a check and an agent")
	}

	// Validate alert type
	if !IsValidAlertType(alert.Type) {
		return fmt.Errorf("unsupported alert type: %s", alert.Type)
	}

	// Validate condition type
	if err := validateAlertConditionType(alert.ConditionType, alert.CheckID != nil); err != nil {
		return err
	}

	// Validate condition value for threshold-based conditions
	if needsConditionValue(alert.ConditionType) {
		if alert.ConditionValue == nil {
			return fmt.Errorf("condition value is required for condition type: %s", alert.ConditionType)
		}

		if *alert.ConditionValue < 0 || *alert.ConditionValue > 100 {
			return fmt.Errorf("condition value must be between 0 and 100 for percentage-based conditions")
		}
	}

	// Validate alert configuration
	if err := validateAlertConfig(alert.Type, alert.Config); err != nil {
		return fmt.Errorf("invalid alert configuration: %w", err)
	}

	// Set timestamps if not set
	if alert.CreatedAt.IsZero() {
		alert.CreatedAt = time.Now()
	}

	return nil
}

// ValidateAlertHistory validates a complete AlertHistory entity before database operations.
func ValidateAlertHistory(history *AlertHistory) error {
	// Validate required fields
	if history.AlertID == 0 {
		return fmt.Errorf("alert ID cannot be empty")
	}

	if history.Title == "" {
		return fmt.Errorf("alert title cannot be empty")
	}

	if len(history.Title) > 200 {
		return fmt.Errorf("alert title too long (max 200 chars)")
	}

	if history.Message == "" {
		return fmt.Errorf("alert message cannot be empty")
	}

	if len(history.Message) > 5000 {
		return fmt.Errorf("alert message too long (max 5000 chars)")
	}

	// Validate status
	if !IsValidAlertStatus(history.Status) {
		return fmt.Errorf("invalid alert status: %s", history.Status)
	}

	// Set timestamps if not set
	if history.SentAt.IsZero() {
		history.SentAt = time.Now()
	}
	if history.CreatedAt.IsZero() {
		history.CreatedAt = time.Now()
	}

	return nil
}

// ValidateAdmin validates a complete Admin entity before database operations.
func ValidateAdmin(admin *Admin) error {
	// Validate username
	if admin.Username == "" {
		return fmt.Errorf("username cannot be empty")
	}

	if len(admin.Username) < 3 {
		return fmt.Errorf("username too short (minimum 3 chars)")
	}

	if len(admin.Username) > 50 {
		return fmt.Errorf("username too long (max 50 chars)")
	}

	// Validate username format (alphanumeric and underscores only)
	usernameRegex := regexp.MustCompile(`^[a-zA-Z0-9_]+$`)
	if !usernameRegex.MatchString(admin.Username) {
		return fmt.Errorf("username contains invalid characters (only alphanumeric and underscores allowed)")
	}

	// Validate password (should be hashed)
	if admin.Password == "" {
		return fmt.Errorf("password cannot be empty")
	}

	if len(admin.Password) < 8 {
		return fmt.Errorf("password too short (minimum 8 chars)")
	}

	if len(admin.Password) > 255 {
		return fmt.Errorf("password too long (max 255 chars)")
	}

	// Validate full name
	if admin.FullName == "" {
		return fmt.Errorf("full name cannot be empty")
	}

	if len(admin.FullName) > 100 {
		return fmt.Errorf("full name too long (max 100 chars)")
	}

	return nil
}

// ValidateCheckHistory validates a complete CheckHistory entity before database operations.
func ValidateCheckHistory(history *CheckHistory) error {
	// Validate required fields
	if history.CheckID == 0 {
		return fmt.Errorf("check ID cannot be empty")
	}

	// Validate status
	if !IsValidCheckStatus(history.Status) {
		return fmt.Errorf("invalid check status: %s", history.Status)
	}

	// Validate response time
	if history.ResponseTimeMs != nil && *history.ResponseTimeMs < 0 {
		return fmt.Errorf("response time cannot be negative")
	}

	// Validate status code (for HTTP checks)
	if history.StatusCode != nil {
		if *history.StatusCode < 100 || *history.StatusCode > 599 {
			return fmt.Errorf("invalid HTTP status code: %d", *history.StatusCode)
		}
	}

	// Validate error message length
	if history.ErrorMessage != nil && len(*history.ErrorMessage) > 1000 {
		return fmt.Errorf("error message too long (max 1000 chars)")
	}

	// Set timestamp if not set
	if history.CheckedAt.IsZero() {
		history.CheckedAt = time.Now()
	}

	return nil
}

// ValidateAgentHistory validates a complete AgentHistory entity before database operations.
func ValidateAgentHistory(history *AgentHistory) error {
	// Validate required fields
	if history.AgentID == 0 {
		return fmt.Errorf("agent ID cannot be empty")
	}

	// Validate collection duration
	if history.CollectDurationMs < 0 {
		return fmt.Errorf("collect duration cannot be negative")
	}

	if history.CollectDurationMs > 300000 { // 5 minutes
		return fmt.Errorf("collect duration too long (max 5 minutes)")
	}

	// Validate CPU metrics
	if history.CPULoad1 < 0 || history.CPULoad5 < 0 || history.CPULoad15 < 0 {
		return fmt.Errorf("CPU load values cannot be negative")
	}

	if history.CPUUsagePercent < 0 || history.CPUUsagePercent > 100 {
		return fmt.Errorf("CPU usage percent must be between 0 and 100")
	}

	// Validate memory metrics
	if history.MemoryTotalMB <= 0 {
		return fmt.Errorf("memory total must be positive")
	}

	if history.MemoryUsedMB < 0 || history.MemoryAvailableMB < 0 {
		return fmt.Errorf("memory values cannot be negative")
	}

	if history.MemoryUsagePercent < 0 || history.MemoryUsagePercent > 100 {
		return fmt.Errorf("memory usage percent must be between 0 and 100")
	}

	// Validate disk metrics
	if history.DiskTotalGB <= 0 {
		return fmt.Errorf("disk total must be positive")
	}

	if history.DiskUsedGB < 0 {
		return fmt.Errorf("disk used cannot be negative")
	}

	if history.DiskUsagePercent < 0 || history.DiskUsagePercent > 100 {
		return fmt.Errorf("disk usage percent must be between 0 and 100")
	}

	// Set timestamp if not set
	if history.CollectedAt.IsZero() {
		history.CollectedAt = time.Now()
	}

	return nil
}

// validateCheckTarget validates the target based on check type.
func validateCheckTarget(checkType, target string) error {
	switch checkType {
	case CheckTypeHTTP:
		return validateHTTPCheckTarget(target)
	case CheckTypePing:
		return validatePingCheckTarget(target)
	default:
		return fmt.Errorf("unknown check type: %s", checkType)
	}
}

// validateHTTPCheckTarget validates HTTP/HTTPS check targets.
func validateHTTPCheckTarget(target string) error {
	// Add scheme if missing
	if !strings.Contains(target, "://") {
		target = "https://" + target
	}

	// Parse URL
	parsedURL, err := url.Parse(target)
	if err != nil {
		return fmt.Errorf("invalid URL format: %w", err)
	}

	// Validate scheme
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return fmt.Errorf("invalid scheme: %s (only http and https supported)", parsedURL.Scheme)
	}

	// Validate host
	host := parsedURL.Hostname()
	if host == "" {
		return fmt.Errorf("missing host")
	}

	// Host length
	if len(host) > 253 {
		return fmt.Errorf("hostname too long")
	}

	// IP is allowed
	if net.ParseIP(host) != nil {
		return nil
	}

	// localhost is allowed
	if host == "localhost" {
		return nil
	}

	// Must contain dot (reject not-a-url)
	if !strings.Contains(host, ".") {
		return fmt.Errorf("invalid hostname")
	}

	// Basic hostname validation
	if strings.Contains(host, "..") ||
		strings.HasPrefix(host, ".") ||
		strings.HasSuffix(host, ".") {
		return fmt.Errorf("invalid hostname format")
	}

	return nil
}

// validatePingCheckTarget validates ping check targets (hostnames or IP addresses).
func validatePingCheckTarget(target string) error {
	if target == "" {
		return fmt.Errorf("ping target cannot be empty")
	}

	// First try to validate as IPv4
	if isValidIPv4(target) {
		return nil
	}

	// Then try to validate as IPv6
	if isValidIPv6(target) {
		return nil
	}

	// If it contains no letters, it's not a valid hostname (probably an invalid IP)
	hasLetter := false
	for _, r := range target {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
			hasLetter = true
			break
		}
	}
	if !hasLetter {
		return fmt.Errorf("target is not a valid IP address or hostname")
	}

	// It's a hostname, validate format
	return validateHostname(target)
}

// isValidIPv4 validates IPv4 addresses strictly
func isValidIPv4(ip string) bool {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return false
	}

	for _, part := range parts {
		if part == "" {
			return false
		}

		// Check for leading zeros (except "0" itself)
		if len(part) > 1 && part[0] == '0' {
			return false
		}

		// Parse as integer to validate range
		val := 0
		for _, digit := range part {
			if digit < '0' || digit > '9' {
				return false
			}
			val = val*10 + int(digit-'0')
			if val > 255 {
				return false
			}
		}
	}
	return true
}

// isValidIPv6 validates IPv6 addresses using net.ParseIP but with additional checks
func isValidIPv6(ip string) bool {
	// Must contain colons for IPv6
	if !strings.Contains(ip, ":") {
		return false
	}

	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}

	// Make sure it's actually IPv6 (not IPv4-mapped)
	return parsed.To4() == nil
}

// validateHostname validates hostname format
func validateHostname(target string) error {
	if len(target) > 253 {
		return fmt.Errorf("hostname too long (max 253 chars)")
	}

	// Basic hostname validation
	if strings.Contains(target, "..") || strings.HasPrefix(target, ".") || strings.HasSuffix(target, ".") {
		return fmt.Errorf("invalid hostname format")
	}

	// Check for invalid characters
	for _, char := range target {
		if !((char >= 'a' && char <= 'z') ||
			(char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') ||
			char == '.' || char == '-') {
			return fmt.Errorf("hostname contains invalid characters")
		}
	}

	return nil
}

// validateCheckConfig validates check configuration for a specific type.
func validateCheckConfig(checkType, configStr string) (string, error) {
	switch checkType {
	case CheckTypeHTTP:
		// Convert HTTPDefaultsConfig to HTTPCheckConfig
		var httpCheckDefaults *HTTPCheckConfig
		if globalHTTPDefaults != nil {
			httpCheckDefaults = &HTTPCheckConfig{
				Method:          globalHTTPDefaults.Method,
				Headers:         globalHTTPDefaults.Headers,
				Body:            globalHTTPDefaults.Body,
				ExpectedStatus:  globalHTTPDefaults.ExpectedStatus,
				ExpectedContent: globalHTTPDefaults.ExpectedContent,
				FollowRedirects: globalHTTPDefaults.FollowRedirects,
				VerifySSL:       globalHTTPDefaults.VerifySSL,
			}
		}
		return ValidateHTTPCheckConfig(configStr, httpCheckDefaults)
	case CheckTypePing:
		// Convert PingDefaultsConfig to PingCheckConfig
		var pingCheckDefaults *PingCheckConfig
		if globalPingDefaults != nil {
			pingCheckDefaults = &PingCheckConfig{
				Count:    globalPingDefaults.Count,
				Interval: globalPingDefaults.IntervalMs,
				Size:     globalPingDefaults.PacketSize,
			}
		}
		return ValidatePingCheckConfig(configStr, pingCheckDefaults)
	default:
		return "", fmt.Errorf("unsupported check type: %s", checkType)
	}
}

// ValidateCheckWithDefaults validates a complete Check entity with provided defaults.
func ValidateCheckWithDefaults(check *Check, httpDefaults *HTTPDefaultsConfig, pingDefaults *PingDefaultsConfig) error {
	// Validate required fields
	if check.Name == "" {
		return fmt.Errorf("check name cannot be empty")
	}

	if len(check.Name) > 100 {
		return fmt.Errorf("check name too long (max 100 chars)")
	}

	// Validate name format (alphanumeric, spaces, hyphens, underscores only)
	for _, char := range check.Name {
		if !((char >= 'a' && char <= 'z') ||
			(char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') ||
			char == ' ' || char == '-' || char == '_') {
			return fmt.Errorf("check name contains invalid characters (only alphanumeric, spaces, hyphens, underscores allowed)")
		}
	}

	// Validate check type
	if !IsValidCheckType(check.Type) {
		return fmt.Errorf("unsupported check type: %s", check.Type)
	}

	// Validate target
	if check.Target == "" {
		return fmt.Errorf("check target cannot be empty")
	}

	if err := validateCheckTarget(check.Type, check.Target); err != nil {
		return fmt.Errorf("invalid target: %w", err)
	}

	// Validate intervals
	if check.IntervalSeconds < 5 {
		return fmt.Errorf("check interval too short (minimum 5 seconds)")
	}

	if check.IntervalSeconds > 86400 { // 24 hours
		return fmt.Errorf("check interval too long (maximum 24 hours)")
	}

	if check.TimeoutSeconds < 1 {
		return fmt.Errorf("check timeout too short (minimum 1 second)")
	}

	if check.TimeoutSeconds > 300 { // 5 minutes
		return fmt.Errorf("check timeout too long (maximum 5 minutes)")
	}

	if check.TimeoutSeconds >= check.IntervalSeconds {
		return fmt.Errorf("check timeout must be less than interval")
	}

	// Validate and normalize configuration with provided defaults
	validatedConfig, err := validateCheckConfigWithDefaults(check.Type, check.Config, httpDefaults, pingDefaults)
	if err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	// Update check with validated config
	check.Config = validatedConfig

	return nil
}

// validateCheckConfigWithDefaults validates check configuration for a specific type with provided defaults.
func validateCheckConfigWithDefaults(checkType, configStr string, httpDefaults *HTTPDefaultsConfig, pingDefaults *PingDefaultsConfig) (string, error) {
	switch checkType {
	case CheckTypeHTTP:
		// Convert HTTPDefaultsConfig to HTTPCheckConfig
		var httpCheckDefaults *HTTPCheckConfig
		if httpDefaults != nil {
			httpCheckDefaults = &HTTPCheckConfig{
				Method:          httpDefaults.Method,
				Headers:         httpDefaults.Headers,
				Body:            httpDefaults.Body,
				ExpectedStatus:  httpDefaults.ExpectedStatus,
				ExpectedContent: httpDefaults.ExpectedContent,
				FollowRedirects: httpDefaults.FollowRedirects,
				VerifySSL:       httpDefaults.VerifySSL,
			}
		}
		return ValidateHTTPCheckConfig(configStr, httpCheckDefaults)
	case CheckTypePing:
		// Convert PingDefaultsConfig to PingCheckConfig
		var pingCheckDefaults *PingCheckConfig
		if pingDefaults != nil {
			pingCheckDefaults = &PingCheckConfig{
				Count:    pingDefaults.Count,
				Interval: pingDefaults.IntervalMs,
				Size:     pingDefaults.PacketSize,
			}
		}
		return ValidatePingCheckConfig(configStr, pingCheckDefaults)
	default:
		return "", fmt.Errorf("unsupported check type: %s", checkType)
	}
}

// HTTPCheckConfig represents HTTP check configuration.
type HTTPCheckConfig struct {
	Method          string            `json:"method"`           // HTTP method (default: GET)
	Headers         map[string]string `json:"headers"`          // Custom headers
	Body            string            `json:"body"`             // Request body
	ExpectedStatus  int               `json:"expected_status"`  // Expected status code (default: 200)
	ExpectedContent string            `json:"expected_content"` // Expected content in response
	FollowRedirects bool              `json:"follow_redirects"` // Follow redirects (default: true)
	VerifySSL       bool              `json:"verify_ssl"`       // Verify SSL certificates (default: true)
}

// ValidateHTTPCheckConfig validates HTTP check configuration with custom defaults.
func ValidateHTTPCheckConfig(configStr string, defaults *HTTPCheckConfig) (string, error) {
	// Start with provided defaults or fallback defaults
	config := &HTTPCheckConfig{
		Method:          "GET",
		Headers:         make(map[string]string),
		ExpectedStatus:  200,
		FollowRedirects: true,
		VerifySSL:       true,
	}

	// Apply custom defaults if provided
	if defaults != nil {
		if defaults.Method != "" {
			config.Method = defaults.Method
		}
		if defaults.ExpectedStatus != 0 {
			config.ExpectedStatus = defaults.ExpectedStatus
		}
		config.FollowRedirects = defaults.FollowRedirects
		config.VerifySSL = defaults.VerifySSL
		if defaults.Headers != nil {
			for k, v := range defaults.Headers {
				config.Headers[k] = v
			}
		}
		if defaults.Body != "" {
			config.Body = defaults.Body
		}
		if defaults.ExpectedContent != "" {
			config.ExpectedContent = defaults.ExpectedContent
		}
	}

	// Parse JSON config if provided
	if configStr != "" && configStr != "{}" {
		if err := json.Unmarshal([]byte(configStr), config); err != nil {
			return "", fmt.Errorf("invalid JSON format: %w", err)
		}
	}

	// Validate HTTP method
	validMethods := map[string]bool{
		"GET": true, "POST": true, "PUT": true, "DELETE": true,
		"HEAD": true, "OPTIONS": true, "PATCH": true,
	}

	if config.Method == "" {
		config.Method = "GET"
	}

	// Normalize method to uppercase
	config.Method = strings.ToUpper(config.Method)
	if !validMethods[config.Method] {
		return "", fmt.Errorf("invalid HTTP method: %s (supported: GET, POST, PUT, DELETE, HEAD, OPTIONS, PATCH)", config.Method)
	}

	// Validate expected status code
	if config.ExpectedStatus < 100 || config.ExpectedStatus > 599 {
		return "", fmt.Errorf("invalid expected status code: %d (must be between 100-599)", config.ExpectedStatus)
	}

	// Validate headers
	if config.Headers == nil {
		config.Headers = make(map[string]string)
	}

	for key, value := range config.Headers {
		if key == "" {
			return "", fmt.Errorf("header key cannot be empty")
		}
		if len(key) > 100 {
			return "", fmt.Errorf("header key too long: %s (max 100 chars)", key)
		}
		if len(value) > 1000 {
			return "", fmt.Errorf("header value too long for key %s (max 1000 chars)", key)
		}
	}

	// Validate body size
	if len(config.Body) > 10*1024*1024 { // 10MB limit
		return "", fmt.Errorf("request body too large (max 10MB)")
	}

	// Validate expected content length
	if len(config.ExpectedContent) > 1000 {
		return "", fmt.Errorf("expected content too long (max 1000 chars)")
	}

	// Convert back to JSON string
	validatedJSON, err := json.Marshal(config)
	if err != nil {
		return "", fmt.Errorf("failed to marshal validated config: %w", err)
	}

	return string(validatedJSON), nil
}

// PingCheckConfig represents ping check configuration.
type PingCheckConfig struct {
	Count    int `json:"count"`    // Number of ping packets (default: 3)
	Interval int `json:"interval"` // Interval between pings in ms (default: 1000)
	Size     int `json:"size"`     // Packet size in bytes (default: 56)
}

// ValidatePingCheckConfig validates Ping check configuration with custom defaults.
func ValidatePingCheckConfig(configStr string, defaults *PingCheckConfig) (string, error) {
	// Start with provided defaults or fallback defaults
	config := &PingCheckConfig{
		Count:    3,
		Interval: 300,
		Size:     56,
	}

	// Apply custom defaults if provided
	if defaults != nil {
		if defaults.Count != 0 {
			config.Count = defaults.Count
		}
		if defaults.Interval != 0 {
			config.Interval = defaults.Interval
		}
		if defaults.Size != 0 {
			config.Size = defaults.Size
		}
	}

	// Parse JSON config if provided
	if configStr != "" && configStr != "{}" {
		if err := json.Unmarshal([]byte(configStr), config); err != nil {
			return "", fmt.Errorf("invalid JSON format: %w", err)
		}
	}

	// Validate count
	if config.Count <= 0 || config.Count > 10 {
		return "", fmt.Errorf("invalid count: %d (must be between 1-10)", config.Count)
	}

	// Validate interval
	if config.Interval < 100 || config.Interval > 10000 {
		return "", fmt.Errorf("invalid interval: %d ms (must be between 100-10000)", config.Interval)
	}

	// Validate packet size
	if config.Size < 8 || config.Size > 1472 {
		return "", fmt.Errorf("invalid packet size: %d bytes (must be between 8-1472)", config.Size)
	}

	// Convert back to JSON string
	validatedJSON, err := json.Marshal(config)
	if err != nil {
		return "", fmt.Errorf("failed to marshal validated config: %w", err)
	}

	return string(validatedJSON), nil
}

// IsValidCheckType validates if a check type is supported.
func IsValidCheckType(checkType string) bool {
	switch checkType {
	case CheckTypeHTTP, CheckTypePing:
		return true
	default:
		return false
	}
}

// IsValidCheckStatus validates if a check status is valid.
func IsValidCheckStatus(status string) bool {
	switch status {
	case CheckStatusUp, CheckStatusDown, CheckStatusError, CheckStatusTimeout:
		return true
	default:
		return false
	}
}

// IsValidAlertType validates if an alert type is supported.
func IsValidAlertType(alertType string) bool {
	switch alertType {
	case AlertTypeTelegram, AlertTypeBale, AlertTypeEmail, AlertTypeWebhook:
		return true
	default:
		return false
	}
}

// IsValidAlertStatus validates if an alert status is valid.
func IsValidAlertStatus(status string) bool {
	switch status {
	case AlertStatusSent, AlertStatusFailed, AlertStatusPending:
		return true
	default:
		return false
	}
}

// IsValidAgentStatus validates if an agent status is valid.
func IsValidAgentStatus(status string) bool {
	switch status {
	case AgentStatusOnline, AgentStatusOffline:
		return true
	default:
		return false
	}
}

// Helper functions

// generateAuthToken generates a secure random auth token.
func generateAuthToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// validateAlertConditionType validates alert condition types based on context.
func validateAlertConditionType(conditionType string, isCheckAlert bool) error {
	checkConditions := []string{"status_down", "status_timeout", "status_error"}
	agentConditions := []string{"cpu_usage_high", "memory_usage_high", "disk_usage_high", "agent_offline"}

	if isCheckAlert {
		for _, condition := range checkConditions {
			if conditionType == condition {
				return nil
			}
		}
		return fmt.Errorf("invalid condition type for check alert: %s (supported: %v)", conditionType, checkConditions)
	} else {
		for _, condition := range agentConditions {
			if conditionType == condition {
				return nil
			}
		}
		return fmt.Errorf("invalid condition type for agent alert: %s (supported: %v)", conditionType, agentConditions)
	}
}

// needsConditionValue returns true if the condition type requires a threshold value.
func needsConditionValue(conditionType string) bool {
	thresholdConditions := []string{"cpu_usage_high", "memory_usage_high", "disk_usage_high"}
	for _, condition := range thresholdConditions {
		if conditionType == condition {
			return true
		}
	}
	return false
}

// validateAlertConfig validates alert configuration based on alert type.
func validateAlertConfig(alertType, configStr string) error {
	if configStr == "" || configStr == "{}" {
		return nil // Empty config is allowed
	}

	// Parse JSON to ensure it's valid
	var config map[string]interface{}
	if err := json.Unmarshal([]byte(configStr), &config); err != nil {
		return fmt.Errorf("invalid JSON format: %w", err)
	}

	// Type-specific validation
	switch alertType {
	case AlertTypeTelegram:
		return validateTelegramAlertConfig(config)
	case AlertTypeBale:
		return validateBaleAlertConfig(config)
	case AlertTypeEmail:
		return validateEmailAlertConfig(config)
	case AlertTypeWebhook:
		return validateWebhookAlertConfig(config)
	default:
		return fmt.Errorf("unsupported alert type: %s", alertType)
	}
}

// validateTelegramAlertConfig validates Telegram alert configuration.
func validateTelegramAlertConfig(config map[string]interface{}) error {
	// Token validation
	if token, exists := config["token"]; exists {
		if tokenStr, ok := token.(string); ok {
			if len(tokenStr) < 10 {
				return fmt.Errorf("telegram token too short")
			}
		} else {
			return fmt.Errorf("telegram token must be a string")
		}
	}

	// Chat ID validation
	if chatID, exists := config["chat_id"]; exists {
		if chatIDStr, ok := chatID.(string); ok {
			if len(chatIDStr) == 0 {
				return fmt.Errorf("telegram chat_id cannot be empty")
			}
		} else {
			return fmt.Errorf("telegram chat_id must be a string")
		}
	}

	return nil
}

// validateBaleAlertConfig validates Bale alert configuration.
func validateBaleAlertConfig(config map[string]interface{}) error {
	// Similar to Telegram validation
	return validateTelegramAlertConfig(config)
}

// validateEmailAlertConfig validates Email alert configuration.
func validateEmailAlertConfig(config map[string]interface{}) error {
	// SMTP host validation
	if host, exists := config["smtp_host"]; exists {
		if hostStr, ok := host.(string); ok {
			if len(hostStr) == 0 {
				return fmt.Errorf("smtp_host cannot be empty")
			}
		} else {
			return fmt.Errorf("smtp_host must be a string")
		}
	}

	// Email validation
	if to, exists := config["to"]; exists {
		if toStr, ok := to.(string); ok {
			if !strings.Contains(toStr, "@") {
				return fmt.Errorf("invalid email format")
			}
		} else {
			return fmt.Errorf("email 'to' field must be a string")
		}
	}

	return nil
}

// validateWebhookAlertConfig validates Webhook alert configuration.
func validateWebhookAlertConfig(config map[string]interface{}) error {
	// URL validation
	if urlField, exists := config["url"]; exists {
		if urlStr, ok := urlField.(string); ok {
			if _, err := url.Parse(urlStr); err != nil {
				return fmt.Errorf("invalid webhook URL: %w", err)
			}
		} else {
			return fmt.Errorf("webhook URL must be a string")
		}
	}

	return nil
}
