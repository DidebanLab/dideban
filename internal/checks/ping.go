// Package checks provides ICMP ping monitoring functionality.
package checks

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"dideban/internal/config"
	"dideban/internal/storage"
)

// PingConfig represents ping check configuration.
type PingConfig struct {
	Count          int `json:"count"`           // Number of ping packets (default: 3)
	IntervalMs     int `json:"interval_ms"`     // Interval between pings in ms (default: 1000)
	PacketSize     int `json:"packet_size"`     // Packet size in bytes (default: 56)
	TimeoutSeconds int `json:"timeout_seconds"` // Timeout per packet in seconds (default: 5)
}

// PingChecker implements ICMP ping monitoring checks.
type PingChecker struct {
	*BaseChecker
	defaults *config.PingDefaultsConfig
}

// NewPingChecker creates a new ping checker instance.
//
// Parameters:
//   - cfg: Application configuration for defaults
//
// Returns:
//   - *PingChecker: Initialized ping checker
func NewPingChecker(cfg *config.Config) *PingChecker {
	return &PingChecker{
		BaseChecker: NewBaseChecker(),
		defaults:    &cfg.Checks.Ping,
	}
}

// Type returns the checker type identifier.
//
// Returns:
//   - string: Type identifier "ping"
func (p *PingChecker) Type() string {
	return "ping"
}

// Check executes an ICMP ping monitoring check.
//
// Parameters:
//   - ctx: Context for cancellation and timeout
//   - check: Check configuration containing target host and settings
//
// Returns:
//   - *storage.CheckHistory: Result of the ping check
//   - error: Any error that occurred during the check
func (p *PingChecker) Check(ctx context.Context, check *storage.Check) (*storage.CheckHistory, error) {
	startTime := time.Now()

	// Parse and validate configuration
	cfg, err := p.parseConfig(check.Config)
	if err != nil {
		responseTime := time.Since(startTime).Milliseconds()
		status := p.DetermineErrorStatus(err)
		return p.CreateErrorResult(check.ID, status, fmt.Errorf("invalid config: %w", err), responseTime, nil), err
	}

	// Resolve target host
	target, err := p.resolveTarget(check.Target)
	if err != nil {
		responseTime := time.Since(startTime).Milliseconds()
		status := p.DetermineErrorStatus(err)
		return p.CreateErrorResult(check.ID, status, fmt.Errorf("failed to resolve target: %w", err), responseTime, nil), err
	}

	// Execute ping
	result, err := p.executePing(ctx, target, cfg, check.ID)
	responseTime := time.Since(startTime).Milliseconds()

	if err != nil {
		status := p.DetermineErrorStatus(err)
		return p.CreateErrorResult(check.ID, status, err, responseTime, nil), err
	}

	// Update result with check ID
	result.CheckID = check.ID
	if result.ResponseTimeMs == nil {
		responseTimeMs := int(responseTime)
		result.ResponseTimeMs = &responseTimeMs
	}

	return result, nil
}

// parseConfig parses the ping check configuration.
// Config is already validated by storage layer, so we just parse and apply defaults.
// However, we do basic validation for direct checker usage (like in tests).
//
// Parameters:
//   - configStr: JSON configuration string from the check (already validated)
//
// Returns:
//   - *PingConfig: Parsed configuration with defaults applied
//   - error: Any error that occurred during parsing
func (p *PingChecker) parseConfig(configStr string) (*PingConfig, error) {
	// Start with defaults from application config
	cfg := &PingConfig{
		Count:          p.defaults.Count,
		IntervalMs:     p.defaults.IntervalMs,
		PacketSize:     p.defaults.PacketSize,
		TimeoutSeconds: p.defaults.TimeoutSeconds,
	}

	// Parse JSON config if provided (config is already validated by storage)
	if configStr != "" && configStr != "{}" {
		// Parse into storage format first
		var storageConfig storage.PingCheckConfig
		if err := json.Unmarshal([]byte(configStr), &storageConfig); err != nil {
			return nil, fmt.Errorf("failed to parse config: %w", err)
		}

		// Apply values from config, keeping defaults for unspecified fields
		if storageConfig.Count != 0 {
			cfg.Count = storageConfig.Count
		}
		if storageConfig.Interval != 0 {
			cfg.IntervalMs = storageConfig.Interval // Note: storage uses "interval", we use "interval_ms"
		}
		if storageConfig.Size != 0 {
			cfg.PacketSize = storageConfig.Size // Note: storage uses "size", we use "packet_size"
		}
	}

	// Basic validation for direct checker usage (like in tests)
	// This is a safety net when checker is used without storage validation
	if cfg.Count <= 0 || cfg.Count > 10 {
		return nil, fmt.Errorf("invalid count: %d (must be between 1-10)", cfg.Count)
	}
	if cfg.IntervalMs < 100 || cfg.IntervalMs > 10000 {
		return nil, fmt.Errorf("invalid interval: %d ms (must be between 100-10000)", cfg.IntervalMs)
	}
	if cfg.PacketSize < 8 || cfg.PacketSize > 1472 {
		return nil, fmt.Errorf("invalid packet size: %d bytes (must be between 8-1472)", cfg.PacketSize)
	}

	return cfg, nil
}

// resolveTarget resolves the target hostname to an IP address.
//
// Parameters:
//   - target: Target hostname or IP address
//
// Returns:
//   - string: Resolved IP address
//   - error: Any error that occurred during resolution
func (p *PingChecker) resolveTarget(target string) (string, error) {
	// Check if target is already an IP address
	if net.ParseIP(target) != nil {
		return target, nil
	}

	// Resolve hostname
	ips, err := net.LookupIP(target)
	if err != nil {
		return "", fmt.Errorf("failed to resolve hostname %s: %w", target, err)
	}

	if len(ips) == 0 {
		return "", fmt.Errorf("no IP addresses found for hostname %s", target)
	}

	// Prefer IPv4
	for _, ip := range ips {
		if ip.To4() != nil {
			return ip.String(), nil
		}
	}

	// Fall back to IPv6
	return ips[0].String(), nil
}

// executePing executes the ping command and parses the results.
// Supports cross-platform ping commands (Windows, Unix/Linux/macOS).
//
// Parameters:
//   - ctx: Context for cancellation and timeout
//   - target: Target IP address
//   - config: Ping configuration
//
// Returns:
//   - *storage.CheckHistory: Ping result
//   - error: Any error that occurred during ping execution
func (p *PingChecker) executePing(ctx context.Context, target string, config *PingConfig, checkID int64) (*storage.CheckHistory, error) {
	// Build platform-specific ping command
	cmd := p.buildPingCommand(ctx, target, config)

	// Execute ping command
	output, err := cmd.Output()

	if err != nil {
		// Check if it's a timeout or other error
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, fmt.Errorf("ping timeout")
		}
		return nil, fmt.Errorf("ping command failed: %w", err)
	}

	// Parse ping output (platform-specific)
	return p.parsePingOutput(checkID, string(output))
}

// parsePingOutput parses the output of the ping command.
// Supports cross-platform output parsing (Windows vs Unix/Linux/macOS).
//
// Parameters:
//   - output: Raw ping command output
//
// Returns:
//   - *storage.CheckHistory: Parsed ping result
//   - error: Any error that occurred during parsing
func (p *PingChecker) parsePingOutput(checkID int64, output string) (*storage.CheckHistory, error) {
	lines := strings.Split(output, "\n")

	switch runtime.GOOS {
	case "windows":
		return p.parseWindowsPingOutput(checkID, lines)
	default:
		return p.parseUnixPingOutput(checkID, lines)
	}
}

// buildPingCommand builds a platform-specific ping command.
//
// Parameters:
//   - ctx: Context for cancellation and timeout
//   - target: Target IP address
//   - config: Ping configuration
//
// Returns:
//   - *exec.Cmd: Platform-specific ping command
func (p *PingChecker) buildPingCommand(ctx context.Context, target string, config *PingConfig) *exec.Cmd {
	var args []string

	switch runtime.GOOS {
	case "windows":
		args = []string{
			"-n", strconv.Itoa(config.Count), // count
			"-w", strconv.Itoa(config.TimeoutSeconds * 1000), // timeout in milliseconds
			"-l", strconv.Itoa(config.PacketSize), // packet size
			target,
		}
	default: // Unix/Linux/macOS
		args = []string{
			"-c", strconv.Itoa(config.Count), // count
			"-i", fmt.Sprintf("%.3f", float64(config.IntervalMs)/1000.0), // interval in seconds
			"-s", strconv.Itoa(config.PacketSize), // packet size
			"-W", strconv.Itoa(config.TimeoutSeconds), // timeout in seconds
			target,
		}
	}

	return exec.CommandContext(ctx, "ping", args...)
}

// parseUnixPingOutput parses Unix/Linux/macOS ping output.
//
// Parameters:
//   - lines: Lines of ping output
//
// Returns:
//   - *storage.CheckHistory: Parsed ping result
//   - error: Any error that occurred during parsing
func (p *PingChecker) parseUnixPingOutput(checkID int64, lines []string) (*storage.CheckHistory, error) {
	// Parse statistics line (e.g., "3 packets transmitted, 3 received, 0% packet loss")
	var received int
	var packetLoss float64

	statsRegex := regexp.MustCompile(`(\d+) packets transmitted, (\d+) (?:packets )?received, ([\d.]+)% packet loss`)

	for _, line := range lines {
		if matches := statsRegex.FindStringSubmatch(line); matches != nil {
			_, _ = strconv.Atoi(matches[1]) // transmitted (not used)
			received, _ = strconv.Atoi(matches[2])
			packetLoss, _ = strconv.ParseFloat(matches[3], 64)
			break
		}
	}

	// Parse timing information (e.g., "rtt min/avg/max/mdev = 1.234/2.345/3.456/0.123 ms")
	var avgRTT float64

	timingRegex := regexp.MustCompile(`rtt min/avg/max/mdev = ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+) ms`)

	for _, line := range lines {
		if matches := timingRegex.FindStringSubmatch(line); matches != nil {
			_, _ = strconv.ParseFloat(matches[1], 64) // minRTT (not used)
			avgRTT, _ = strconv.ParseFloat(matches[2], 64)
			_, _ = strconv.ParseFloat(matches[3], 64) // maxRTT (not used)
			_, _ = strconv.ParseFloat(matches[4], 64) // mdevRTT (not used)
			break
		}
	}

	return p.createPingResult(checkID, received, packetLoss, avgRTT)
}

// parseWindowsPingOutput parses Windows ping output.
//
// Parameters:
//   - lines: Lines of ping output
//
// Returns:
//   - *storage.CheckHistory: Parsed ping result
//   - error: Any error that occurred during parsing
func (p *PingChecker) parseWindowsPingOutput(checkID int64, lines []string) (*storage.CheckHistory, error) {
	// Parse statistics line (e.g., "Packets: Sent = 4, Received = 4, Lost = 0 (0% loss)")
	var received int
	var packetLoss float64

	statsRegex := regexp.MustCompile(`Packets: Sent = (\d+), Received = (\d+), Lost = \d+ \(([\d.]+)% loss\)`)

	for _, line := range lines {
		if matches := statsRegex.FindStringSubmatch(line); matches != nil {
			_, _ = strconv.Atoi(matches[1]) // sent (not used)
			received, _ = strconv.Atoi(matches[2])
			packetLoss, _ = strconv.ParseFloat(matches[3], 64)
			break
		}
	}

	// Parse timing information from individual ping lines
	// Windows format: "Reply from 8.8.8.8: bytes=32 time=15ms TTL=117"
	var totalRTT float64
	var rttCount int

	rttRegex := regexp.MustCompile(`time=(\d+)ms`)

	for _, line := range lines {
		if matches := rttRegex.FindStringSubmatch(line); matches != nil {
			if rtt, err := strconv.ParseFloat(matches[1], 64); err == nil {
				totalRTT += rtt
				rttCount++
			}
		}
	}

	var avgRTT float64
	if rttCount > 0 {
		avgRTT = totalRTT / float64(rttCount)
	}

	return p.createPingResult(checkID, received, packetLoss, avgRTT)
}

// createPingResult creates a standardized ping result.
//
// Parameters:
//   - checkID: ID of the check being executed
//   - received: Number of packets received
//   - packetLoss: Packet loss percentage
//   - avgRTT: Average round-trip time in milliseconds
//
// Returns:
//   - *storage.CheckHistory: Standardized ping result
//   - error: Always returns nil (ping execution always produces a result)
func (p *PingChecker) createPingResult(checkID int64, received int, packetLoss, avgRTT float64) (*storage.CheckHistory, error) {
	responseTime := int64(avgRTT)

	// Case 1: No packets received → DOWN
	if received == 0 {
		errMsg := "100% packet loss"
		return p.CreateErrorResult(checkID, storage.CheckStatusDown, errors.New(errMsg), responseTime, nil), nil
	}

	// Case 2: High packet loss (>50%) → DOWN
	if packetLoss > 50 {
		errMsg := fmt.Sprintf("%.1f%% packet loss", packetLoss)
		return p.CreateErrorResult(checkID, storage.CheckStatusDown, errors.New(errMsg), responseTime, nil), nil
	}

	// Case 3: Acceptable packet loss → UP
	message := fmt.Sprintf("%.1f%% packet loss", packetLoss)
	return p.CreateSuccessResult(checkID, responseTime, nil, message), nil
}
