// Package alert provides alerting functionality for the Dideban monitoring system.
//
// This package manages different alert channels (Telegram, Bale, Email, etc.)
// and handles alert dispatching, throttling, and formatting.
//
// Supported alert channels:
//   - Telegram Bot API
//   - Bale.ai Bot API
//   - Email (planned)
//   - Webhooks (planned)
//
// Example usage:
//
//	manager, err := alert.NewManager(cfg.Alert, logger)
//	if err != nil {
//	    log.Fatal("Failed to create alert manager", err)
//	}
//
//	alertData := alert.AlertData{
//	    MonitorName: "Web Server",
//	    Status: "down",
//	    Error: "Connection timeout",
//	}
//
//	err = manager.SendAlert(alertData)
package alert

import (
	"fmt"
	"sync"
	"time"

	"dideban/internal/config"

	"github.com/rs/zerolog/log"
)

// Data represents the data structure for alerts.
type Data struct {
	MonitorID    int64     `json:"monitor_id"`
	MonitorName  string    `json:"monitor_name"`
	Status       string    `json:"status"` // up, down, warning
	Error        string    `json:"error"`
	ResponseTime int64     `json:"response_time"` // milliseconds
	CheckedAt    time.Time `json:"checked_at"`

	// Additional context
	Target   string                 `json:"target"`
	Metadata map[string]interface{} `json:"metadata"`
}

// Alerter defines the interface that all alert channels must implement.
type Alerter interface {
	// SendAlert sends an alert through the specific channel.
	SendAlert(data Data) error

	// Type returns the alerter type identifier.
	Type() string

	// IsEnabled returns whether the alerter is enabled.
	IsEnabled() bool
}

// Manager manages different alert channels and handles alert dispatching.
type Manager struct {
	alerters []Alerter

	// Alert throttling
	throttle map[string]time.Time
	mu       sync.RWMutex
}

// NewManager creates a new alert manager with configured alert channels.
//
// Parameters:
//   - cfg: Alert configuration containing channel settings
//
// Returns:
//   - *Manager: Initialized alert manager
//   - error: Any error that occurred during initialization
func NewManager(cfg config.AlertConfig) (*Manager, error) {
	manager := &Manager{
		alerters: make([]Alerter, 0),
		throttle: make(map[string]time.Time),
	}

	// Initialize Telegram alerter
	if cfg.Telegram.Enabled {
		telegramAlerter, err := NewTelegramAlerter(cfg.Telegram)
		if err != nil {
			return nil, fmt.Errorf("failed to create Telegram alerter: %w", err)
		}
		manager.alerters = append(manager.alerters, telegramAlerter)
		log.Info().Msg("Telegram alerter initialized")
	}

	// Initialize Bale alerter
	if cfg.Bale.Enabled {
		baleAlerter, err := NewBaleAlerter(cfg.Bale)
		if err != nil {
			return nil, fmt.Errorf("failed to create Bale alerter: %w", err)
		}
		manager.alerters = append(manager.alerters, baleAlerter)
		log.Info().Msg("Bale alerter initialized")
	}

	if len(manager.alerters) == 0 {
		log.Warn().Msg("No alert channels configured")
	}

	return manager, nil
}

// SendAlert sends an alert through all enabled channels.
// It handles throttling to prevent spam and formats the alert appropriately.
//
// Parameters:
//   - data: Alert data to send
//
// Returns:
//   - error: Any error that occurred during alert sending
func (m *Manager) SendAlert(data Data) error {
	// Check throttling
	if m.isThrottled(data) {
		log.Debug().Int64("monitor_id", data.MonitorID).Str("status", data.Status).Msg("Alert throttled")
		return nil
	}

	// Update throttle
	m.updateThrottle(data)

	log.Info().Int64("monitor_id", data.MonitorID).Str("monitor_name", data.MonitorName).Str("status", data.Status).Msg("Sending alert")

	// Send through all enabled alerters
	var errors []error
	for _, alerter := range m.alerters {
		if !alerter.IsEnabled() {
			continue
		}

		if err := alerter.SendAlert(data); err != nil {
			log.Error().Str("alerter_type", alerter.Type()).Err(err).Msg("Failed to send alert")
			errors = append(errors, fmt.Errorf("%s: %w", alerter.Type(), err))
		} else {
			log.Debug().Str("alerter_type", alerter.Type()).Msg("Alert sent successfully")
		}
	}

	// Return combined errors if any
	if len(errors) > 0 {
		return fmt.Errorf("alert sending failed: %v", errors)
	}

	return nil
}

// isThrottled checks if an alert should be throttled based on recent alerts.
// This prevents spam by limiting alerts for the same monitor within a time window.
//
// Parameters:
//   - data: Alert data to check
//
// Returns:
//   - bool: True if alert should be throttled, false otherwise
func (m *Manager) isThrottled(data Data) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	throttleKey := fmt.Sprintf("%d_%s", data.MonitorID, data.Status)
	lastAlert, exists := m.throttle[throttleKey]

	if !exists {
		return false
	}

	// Throttle for 5 minutes for the same status
	throttleDuration := 5 * time.Minute

	// Different throttling for different statuses
	switch data.Status {
	case "down":
		throttleDuration = 10 * time.Minute // Longer throttle for down alerts
	case "up":
		throttleDuration = 1 * time.Minute // Shorter throttle for recovery alerts
	case "warning":
		throttleDuration = 15 * time.Minute // Longer throttle for warnings
	}

	return time.Since(lastAlert) < throttleDuration
}

// updateThrottle updates the throttle timestamp for an alert.
//
// Parameters:
//   - data: Alert data to update throttle for
func (m *Manager) updateThrottle(data Data) {
	m.mu.Lock()
	defer m.mu.Unlock()

	throttleKey := fmt.Sprintf("%d_%s", data.MonitorID, data.Status)
	m.throttle[throttleKey] = time.Now()

	// Clean up old throttle entries (older than 1 hour)
	cutoff := time.Now().Add(-1 * time.Hour)
	for key, timestamp := range m.throttle {
		if timestamp.Before(cutoff) {
			delete(m.throttle, key)
		}
	}
}

// FormatAlertMessage formats an alert message for human consumption.
// This creates a standardized alert message format across all channels.
//
// Parameters:
//   - data: Alert data to format
//
// Returns:
//   - string: Formatted alert message
func FormatAlertMessage(data Data) string {
	var statusEmoji string
	switch data.Status {
	case "up":
		statusEmoji = "✅"
	case "down":
		statusEmoji = "❌"
	case "warning":
		statusEmoji = "⚠️"
	default:
		statusEmoji = "ℹ️"
	}

	message := fmt.Sprintf("%s *%s* is %s\n", statusEmoji, data.MonitorName, data.Status)

	if data.Target != "" {
		message += fmt.Sprintf("🎯 Target: `%s`\n", data.Target)
	}

	if data.Error != "" {
		message += fmt.Sprintf("❗ Error: %s\n", data.Error)
	}

	if data.ResponseTime > 0 {
		message += fmt.Sprintf("⏱️ Response Time: %dms\n", data.ResponseTime)
	}

	message += fmt.Sprintf("🕐 Time: %s", data.CheckedAt.Format("2006-01-02 15:04:05"))

	return message
}
