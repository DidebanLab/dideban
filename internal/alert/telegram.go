// Package alert provides Telegram alerting functionality.
package alert

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"

	"dideban/internal/config"

	"github.com/rs/zerolog/log"
)

// TelegramMessage represents a Telegram bot API message.
type TelegramMessage struct {
	ChatID    string `json:"chat_id"`
	Text      string `json:"text"`
	ParseMode string `json:"parse_mode"`
}

// TelegramAlerter implements Telegram bot alerting.
type TelegramAlerter struct {
	config config.BotConfig
	client *http.Client
	apiURL string
}

// NewTelegramAlerter creates a new Telegram alerter instance.
//
// Parameters:
//   - cfg: Bot configuration containing bot token and chat ID
//
// Returns:
//   - *TelegramAlerter: Initialized Telegram alerter
//   - error: Any error that occurred during initialization
func NewTelegramAlerter(cfg config.BotConfig) (*TelegramAlerter, error) {
	if cfg.Token == "" {
		return nil, fmt.Errorf("telegram bot token is required")
	}
	if cfg.ChatID == "" {
		return nil, fmt.Errorf("telegram chat ID is required")
	}

	client := &http.Client{
		Timeout: cfg.Timeout,
	}

	apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", cfg.Token)

	alerter := &TelegramAlerter{
		config: cfg,
		client: client,
		apiURL: apiURL,
	}

	// Test connection
	if err := alerter.testConnection(); err != nil {
		return nil, fmt.Errorf("failed to connect to Telegram API: %w", err)
	}

	return alerter, nil
}

// Type returns the alerter type identifier.
//
// Returns:
//   - string: Type identifier "telegram"
func (t *TelegramAlerter) Type() string {
	return "telegram"
}

// IsEnabled returns whether the Telegram alerter is enabled.
//
// Returns:
//   - bool: True if enabled, false otherwise
func (t *TelegramAlerter) IsEnabled() bool {
	return t.config.Enabled
}

// SendAlert sends an alert message via Telegram bot.
//
// Parameters:
//   - data: Alert data to send
//
// Returns:
//   - error: Any error that occurred during sending
func (t *TelegramAlerter) SendAlert(data Data) error {
	// Format message
	message := FormatAlertMessage(data)

	// Create Telegram message
	telegramMsg := TelegramMessage{
		ChatID:    t.config.ChatID,
		Text:      message,
		ParseMode: "Markdown",
	}

	// Send message
	if err := t.sendMessage(telegramMsg); err != nil {
		return fmt.Errorf("failed to send Telegram message: %w", err)
	}

	log.Debug().Int64("monitor_id", data.MonitorID).Str("chat_id", t.config.ChatID).Msg("Telegram alert sent")
	return nil
}

// sendMessage sends a message via Telegram bot API.
//
// Parameters:
//   - message: Telegram message to send
//
// Returns:
//   - error: Any error that occurred during sending
func (t *TelegramAlerter) sendMessage(message TelegramMessage) error {
	// Marshal message to JSON
	jsonData, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %w", err)
	}

	// Create HTTP request
	req, err := http.NewRequest("POST", t.apiURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	// Send request
	resp, err := t.client.Do(req)
	if err != nil {
		return fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("telegram API returned status %d", resp.StatusCode)
	}

	// Parse response
	var response map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}

	// Check if request was successful
	if ok, exists := response["ok"].(bool); !exists || !ok {
		description := "unknown error"
		if desc, exists := response["description"].(string); exists {
			description = desc
		}
		return fmt.Errorf("telegram API error: %s", description)
	}

	return nil
}

// testConnection tests the connection to Telegram API by calling getMe.
//
// Returns:
//   - error: Any error that occurred during testing
func (t *TelegramAlerter) testConnection() error {
	getMeURL := fmt.Sprintf("https://api.telegram.org/bot%s/getMe", t.config.Token)

	resp, err := t.client.Get(getMeURL)
	if err != nil {
		return fmt.Errorf("failed to connect to Telegram API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("telegram API returned status %d", resp.StatusCode)
	}

	var response map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}

	if ok, exists := response["ok"].(bool); !exists || !ok {
		return fmt.Errorf("telegram API test failed")
	}

	log.Debug().Msg("Telegram connection test successful")
	return nil
}
