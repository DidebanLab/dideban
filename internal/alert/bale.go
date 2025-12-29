// Package alert provides Bale.ai alerting functionality.
package alert

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"

	"dideban/internal/config"

	"github.com/rs/zerolog/log"
)

// BaleMessage represents a Bale bot API message.
type BaleMessage struct {
	ChatID string `json:"chat_id"`
	Text   string `json:"text"`
}

// BaleAlerter implements Bale.ai bot alerting.
type BaleAlerter struct {
	config config.BotConfig
	client *http.Client
	apiURL string
}

// NewBaleAlerter creates a new Bale alerter instance.
//
// Parameters:
//   - cfg: Bot configuration containing bot token and chat ID
//
// Returns:
//   - *BaleAlerter: Initialized Bale alerter
//   - error: Any error that occurred during initialization
func NewBaleAlerter(cfg config.BotConfig) (*BaleAlerter, error) {
	if cfg.Token == "" {
		return nil, fmt.Errorf("bale bot token is required")
	}
	if cfg.ChatID == "" {
		return nil, fmt.Errorf("bale chat id is required")
	}

	client := &http.Client{
		Timeout: cfg.Timeout,
	}

	apiURL := fmt.Sprintf("https://tapi.bale.ai/bot%s/sendMessage", cfg.Token)

	alerter := &BaleAlerter{
		config: cfg,
		client: client,
		apiURL: apiURL,
	}

	// Test connection
	if err := alerter.testConnection(); err != nil {
		return nil, fmt.Errorf("failed to connect to Bale API: %w", err)
	}

	return alerter, nil
}

// Type returns the alerter type identifier.
//
// Returns:
//   - string: Type identifier "bale"
func (b *BaleAlerter) Type() string {
	return "bale"
}

// IsEnabled returns whether the Bale alerter is enabled.
//
// Returns:
//   - bool: True if enabled, false otherwise
func (b *BaleAlerter) IsEnabled() bool {
	return b.config.Enabled
}

// SendAlert sends an alert message via Bale bot.
//
// Parameters:
//   - data: Alert data to send
//
// Returns:
//   - error: Any error that occurred during sending
func (b *BaleAlerter) SendAlert(data Data) error {
	// Format message (Bale doesn't support Markdown, so use plain text)
	message := FormatAlertMessage(data)

	// Create Bale message
	baleMsg := BaleMessage{
		ChatID: b.config.ChatID,
		Text:   message,
	}

	// Send message
	if err := b.sendMessage(baleMsg); err != nil {
		return fmt.Errorf("failed to send Bale message: %w", err)
	}

	log.Debug().Int64("monitor_id", data.MonitorID).Str("chat_id", b.config.ChatID).Msg("Bale alert sent")
	return nil
}

// sendMessage sends a message via Bale bot API.
//
// Parameters:
//   - message: Bale message to send
//
// Returns:
//   - error: Any error that occurred during sending
func (b *BaleAlerter) sendMessage(message BaleMessage) error {
	// Marshal message to JSON
	jsonData, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %w", err)
	}

	// Create HTTP request
	req, err := http.NewRequest("POST", b.apiURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	// Send request
	resp, err := b.client.Do(req)
	if err != nil {
		return fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bale API returned status %d", resp.StatusCode)
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
		return fmt.Errorf("bale API error: %s", description)
	}

	return nil
}

// testConnection tests the connection to Bale API by calling getMe.
//
// Returns:
//   - error: Any error that occurred during testing
func (b *BaleAlerter) testConnection() error {
	getMeURL := fmt.Sprintf("https://tapi.bale.ai/bot%s/getMe", b.config.Token)

	resp, err := b.client.Get(getMeURL)
	if err != nil {
		return fmt.Errorf("failed to connect to Bale API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bale API returned status %d", resp.StatusCode)
	}

	var response map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}

	if ok, exists := response["ok"].(bool); !exists || !ok {
		return fmt.Errorf("bale API test failed")
	}

	log.Debug().Msg("Bale connection test successful")
	return nil
}
