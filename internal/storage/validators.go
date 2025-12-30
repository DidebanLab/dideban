// Package storage provides interfaces and implementations for interacting with the database.
// It includes functions for validating check types, statuses, alert types, statuses, and agent statuses.
package storage

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
