// Package storage defines the data models for Dideban monitoring system.
//
// All models use struct tags to define database column mappings and constraints.
// The ORM uses these tags for automatic query generation and result mapping.
//
// Struct Tag Format:
//
//	`db:"column_name,constraint1,constraint2"`
//
// Supported constraints:
//   - primary: Marks the field as primary key
//   - unique: Adds unique constraint
//   - not_null: Adds NOT NULL constraint
//   - auto_increment: For auto-incrementing fields
package storage

import (
	"time"
)

// Check represents a monitoring target (HTTP endpoint, ping target, or agent).
//
// This is the core entity in Dideban - everything revolves around checks.
// Each check defines what to monitor, how often, and what constitutes success/failure.
type Check struct {
	// ID is the unique identifier for the check
	ID int64 `db:"id,primary,auto_increment"`

	// Enabled determines if the check is active
	Enabled bool `db:"enabled,not_null"`

	// Name is a human-readable identifier for the check
	// Must be unique across all checks
	Name string `db:"name,not_null,unique"`

	// Type defines the kind of check: 'http', 'ping'
	Type string `db:"type,not_null"`

	// Target is the monitoring target (URL for HTTP, hostname for ping)
	Target string `db:"target,not_null"`

	// IntervalSeconds defines how often the check should run (in seconds)
	IntervalSeconds int `db:"interval_seconds,not_null"`

	// TimeoutSeconds defines the maximum time to wait for a response
	TimeoutSeconds int `db:"timeout_seconds,not_null"`

	// CreatedAt is the timestamp when the check was created
	CreatedAt time.Time `db:"created_at,not_null"`

	// UpdatedAt is the timestamp when the check was last modified
	UpdatedAt time.Time `db:"updated_at,not_null"`
}

// CheckResult represents the result of a single check execution.
//
// This table stores historical data for all check executions,
// enabling trend analysis and performance monitoring.
type CheckResult struct {
	// ID is the unique identifier for the check result
	ID int64 `db:"id,primary,auto_increment"`

	// CheckID references the check that was executed
	CheckID int64 `db:"check_id,not_null"`

	// Status is the result status: 'up', 'down', 'timeout', or 'error'
	Status string `db:"status,not_null"`

	// ResponseTimeMs is the response time in milliseconds (for HTTP/ping checks)
	ResponseTimeMs *int `db:"response_time_ms"`

	// StatusCode is the HTTP status code (for HTTP checks only)
	StatusCode *int `db:"status_code"`

	// ErrorMessage contains error details if the check failed
	ErrorMessage *string `db:"error_message"`

	// CheckedAt is the timestamp when the check was executed
	CheckedAt time.Time `db:"checked_at,not_null"`

	// Check is the associated check (loaded via JOIN queries)
	Check *Check `db:"-"` // The "-" tag excludes this from database operations
}

// Alert represents an alert configuration for a check.
//
// Alerts define how and when to notify users about check failures.
// Multiple alerts can be configured for a single check.
type Alert struct {
	// ID is the unique identifier for the alert
	ID int64 `db:"id,primary,auto_increment"`

	// CheckID references the check this alert monitors
	CheckID int64 `db:"check_id,not_null"`

	// Type defines the alert method: 'telegram', 'bale', 'email', or 'webhook'
	Type string `db:"type,not_null"`

	// Config contains JSON configuration specific to the alert type
	// For Telegram: {"token": "...", "chat_id": "..."}
	// For Email: {"smtp_host": "...", "to": "..."}
	Config string `db:"config,not_null"`

	// Enabled determines if the alert is active
	Enabled bool `db:"enabled,not_null"`

	// LastSent is the timestamp of the most recent alert sent
	LastSent *time.Time `db:"last_sent"`

	// CreatedAt is the timestamp when the alert was created
	CreatedAt time.Time `db:"created_at,not_null"`

	// Check is the associated check (loaded via JOIN queries)
	Check *Check `db:"-"`
}

// Agent represents a system monitoring agent.
//
// Agents are lightweight processes that collect system metrics
// and report them back to the Dideban server.
type Agent struct {
	// ID is the unique identifier for the agent
	ID int64 `db:"id,primary,auto_increment"`

	// Name is a human-readable identifier for the agent
	// Must be unique across all agents
	Name string `db:"name,not_null,unique"`

	// Enabled determines if the agent is active
	Enabled bool `db:"enabled,not_null"`

	// IntervalSeconds defines how often the agent should collect metrics (in seconds)
	IntervalSeconds int `db:"interval_seconds,not_null"`

	// AuthToken is the authentication token for secure agent communication
	AuthToken string `db:"auth_token,not_null,unique"`

	// CreatedAt is the timestamp when the agent was first registered
	CreatedAt time.Time `db:"created_at,not_null"`

	// UpdatedAt is the timestamp when the agent was last updated
	UpdatedAt time.Time `db:"updated_at,not_null"`
}

// AgentMetric represents a complete metrics snapshot from an agent.
//
// Instead of storing individual metrics in separate rows, this stores
// all metrics from a single collection cycle as structured fields.
// This reduces database rows from ~13 per collection to 1 per collection.
type AgentMetric struct {
	// ID is the unique identifier for the metric record
	ID int64 `db:"id,primary,auto_increment"`

	// AgentID references the agent that collected this metric
	AgentID int64 `db:"agent_id,not_null"`

	// CollectDurationMs is how long it took to collect all metrics (in milliseconds)
	CollectDurationMs int `db:"collect_duration_ms,not_null"`

	// CPULoad1 is the 1-minute load average
	CPULoad1 float64 `db:"cpu_load_1,not_null"`

	// CPULoad5 is the 5-minute load average
	CPULoad5 float64 `db:"cpu_load_5,not_null"`

	// CPULoad15 is the 15-minute load average
	CPULoad15 float64 `db:"cpu_load_15,not_null"`

	// CPUUsagePercent is the CPU usage percentage
	CPUUsagePercent float64 `db:"cpu_usage_percent,not_null"`

	// MemoryTotalMB is the total memory in MB
	MemoryTotalMB int64 `db:"memory_total_mb,not_null"`

	// MemoryUsedMB is the used memory in MB
	MemoryUsedMB int64 `db:"memory_used_mb,not_null"`

	// MemoryAvailableMB is the available memory in MB
	MemoryAvailableMB int64 `db:"memory_available_mb,not_null"`

	// MemoryUsagePercent is the memory usage percentage
	MemoryUsagePercent float64 `db:"memory_usage_percent,not_null"`

	// DiskTotalGB is the total disk space in GB
	DiskTotalGB int64 `db:"disk_total_gb,not_null"`

	// DiskUsedGB is the used disk space in GB
	DiskUsedGB int64 `db:"disk_used_gb,not_null"`

	// DiskUsagePercent is the disk usage percentage
	DiskUsagePercent float64 `db:"disk_usage_percent,not_null"`

	// CollectedAt is the timestamp when metrics were collected
	CollectedAt time.Time `db:"collected_at,not_null"`

	// Agent is the associated agent (loaded via JOIN queries)
	Agent *Agent `db:"-"`
}

// Admin represents an administrator user for the Dideban dashboard.
//
// Admins can access the web interface to manage checks, agents, and alerts.
// Passwords should be hashed before storage (bcrypt recommended).
type Admin struct {
	// ID is the unique identifier for the admin
	ID int64 `db:"id,primary,auto_increment"`

	// Username is the login username (must be unique)
	Username string `db:"username,not_null,unique"`

	// Password is the hashed password (never store plaintext)
	Password string `db:"password,not_null"`

	// FullName is the admin's display name
	FullName string `db:"full_name,not_null"`
}

// CheckType constants define the supported check types.
const (
	CheckTypeHTTP = "http"
	CheckTypePing = "ping"
)

// CheckStatus constants define the possible check statuses.
const (
	CheckStatusUp      = "up"
	CheckStatusDown    = "down"
	CheckStatusUnknown = "unknown"
)

// CheckResultStatus constants define the possible check result statuses.
const (
	ResultStatusUp    = "up"
	ResultStatusDown  = "down"
	ResultStatusError = "error"
)

// AlertType constants define the supported alert types.
const (
	AlertTypeTelegram = "telegram"
	AlertTypeBale     = "bale"
	AlertTypeEmail    = "email"
	AlertTypeWebhook  = "webhook"
)

// AgentStatus constants define the possible agent statuses.
const (
	AgentStatusPending = "pending"
	AgentStatusOnline  = "online"
	AgentStatusOffline = "offline"
	AgentStatusUnknown = "unknown"
)

// TableName methods return the database table name for each model.
// These are used by the ORM for automatic table name resolution.

// TableName returns the database table name for Check.
func (Check) TableName() string {
	return "checks"
}

// TableName returns the database table name for CheckResult.
func (CheckResult) TableName() string {
	return "check_results"
}

// TableName returns the database table name for Alert.
func (Alert) TableName() string {
	return "alerts"
}

// TableName returns the database table name for Agent.
func (Agent) TableName() string {
	return "agents"
}

// TableName returns the database table name for AgentMetric.
func (AgentMetric) TableName() string {
	return "agent_metrics"
}

// TableName returns the database table name for Admin.
func (Admin) TableName() string {
	return "admins"
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
	case CheckStatusUp, CheckStatusDown, CheckStatusUnknown:
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

// IsValidAgentStatus validates if an agent status is valid.
func IsValidAgentStatus(status string) bool {
	switch status {
	case AgentStatusPending, AgentStatusOnline, AgentStatusOffline, AgentStatusUnknown:
		return true
	default:
		return false
	}
}
