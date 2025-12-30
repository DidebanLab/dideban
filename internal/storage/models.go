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

// CheckHistory represents the result of a single check execution.
//
// This table stores historical data for all check executions,
// enabling trend analysis and performance monitoring.
type CheckHistory struct {
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

// AgentHistory represents a complete metrics snapshot from an agent.
//
// Instead of storing individual metrics in separate rows, this stores
// all metrics from a single collection cycle as structured fields.
// This reduces database rows from ~13 per collection to 1 per collection.
type AgentHistory struct {
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

// Alert represents an alert configuration for a check or agent.
//
// Alerts define how and when to notify users about check failures or agent issues.
// Multiple alerts can be configured for a single check or agent.
type Alert struct {
	// ID is the unique identifier for the alert
	ID int64 `db:"id,primary,auto_increment"`

	// CheckID references the check this alert monitors (optional)
	CheckID *int64 `db:"check_id"`

	// AgentID references the agent this alert monitors (optional)
	AgentID *int64 `db:"agent_id"`

	// Type defines the alert method: 'telegram', 'bale', 'email', or 'webhook'
	Type string `db:"type,not_null"`

	// Config contains JSON configuration specific to the alert type
	// For Telegram: {"token": "...", "chat_id": "..."}
	// For Email: {"smtp_host": "...", "to": "..."}
	Config string `db:"config,not_null"`

	// ConditionType defines the condition that triggers the alert
	// For checks: 'status_down', 'status_timeout', 'status_error'
	// For agents: 'cpu_usage_high', 'memory_usage_high', 'disk_usage_high', 'agent_offline'
	ConditionType string `db:"condition_type,not_null"`

	// ConditionValue contains the threshold value for the condition (e.g., 75 for 75% disk usage)
	ConditionValue *float64 `db:"condition_value"`

	// Enabled determines if the alert is active
	Enabled bool `db:"enabled,not_null"`

	// CreatedAt is the timestamp when the alert was created
	CreatedAt time.Time `db:"created_at,not_null"`

	// Check is the associated check (loaded via JOIN queries)
	Check *Check `db:"-"`

	// Agent is the associated agent (loaded via JOIN queries)
	Agent *Agent `db:"-"`
}

// AlertHistory represents a record of an alert that was sent.
//
// This model stores historical information about alerts that were sent,
// including when they were sent, what triggered them, and their status.
type AlertHistory struct {
	// ID is the unique identifier for the alert history record
	ID int64 `db:"id,primary,auto_increment"`

	// AlertID references the alert configuration that triggered this record
	AlertID int64 `db:"alert_id,not_null"`

	// CheckResultID references the check result that triggered the alert (optional)
	CheckResultID *int64 `db:"check_result_id"`

	// AgentMetricID references the agent metric that triggered the alert (optional)
	AgentMetricID *int64 `db:"agent_metric_id"`

	// Title is the title of the alert message
	Title string `db:"title,not_null"`

	// Message is the full alert message that was sent
	Message string `db:"message,not_null"`

	// Status indicates the status of the alert: 'sent', 'failed', 'pending'
	Status string `db:"status,not_null"`

	// SentAt is the timestamp when the alert was sent
	SentAt time.Time `db:"sent_at,not_null"`

	// CreatedAt is the timestamp when the history record was created
	CreatedAt time.Time `db:"created_at,not_null"`
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

// TableName methods return the database table name for each model.
// These are used by the ORM for automatic table name resolution.

// TableName returns the database table name for Check.
func (Check) TableName() string {
	return "checks"
}

// TableName returns the database table name for CheckHistory.
func (CheckHistory) TableName() string {
	return "check_history"
}

// TableName returns the database table name for Agent.
func (Agent) TableName() string {
	return "agents"
}

// TableName returns the database table name for AgentHistory.
func (AgentHistory) TableName() string {
	return "agent_history"
}

// TableName returns the database table name for Alert.
func (Alert) TableName() string {
	return "alerts"
}

// TableName returns the database table name for AlertHistory.
func (AlertHistory) TableName() string {
	return "alert_history"
}

// TableName returns the database table name for Admin.
func (Admin) TableName() string {
	return "admins"
}

// CheckType constants define the supported check types.
const (
	CheckTypeHTTP = "http"
	CheckTypePing = "ping"
)

// CheckTypes contains all possible check types.
var CheckTypes = []string{CheckTypeHTTP, CheckTypePing}

// CheckStatus constants define the possible check result statuses.
const (
	CheckStatusUp      = "up"
	CheckStatusDown    = "down"
	CheckStatusError   = "error"
	CheckStatusTimeout = "timeout"
)

// CheckStatuses contains all possible check statuses.
var CheckStatuses = []string{CheckStatusUp, CheckStatusDown, CheckStatusError, CheckStatusTimeout}

// AlertType constants define the supported alert types.
const (
	AlertTypeTelegram = "telegram"
	AlertTypeBale     = "bale"
	AlertTypeEmail    = "email"
	AlertTypeWebhook  = "webhook"
)

// AlertTypes contains all possible alert types.
var AlertTypes = []string{AlertTypeTelegram, AlertTypeBale, AlertTypeEmail, AlertTypeWebhook}

// AlertStatus constants define the possible alert history statuses.
const (
	AlertStatusSent    = "sent"
	AlertStatusFailed  = "failed"
	AlertStatusPending = "pending"
)

// AlertStatuses contains all possible alert statuses.
var AlertStatuses = []string{AlertStatusSent, AlertStatusFailed, AlertStatusPending}

// AlertConditionTypes contains all possible alert condition types.
var AlertConditionTypes = []string{
	"status_down",
	"status_timeout",
	"status_error",
	"cpu_usage_high",
	"memory_usage_high",
	"disk_usage_high",
	"agent_offline",
}

// AgentStatus constants define the possible agent statuses.
const (
	AgentStatusOnline  = "online"
	AgentStatusOffline = "offline"
)

// AgentStatuses contains all possible agent statuses.
var AgentStatuses = []string{AgentStatusOnline, AgentStatusOffline}
