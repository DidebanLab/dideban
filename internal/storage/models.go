// Package storage defines the data models for the Dideban monitoring system.
//
// All models are designed to work with GORM v2 and follow production-grade
// conventions for SQLite and Postgresql applications. Each model includes:
//   - GORM struct tags for precise schema control
//   - TableName() method for explicit table naming
//   - Validate() method that delegates to validators.go
//   - GORM hooks (BeforeCreate, BeforeUpdate) for automatic validation
//   - Proper use of pointers for nullable fields
//   - Clear documentation for every field and constant
package storage

import (
	"time"

	"gorm.io/gorm"
)

// Check represents a monitoring target such as an HTTP endpoint or a ping host.
// It is the core entity around which checks, alerts, and history are built.
type Check struct {
	ID              int64     `gorm:"primaryKey;autoIncrement;not null"`
	Enabled         bool      `gorm:"not null;default:true"`
	Name            string    `gorm:"not null;uniqueIndex;size:100"`
	Type            string    `gorm:"not null;size:10"` // e.g., "http", "ping"
	Config          string    `gorm:"type:text"`        // JSON-encoded configuration
	Target          string    `gorm:"not null"`
	IntervalSeconds int       `gorm:"not null;default:60"`
	TimeoutSeconds  int       `gorm:"not null;default:5"`
	CreatedAt       time.Time `gorm:"not null;default:CURRENT_TIMESTAMP"`
	UpdatedAt       time.Time `gorm:"not null;default:CURRENT_TIMESTAMP"`
}

// TableName returns the database table name for Check.
func (Check) TableName() string {
	return "checks"
}

// Validate delegates validation to the external validator function.
func (c *Check) Validate() error {
	return ValidateCheck(c)
}

// BeforeCreate runs before inserting a new Check into the database.
// It ensures the entity is valid before persistence.
func (c *Check) BeforeCreate(tx *gorm.DB) error {
	return c.Validate()
}

// BeforeUpdate runs before updating an existing Check in the database.
// It ensures the modified entity remains valid.
func (c *Check) BeforeUpdate(tx *gorm.DB) error {
	return c.Validate()
}

// CheckHistory records the result of a single execution of a Check.
// It captures performance metrics, status, and errors for historical analysis.
type CheckHistory struct {
	ID             int64     `gorm:"primaryKey;autoIncrement;not null"`
	CheckID        int64     `gorm:"not null;index"`
	Status         string    `gorm:"not null;size:10"` // e.g., "up", "down", "error", "timeout"
	ResponseTimeMs *int      `gorm:"null"`             // in milliseconds
	StatusCode     *int      `gorm:"null"`             // HTTP status code (for HTTP checks)
	ErrorMessage   *string   `gorm:"null;size:1000"`
	CheckedAt      time.Time `gorm:"not null;default:CURRENT_TIMESTAMP;index"`
}

// TableName returns the database table name for CheckHistory.
func (CheckHistory) TableName() string {
	return "check_history"
}

// Validate delegates validation to the external validator function.
func (ch *CheckHistory) Validate() error {
	return ValidateCheckHistory(ch)
}

// BeforeCreate runs before inserting a new CheckHistory record.
func (ch *CheckHistory) BeforeCreate(tx *gorm.DB) error {
	return ch.Validate()
}

// BeforeUpdate runs before updating an existing CheckHistory record.
func (ch *CheckHistory) BeforeUpdate(tx *gorm.DB) error {
	return ch.Validate()
}

// Agent represents a remote monitoring agent that collects system metrics.
// Agents authenticate via a unique token and report metrics periodically.
type Agent struct {
	ID              int64      `gorm:"primaryKey;autoIncrement;not null"`
	Name            string     `gorm:"not null;uniqueIndex;size:100"`
	Enabled         bool       `gorm:"not null;default:true"`
	IntervalSeconds int        `gorm:"not null;default:60"`
	AuthToken       string     `gorm:"not null;uniqueIndex;size:128"`
	Status          string     `gorm:"not null;size:7;default:'offline'"` // "online" or "offline"
	LastSeenAt      *time.Time `gorm:"null;index"`
	CreatedAt       time.Time  `gorm:"not null;default:CURRENT_TIMESTAMP"`
	UpdatedAt       time.Time  `gorm:"not null;default:CURRENT_TIMESTAMP"`

	// Composite index for stats query
	_ struct{} `gorm:"index:idx_agents_enabled_status,columns:enabled,status"`
}

// TableName returns the database table name for Agent.
func (Agent) TableName() string {
	return "agents"
}

// Validate delegates validation to the external validator function.
func (a *Agent) Validate() error {
	return ValidateAgent(a)
}

// BeforeCreate runs before inserting a new Agent.
func (a *Agent) BeforeCreate(tx *gorm.DB) error {
	return a.Validate()
}

// BeforeUpdate runs before updating an existing Agent.
func (a *Agent) BeforeUpdate(tx *gorm.DB) error {
	return a.Validate()
}

// AgentHistory captures a full snapshot of system metrics collected by an Agent.
// One record = one collection cycle, minimizing row count while preserving granularity.
type AgentHistory struct {
	ID                 int64     `gorm:"primaryKey;autoIncrement;not null"`
	IsOffline          bool      `gorm:"not null;default:false;index"`
	AgentID            int64     `gorm:"not null;index"`
	CollectDurationMs  int64     `gorm:"not null"`
	CPULoad1           float64   `gorm:"not null"`
	CPULoad5           float64   `gorm:"not null"`
	CPULoad15          float64   `gorm:"not null"`
	CPUUsagePercent    float64   `gorm:"not null"`
	MemoryTotalMB      int64     `gorm:"not null"`
	MemoryUsedMB       int64     `gorm:"not null"`
	MemoryAvailableMB  int64     `gorm:"not null"`
	MemoryUsagePercent float64   `gorm:"not null"`
	DiskTotalGB        int64     `gorm:"not null"`
	DiskUsedGB         int64     `gorm:"not null"`
	DiskUsagePercent   float64   `gorm:"not null"`
	CollectedAt        time.Time `gorm:"not null;default:CURRENT_TIMESTAMP;index"`
}

// TableName returns the database table name for AgentHistory.
func (AgentHistory) TableName() string {
	return "agent_history"
}

// Validate delegates validation to the external validator function.
func (ah *AgentHistory) Validate() error {
	return ValidateAgentHistory(ah)
}

// BeforeCreate runs before inserting a new AgentHistory record.
func (ah *AgentHistory) BeforeCreate(tx *gorm.DB) error {
	return ah.Validate()
}

// BeforeUpdate runs before updating an existing AgentHistory record.
func (ah *AgentHistory) BeforeUpdate(tx *gorm.DB) error {
	return ah.Validate()
}

// Alert defines a notification rule triggered by check failures or agent anomalies.
// Each alert is associated with exactly one Check or one Agent (not both).
type Alert struct {
	ID             int64     `gorm:"primaryKey;autoIncrement;not null"`
	CheckID        *int64    `gorm:"null;index"`
	AgentID        *int64    `gorm:"null;index"`
	Type           string    `gorm:"not null;size:20"` // e.g., "telegram", "email"
	Config         string    `gorm:"type:text"`        // JSON-encoded alert-specific config
	ConditionType  string    `gorm:"not null;size:30"`
	ConditionValue *float64  `gorm:"null"`
	Enabled        bool      `gorm:"not null;default:true"`
	CreatedAt      time.Time `gorm:"not null;default:CURRENT_TIMESTAMP"`
}

// TableName returns the database table name for Alert.
func (Alert) TableName() string {
	return "alerts"
}

// Validate delegates validation to the external validator function.
func (a *Alert) Validate() error {
	return ValidateAlert(a)
}

// BeforeCreate runs before inserting a new Alert.
func (a *Alert) BeforeCreate(tx *gorm.DB) error {
	return a.Validate()
}

// BeforeUpdate runs before updating an existing Alert.
func (a *Alert) BeforeUpdate(tx *gorm.DB) error {
	return a.Validate()
}

// AlertHistory records the outcome of sent alert (success/failure/pending).
// It is used for auditing, debugging, and retry logic.
type AlertHistory struct {
	ID            int64     `gorm:"primaryKey;autoIncrement;not null"`
	AlertID       int64     `gorm:"not null;index"`
	CheckResultID *int64    `gorm:"null;index"`
	AgentMetricID *int64    `gorm:"null;index"`
	Title         string    `gorm:"not null;size:200"`
	Message       string    `gorm:"not null;size:5000"`
	Status        string    `gorm:"not null;size:20"` // e.g., "sent", "failed"
	SentAt        time.Time `gorm:"not null;index"`
	CreatedAt     time.Time `gorm:"not null;default:CURRENT_TIMESTAMP"`
}

// TableName returns the database table name for AlertHistory.
func (AlertHistory) TableName() string {
	return "alert_history"
}

// Validate delegates validation to the external validator function.
func (ah *AlertHistory) Validate() error {
	return ValidateAlertHistory(ah)
}

// BeforeCreate runs before inserting a new AlertHistory record.
func (ah *AlertHistory) BeforeCreate(tx *gorm.DB) error {
	return ah.Validate()
}

// BeforeUpdate runs before updating an existing AlertHistory record.
func (ah *AlertHistory) BeforeUpdate(tx *gorm.DB) error {
	return ah.Validate()
}

// Admin represents a system administrator with access to the management dashboard.
// Passwords must be bcrypt-hashed before storage.
type Admin struct {
	ID       int64  `gorm:"primaryKey;autoIncrement;not null"`
	Username string `gorm:"not null;uniqueIndex;size:50"`
	Password string `gorm:"not null;size:255"` // bcrypt hash
	FullName string `gorm:"not null;size:100"`
}

// TableName returns the database table name for Admin.
func (Admin) TableName() string {
	return "admins"
}

// Validate delegates validation to the external validator function.
func (a *Admin) Validate() error {
	return ValidateAdmin(a)
}

// BeforeCreate runs before inserting a new Admin.
func (a *Admin) BeforeCreate(tx *gorm.DB) error {
	return a.Validate()
}

// BeforeUpdate runs before updating an existing Admin.
func (a *Admin) BeforeUpdate(tx *gorm.DB) error {
	return a.Validate()
}

// CheckType constants define supported monitoring types.
const (
	CheckTypeHTTP = "http"
	CheckTypePing = "ping"
)

// CheckStatus constants define possible outcomes of a check execution.
const (
	CheckStatusUp      = "up"
	CheckStatusDown    = "down"
	CheckStatusError   = "error"
	CheckStatusTimeout = "timeout"
)

// AlertType constants define supported notification channels.
const (
	AlertTypeTelegram = "telegram"
	AlertTypeBale     = "bale"
	AlertTypeEmail    = "email"
	AlertTypeWebhook  = "webhook"
)

// AlertStatus constants define delivery states of an alert.
const (
	AlertStatusSent    = "sent"
	AlertStatusFailed  = "failed"
	AlertStatusPending = "pending"
)

// AgentStatus constants define runtime states of an agent.
const (
	AgentStatusOnline  = "online"
	AgentStatusOffline = "offline"
)
