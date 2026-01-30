package agents

import "time"

// AgentRequest represents the request payload for creating or updating an agent
type AgentRequest struct {
	Name            *string `json:"name,omitempty" binding:"omitempty,min=1,max=100"`
	IntervalSeconds *int    `json:"interval_seconds,omitempty" binding:"omitempty,min=10,max=86400"`
	Enabled         *bool   `json:"enabled,omitempty"`
}

// AgentResponse represents an agent in API responses
type AgentResponse struct {
	ID              int64      `json:"id"`
	Name            string     `json:"name"`
	Enabled         bool       `json:"enabled"`
	IntervalSeconds int        `json:"interval_seconds"`
	AuthToken       string     `json:"auth_token"`
	Status          string     `json:"status"`
	LastSeen        *time.Time `json:"last_seen"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

// AgentMetricsRequest represents the request payload for submitting agent metrics
type AgentMetricsRequest struct {
	TimestampMs       int64 `json:"timestamp_ms" binding:"required,min=0"`
	CollectDurationMs int64 `json:"collect_duration_ms" binding:"required,min=0"`

	CPU struct {
		Load1        float64 `json:"load_1" binding:"required,min=0"`
		Load5        float64 `json:"load_5" binding:"required,min=0"`
		Load15       float64 `json:"load_15" binding:"required,min=0"`
		UsagePercent float64 `json:"usage_percent" binding:"required,min=0,max=100"`
	} `json:"cpu" binding:"required"`

	Memory struct {
		TotalMB      int64   `json:"total_mb" binding:"required,min=0"`
		UsedMB       int64   `json:"used_mb" binding:"required,min=0"`
		AvailableMB  int64   `json:"available_mb" binding:"required,min=0"`
		UsagePercent float64 `json:"usage_percent" binding:"required,min=0,max=100"`
	} `json:"memory" binding:"required"`

	Disk struct {
		TotalGB      int64   `json:"total_gb" binding:"required,min=0"`
		UsedGB       int64   `json:"used_gb" binding:"required,min=0"`
		UsagePercent float64 `json:"usage_percent" binding:"required,min=0,max=100"`
	} `json:"disk" binding:"required"`
}

// AgentMetricsResponse represents agent metrics in API responses
type AgentMetricsResponse struct {
	ID                 int64     `json:"id"`
	AgentID            int64     `json:"agent_id"`
	IsOffline          bool      `json:"is_offline"`
	CollectDurationMs  int64     `json:"collect_duration_ms"`
	CPULoad1           float64   `json:"cpu_load_1"`
	CPULoad5           float64   `json:"cpu_load_5"`
	CPULoad15          float64   `json:"cpu_load_15"`
	CPUUsagePercent    float64   `json:"cpu_usage_percent"`
	MemoryTotalMB      int64     `json:"memory_total_mb"`
	MemoryUsedMB       int64     `json:"memory_used_mb"`
	MemoryAvailableMB  int64     `json:"memory_available_mb"`
	MemoryUsagePercent float64   `json:"memory_usage_percent"`
	DiskTotalGB        int64     `json:"disk_total_gb"`
	DiskUsedGB         int64     `json:"disk_used_gb"`
	DiskUsagePercent   float64   `json:"disk_usage_percent"`
	CollectedAt        time.Time `json:"collected_at"`
}
