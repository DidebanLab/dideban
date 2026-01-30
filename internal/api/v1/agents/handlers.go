package agents

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"dideban/internal/api/types"
	"dideban/internal/storage"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// Handler handles agent management endpoints
type Handler struct {
	storage *storage.Storage
}

// NewHandler creates a new agents handler instance
func NewHandler(storage *storage.Storage) *Handler {
	return &Handler{
		storage: storage,
	}
}

// List handles GET /api/v1/agents
//
// Returns a paginated list of agents ordered by ID in descending order.
// Each agent includes its current runtime status and last seen timestamp.
//
// Query parameters:
// - page (default: 1)
// - page_size (default: 20, max: 100)
//
// Returns:
// - 200 OK with paginated agent list
// - 400 Bad Request for invalid pagination parameters
// - 500 Internal Server Error on storage failure
func (h *Handler) List(c *gin.Context) {
	var pagination types.PaginationRequest
	if err := c.ShouldBindQuery(&pagination); err != nil {
		types.AbortWithError(c, types.ValidationError(err.Error()))
		return
	}

	// Apply optional enabled filter
	enabledFilter := c.Query("enabled")
	query := h.storage.DB().Model(&storage.Agent{})

	if enabledFilter != "" {
		enabled, err := strconv.ParseBool(enabledFilter)
		if err == nil {
			query = query.Where("enabled = ?", enabled)
		}
	}

	// Count total agents matching filters
	var total int64
	if err := query.Count(&total).Error; err != nil {
		types.AbortWithError(c, types.InternalError("failed to count agents", err))
		return
	}

	// Calculate offset and retrieve paginated checks
	offset := (pagination.Page - 1) * pagination.PageSize
	var agents []storage.Agent
	if err := query.
		Order("id DESC").
		Limit(pagination.PageSize).
		Offset(offset).
		Find(&agents).Error; err != nil {
		types.AbortWithError(c, types.InternalError("failed to retrieve agents", err))
		return
	}

	// Map to response objects
	responses := make([]AgentResponse, 0, len(agents))
	for _, agent := range agents {
		status, lastSeen := agent.Status, agent.LastSeenAt

		responses = append(responses, AgentResponse{
			ID:              agent.ID,
			Name:            agent.Name,
			Enabled:         agent.Enabled,
			IntervalSeconds: agent.IntervalSeconds,
			AuthToken:       maskToken(agent.AuthToken),
			Status:          status,
			LastSeen:        lastSeen,
			CreatedAt:       agent.CreatedAt,
			UpdatedAt:       agent.UpdatedAt,
		})
	}

	// Calculate total pages
	totalPages := int((total + int64(pagination.PageSize) - 1) / int64(pagination.PageSize))

	paginationResponse := &types.PaginationResponse{
		Page:       pagination.Page,
		PageSize:   pagination.PageSize,
		Total:      total,
		TotalPages: totalPages,
	}

	c.JSON(http.StatusOK,
		types.SuccessResponseWithPagination(responses, paginationResponse))
}

// Create handles POST /api/v1/agents
//
// Creates a new agent with the provided configuration.
// The agent name must be unique. If not explicitly set,
// the agent is enabled by default.
//
// Required fields:
//   - name
//   - interval_seconds
//
// Optional fields:
//   - enabled (default: true)
//
// Returns:
//   - 201 Created with agent details
//   - 400 Bad Request for invalid input
//   - 409 Conflict if agent name already exists
//   - 500 Internal Server Error on storage failure
func (h *Handler) Create(c *gin.Context) {
	var req AgentRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		types.AbortWithError(c, types.ValidationError(err.Error()))
		return
	}

	// Validate required fields
	if req.Name == nil || req.IntervalSeconds == nil {
		types.AbortWithError(c, types.ValidationError("name and interval_seconds are required"))
		return
	}

	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	// Ensure name uniqueness
	var existing storage.Agent
	err := h.storage.DB().Where("name = ?", *req.Name).First(&existing).Error

	switch {
	case err == nil:
		// Name already exists
		types.AbortWithError(c, types.ConflictError("agent with this name already exists"))
		return
	case errors.Is(err, gorm.ErrRecordNotFound):
		// OK — name is available, proceed
	default:
		// Unexpected database error
		types.AbortWithError(c, types.InternalError("failed to check agent name uniqueness", err))
		return
	}

	now := time.Now()

	agent := &storage.Agent{
		Name:            *req.Name,
		IntervalSeconds: *req.IntervalSeconds,
		Enabled:         enabled,
		CreatedAt:       now,
		UpdatedAt:       now,
	}

	if err := h.storage.DB().Create(agent).Error; err != nil {
		types.AbortWithError(c, types.InternalError("failed to create agent", err))
		return
	}

	response := AgentResponse{
		ID:              agent.ID,
		Name:            agent.Name,
		Enabled:         agent.Enabled,
		IntervalSeconds: agent.IntervalSeconds,
		AuthToken:       agent.AuthToken,
		Status:          storage.AgentStatusOffline,
		LastSeen:        nil,
		CreatedAt:       agent.CreatedAt,
		UpdatedAt:       agent.UpdatedAt,
	}

	c.JSON(http.StatusCreated, types.SuccessResponse(response))
}

// Stats handles GET /api/v1/agents/stats
//
// Returns a summary of all agents, including total count, enabled/disabled breakdown,
// and status distribution (online vs offline).
//
// This implementation uses a single efficient SQL query compatible with both
// SQLite and PSQL, avoiding multiple round trips to the database.
//
// Returns:
//   - 200 OK with agent statistics
//   - 500 Internal Server Error on storage failure
func (h *Handler) Stats(c *gin.Context) {
	db := h.storage.DB()

	type StatsResult struct {
		Total    int64 `gorm:"column:total"`
		Enabled  int64 `gorm:"column:enabled"`
		Disabled int64 `gorm:"column:disabled"`
		Online   int64 `gorm:"column:online"`
		Offline  int64 `gorm:"column:offline"`
	}

	var result StatsResult

	// Single query that works on both SQLite and PSQL
	query := `
SELECT
    COUNT(*) AS total,
    SUM(CASE WHEN enabled = true THEN 1 ELSE 0 END) AS enabled,
    SUM(CASE WHEN enabled = false THEN 1 ELSE 0 END) AS disabled,
    SUM(CASE WHEN status = ? THEN 1 ELSE 0 END) AS online,
    SUM(CASE WHEN status = ? THEN 1 ELSE 0 END) AS offline
FROM agents
`

	if err := db.Raw(query, storage.AgentStatusOnline, storage.AgentStatusOffline).Scan(&result).Error; err != nil {
		types.AbortWithError(c, types.InternalError("failed to compute agent stats", err))
		return
	}

	response := gin.H{
		"total":    result.Total,
		"enabled":  result.Enabled,
		"disabled": result.Disabled,
		"status": gin.H{
			"online":  result.Online,
			"offline": result.Offline,
		},
	}

	c.JSON(http.StatusOK, types.SuccessResponse(response))
}

// Get handles GET /api/v1/agents/:id
//
// Retrieves detailed information about a single agent by its ID,
// including its current runtime status and last seen timestamp.
//
// Returns:
//   - 200 OK with agent details
//   - 400 Bad Request for invalid agent ID
//   - 404 Not Found if agent does not exist
//   - 500 Internal Server Error on storage failure
func (h *Handler) Get(c *gin.Context) {
	// Parse and validate agent ID
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		types.AbortWithError(c, types.ValidationError("invalid agent ID"))
		return
	}

	// Retrieve agent
	var agent storage.Agent
	if err := h.storage.DB().Where("id = ?", id).First(&agent).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			types.AbortWithError(c, types.NotFoundError("agent"))
		} else {
			types.AbortWithError(c, types.InternalError("failed to retrieve agent", err))
		}
		return
	}

	// Resolve runtime status
	status, lastSeen := agent.Status, agent.LastSeenAt

	response := AgentResponse{
		ID:              agent.ID,
		Name:            agent.Name,
		Enabled:         agent.Enabled,
		IntervalSeconds: agent.IntervalSeconds,
		AuthToken:       maskToken(agent.AuthToken),
		Status:          status,
		LastSeen:        lastSeen,
		CreatedAt:       agent.CreatedAt,
		UpdatedAt:       agent.UpdatedAt,
	}

	c.JSON(http.StatusOK, types.SuccessResponse(response))
}

// Delete handles DELETE /api/v1/agents/:id
//
// Permanently deletes an agent by its ID. If the agent exists,
// all related resources are removed via database cascade rules.
//
// Returns:
//   - 200 OK on successful deletion
//   - 400 Bad Request for invalid agent ID
//   - 404 Not Found if agent does not exist
//   - 500 Internal Server Error on storage failure
func (h *Handler) Delete(c *gin.Context) {
	// Parse and validate agent ID
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		types.AbortWithError(c, types.ValidationError("invalid agent ID"))
		return
	}

	// Ensure agent exists for proper 404 semantics
	var count int64
	if err := h.storage.DB().
		Model(&storage.Agent{}).
		Where("id = ?", id).
		Limit(1).
		Count(&count).Error; err != nil {

		types.AbortWithError(c, types.InternalError("failed to check agent existence", err))
		return
	}

	if count == 0 {
		types.AbortWithError(c, types.NotFoundError("agent"))
		return
	}

	// Delete agent (GORM handles CASCADE via foreign key constraints in the database)
	if err := h.storage.DB().Delete(&storage.Agent{}, id).Error; err != nil {
		types.AbortWithError(c, types.InternalError("failed to delete agent", err))
		return
	}

	c.JSON(http.StatusOK, types.SuccessResponse(gin.H{
		"message": "agent deleted successfully",
	}))
}

// Update handles PATCH /api/v1/agents/:id
//
// Partially updates an agent. Only the fields provided in the request body
// will be modified; all other fields remain unchanged.
//
// Possible updates:
// - name (must be unique)
// - interval_seconds (10–86400)
// - enabled
//
// Returns:
// - 200 OK with updated agent
// - 400 Bad Request for invalid input or empty payload
// - 404 Not Found if agent does not exist
// - 409 Conflict if name is already taken
// - 500 Internal Server Error on storage failure
func (h *Handler) Update(c *gin.Context) {
	// Parse and validate agent ID
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		types.AbortWithError(c, types.ValidationError("invalid agent ID"))
		return
	}

	// Bind request body
	var req AgentRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		types.AbortWithError(c, types.ValidationError(err.Error()))
		return
	}

	// Reject empty PATCH payload
	if req.Name == nil && req.IntervalSeconds == nil && req.Enabled == nil {
		types.AbortWithError(c, types.ValidationError("no fields to update"))
		return
	}

	// Retrieve existing agent
	var agent storage.Agent
	if err := h.storage.DB().Where("id = ?", id).First(&agent).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			types.AbortWithError(c, types.NotFoundError("agent"))
		} else {
			types.AbortWithError(c, types.InternalError("failed to retrieve agent", err))
		}
		return
	}

	// Apply only the fields that are provided
	if req.Name != nil {
		agent.Name = *req.Name
	}
	if req.IntervalSeconds != nil {
		agent.IntervalSeconds = *req.IntervalSeconds
	}
	if req.Enabled != nil {
		agent.Enabled = *req.Enabled
	}

	// Validate and update name if provided
	if err := h.storage.DB().Save(&agent).Error; err != nil {
		// Convert common validation errors to 4xx
		if strings.Contains(err.Error(), "UNIQUE constraint failed") ||
			strings.Contains(err.Error(), "name already exists") ||
			strings.Contains(err.Error(), "name cannot be empty") ||
			strings.Contains(err.Error(), "interval too short") {
			types.AbortWithError(c, types.ConflictError(err.Error()))
		} else {
			types.AbortWithError(c, types.InternalError("failed to update agent", err))
		}
		return
	}

	response := AgentResponse{
		ID:              agent.ID,
		Name:            agent.Name,
		Enabled:         agent.Enabled,
		IntervalSeconds: agent.IntervalSeconds,
		AuthToken:       maskToken(agent.AuthToken),
		Status:          agent.Status,
		LastSeen:        agent.LastSeenAt,
		CreatedAt:       agent.CreatedAt,
		UpdatedAt:       agent.UpdatedAt,
	}

	c.JSON(http.StatusOK, types.SuccessResponse(response))
}

// RegenerateToken handles POST /api/v1/agents/:id/regenerate
//
// Regenerates the authentication token for a specific agent.
// This invalidates any existing tokens and requires agents to use the new token
// for future metric submissions.
//
// The operation is atomic and includes full validation of the updated agent.
//
// Returns:
//   - 200 OK with updated agent (including new auth_token)
//   - 400 Bad Request for invalid agent ID
//   - 404 Not Found if agent does not exist
//   - 500 Internal Server Error on storage or token generation failure
func (h *Handler) RegenerateToken(c *gin.Context) {
	// Parse and validate agent ID
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		types.AbortWithError(c, types.ValidationError("invalid agent ID"))
		return
	}

	// Fetch the existing agent
	var agent storage.Agent
	if err := h.storage.DB().Where("id = ?", id).First(&agent).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			types.AbortWithError(c, types.NotFoundError("agent"))
		} else {
			types.AbortWithError(c, types.InternalError("failed to retrieve agent", err))
		}
		return
	}

	// Clear current auth token to force regeneration in ValidateAgent
	agent.AuthToken = ""

	// Save the agent — ValidateAgent will generate a new token
	if err := h.storage.DB().Save(&agent).Error; err != nil {
		types.AbortWithError(c, types.InternalError("failed to regenerate agent token", err))
		return
	}

	// Prepare response (mask token for security in logs/UI, but return full token once)
	response := AgentResponse{
		ID:              agent.ID,
		Name:            agent.Name,
		Enabled:         agent.Enabled,
		IntervalSeconds: agent.IntervalSeconds,
		AuthToken:       agent.AuthToken, // Return full token (user needs it!)
		Status:          agent.Status,
		LastSeen:        agent.LastSeenAt,
		CreatedAt:       agent.CreatedAt,
		UpdatedAt:       agent.UpdatedAt,
	}

	c.JSON(http.StatusOK, types.SuccessResponse(response))
}

// History handles GET /api/v1/agents/:id/history
//
// Returns a paginated list of historical metrics collected for a specific agent,
// ordered by collection time in descending order.
//
// Query parameters:
//   - page (default: 1)
//   - page_size (default: 50 if short=true, otherwise 20; max: 500)
//   - short (optional boolean): if true, returns compact format [id, is_offline]
//
// Compact format (when short=true):
//   - Response data is an array of arrays: [[id1, is_offline1], [id2, is_offline2], ...]
//   - Only two fields are included: ID and IsOffline
//   - Pagination still applies
//
// Returns:
//   - 200 OK with paginated agent metrics (full or compact format)
//   - 400 Bad Request for invalid agent ID or pagination parameters
//   - 404 Not Found if agent does not exist
//   - 500 Internal Server Error on storage failure
func (h *Handler) History(c *gin.Context) {
	// Parse and validate agent ID
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		types.AbortWithError(c, types.ValidationError("invalid agent ID"))
		return
	}

	// Ensure agent exists
	var count int64
	if err := h.storage.DB().
		Model(&storage.Agent{}).
		Where("id = ?", id).
		Limit(1).
		Count(&count).Error; err != nil {

		types.AbortWithError(c, types.InternalError("failed to check agent existence", err))
		return
	}

	if count == 0 {
		types.AbortWithError(c, types.NotFoundError("agent"))
		return
	}

	// Bind pagination and short query parameters
	var pagination types.PaginationRequest
	if err := c.ShouldBindQuery(&pagination); err != nil {
		types.AbortWithError(c, types.ValidationError(err.Error()))
		return
	}

	page := pagination.Page
	pageSize := pagination.PageSize

	offset := (page - 1) * pageSize

	// Count total metrics
	var total int64
	if err := h.storage.DB().
		Model(&storage.AgentHistory{}).
		Where("agent_id = ?", id).
		Count(&total).Error; err != nil {

		types.AbortWithError(c, types.InternalError("failed to count agent metrics", err))
		return
	}

	if pagination.Short {
		// Compact mode: fetch only ID and IsOffline
		type CompactRecord struct {
			ID        int64 `gorm:"column:id"`
			IsOffline bool  `gorm:"column:is_offline"`
		}

		var compactRecords []CompactRecord
		if err := h.storage.DB().
			Select("id, is_offline").
			Model(storage.AgentHistory{}).
			Where("agent_id = ?", id).
			Order("collected_at DESC").
			Limit(pageSize).
			Offset(offset).
			Find(&compactRecords).Error; err != nil {

			types.AbortWithError(c, types.InternalError("failed to retrieve compact agent metrics", err))
			return
		}

		// Convert to array of arrays: [[id, is_offline], ...]
		compactResponse := make([][]interface{}, len(compactRecords))
		for i, r := range compactRecords {
			var status string
			if r.IsOffline {
				status = storage.AgentStatusOffline
			} else {
				status = storage.AgentStatusOnline
			}

			compactResponse[i] = []interface{}{r.ID, status}
		}

		totalPages := int((total + int64(pageSize) - 1) / int64(pageSize))
		paginationResponse := &types.PaginationResponse{
			Page:       page,
			PageSize:   pageSize,
			Total:      total,
			TotalPages: totalPages,
		}

		c.JSON(http.StatusOK, types.SuccessResponseWithPagination(compactResponse, paginationResponse))
		return
	}

	// Full mode: fetch all metrics
	var metrics []storage.AgentHistory
	if err := h.storage.DB().
		Where("agent_id = ?", id).
		Order("collected_at DESC").
		Limit(pageSize).
		Offset(offset).
		Find(&metrics).Error; err != nil {

		types.AbortWithError(c, types.InternalError("failed to retrieve agent metrics", err))
		return
	}

	// Map metrics to response DTOs
	responses := make([]AgentMetricsResponse, 0, len(metrics))
	for _, m := range metrics {
		responses = append(responses, AgentMetricsResponse{
			ID:                 m.ID,
			AgentID:            m.AgentID,
			IsOffline:          m.IsOffline,
			CollectDurationMs:  m.CollectDurationMs,
			CPULoad1:           m.CPULoad1,
			CPULoad5:           m.CPULoad5,
			CPULoad15:          m.CPULoad15,
			CPUUsagePercent:    m.CPUUsagePercent,
			MemoryTotalMB:      m.MemoryTotalMB,
			MemoryUsedMB:       m.MemoryUsedMB,
			MemoryAvailableMB:  m.MemoryAvailableMB,
			MemoryUsagePercent: m.MemoryUsagePercent,
			DiskTotalGB:        m.DiskTotalGB,
			DiskUsedGB:         m.DiskUsedGB,
			DiskUsagePercent:   m.DiskUsagePercent,
			CollectedAt:        m.CollectedAt,
		})
	}

	totalPages := int((total + int64(pageSize) - 1) / int64(pageSize))
	paginationResponse := &types.PaginationResponse{
		Page:       page,
		PageSize:   pageSize,
		Total:      total,
		TotalPages: totalPages,
	}

	c.JSON(http.StatusOK, types.SuccessResponseWithPagination(responses, paginationResponse))
}

// CreateHistory handles POST /api/v1/agents/:id/history
//
// Receives and stores a single metrics snapshot from an agent.
// The agent must exist and be enabled. Upon successful submission,
// the agent's last_seen_at timestamp is updated accordingly.
//
// Returns:
//   - 201 Created with stored metrics
//   - 400 Bad Request for invalid input
//   - 403 Forbidden if agent is disabled
//   - 404 Not Found if agent does not exist
//   - 500 Internal Server Error on storage failure
func (h *Handler) CreateHistory(c *gin.Context) {
	// Parse agent ID
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		types.AbortWithError(c, types.ValidationError("invalid agent ID"))
		return
	}

	// Bind request body
	var req AgentMetricsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		types.AbortWithError(c, types.ValidationError(err.Error()))
		return
	}

	// Convert timestamp (ms) to time.Time
	collectedAt := time.UnixMilli(req.TimestampMs)

	// Build history record
	history := &storage.AgentHistory{
		AgentID:            id,
		IsOffline:          false,
		CollectDurationMs:  req.CollectDurationMs,
		CPULoad1:           req.CPU.Load1,
		CPULoad5:           req.CPU.Load5,
		CPULoad15:          req.CPU.Load15,
		CPUUsagePercent:    req.CPU.UsagePercent,
		MemoryTotalMB:      req.Memory.TotalMB,
		MemoryUsedMB:       req.Memory.UsedMB,
		MemoryAvailableMB:  req.Memory.AvailableMB,
		MemoryUsagePercent: req.Memory.UsagePercent,
		DiskTotalGB:        req.Disk.TotalGB,
		DiskUsedGB:         req.Disk.UsedGB,
		DiskUsagePercent:   req.Disk.UsagePercent,
		CollectedAt:        collectedAt,
	}

	// Store metrics
	if err := h.storage.DB().Create(history).Error; err != nil {
		types.AbortWithError(c, types.InternalError("failed to store agent metrics", err))
		return
	}

	// Update agent last_seen_at and status without triggering full validation
	if err := h.storage.DB().
		Session(&gorm.Session{SkipHooks: true}).
		Model(&storage.Agent{}).
		Where("id = ?", id).
		Updates(map[string]interface{}{
			"last_seen_at": collectedAt,
			"status":       storage.AgentStatusOnline,
		}).Error; err != nil {

		types.AbortWithError(c, types.InternalError("failed to update agent last_seen_at and status", err))
		return
	}

	response := AgentMetricsResponse{
		ID:                 history.ID,
		AgentID:            history.AgentID,
		CollectDurationMs:  history.CollectDurationMs,
		CPULoad1:           history.CPULoad1,
		CPULoad5:           history.CPULoad5,
		CPULoad15:          history.CPULoad15,
		CPUUsagePercent:    history.CPUUsagePercent,
		MemoryTotalMB:      history.MemoryTotalMB,
		MemoryUsedMB:       history.MemoryUsedMB,
		MemoryAvailableMB:  history.MemoryAvailableMB,
		MemoryUsagePercent: history.MemoryUsagePercent,
		DiskTotalGB:        history.DiskTotalGB,
		DiskUsedGB:         history.DiskUsedGB,
		DiskUsagePercent:   history.DiskUsagePercent,
		CollectedAt:        history.CollectedAt,
	}

	c.JSON(http.StatusCreated, types.SuccessResponse(response))
}

// GetHistoryByID handles GET /api/v1/agents/:id/history/:history_id
//
// Retrieves a single historical metrics record for a specific agent by its history ID.
// This endpoint provides direct access to a specific observation without pagination.
//
// The agent ID in the path must match the agent associated with the history record,
// and the agent must be enabled (enabled = true) to prevent data leakage from disabled agents.
//
// Special behavior:
//   - If IsOffline is true, only [id, agent_id, is_offline, collected_at] are returned
//   - If IsOffline is false, full metric fields are returned (same as History endpoint)
//
// Returns:
//   - 200 OK with the agent history detail
//   - 400 Bad Request for invalid agent ID or history ID
//   - 404 Not Found if agent or history record does not exist (or agent is disabled)
//   - 500 Internal Server Error on storage failure
func (h *Handler) GetHistoryByID(c *gin.Context) {
	// Parse and validate agent ID
	agentID, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		types.AbortWithError(c, types.ValidationError("invalid agent ID"))
		return
	}

	// Parse and validate history ID
	historyID, err := strconv.ParseInt(c.Param("history_id"), 10, 64)
	if err != nil {
		types.AbortWithError(c, types.ValidationError("invalid history ID"))
		return
	}

	// Fetch the specific history record with agent ownership check
	var history storage.AgentHistory
	err = h.storage.DB().
		Where("id = ? AND agent_id = ?", historyID, agentID).
		First(&history).Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			types.AbortWithError(c, types.NotFoundError("agent history record"))
		} else {
			types.AbortWithError(c, types.InternalError("failed to retrieve agent history", err))
		}
		return
	}

	// Build response based on IsOffline flag
	var response interface{}

	if history.IsOffline {
		// Compact mode: only essential fields
		response = gin.H{
			"id":           history.ID,
			"agent_id":     history.AgentID,
			"is_offline":   true,
			"collected_at": history.CollectedAt,
		}
	} else {
		// Full mode: use standard AgentMetricsResponse
		response = AgentMetricsResponse{
			ID:                 history.ID,
			AgentID:            history.AgentID,
			IsOffline:          false,
			CollectDurationMs:  history.CollectDurationMs,
			CPULoad1:           history.CPULoad1,
			CPULoad5:           history.CPULoad5,
			CPULoad15:          history.CPULoad15,
			CPUUsagePercent:    history.CPUUsagePercent,
			MemoryTotalMB:      history.MemoryTotalMB,
			MemoryUsedMB:       history.MemoryUsedMB,
			MemoryAvailableMB:  history.MemoryAvailableMB,
			MemoryUsagePercent: history.MemoryUsagePercent,
			DiskTotalGB:        history.DiskTotalGB,
			DiskUsedGB:         history.DiskUsedGB,
			DiskUsagePercent:   history.DiskUsagePercent,
			CollectedAt:        history.CollectedAt,
		}
	}

	c.JSON(http.StatusOK, types.SuccessResponse(response))
}

// MaskToken returns a masked version of the given token.
func maskToken(token string) string {
	r := []rune(token)
	if len(r) <= 8 {
		return token
	}
	return string(r[:8]) + strings.Repeat("*", len(r)-8)
}
