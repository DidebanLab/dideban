// Package core provides core functionality for the Dideban application.
// It provides functionality for adding, scheduling, and executing tasks.
package core

import (
	"context"
	"errors"
	"fmt"
	"time"

	"dideban/internal/alert"
	"dideban/internal/storage"

	"github.com/rs/zerolog/log"
)

// AddCheck adds a new check to the engine and schedules it.
//
// Parameters:
//   - check: Check configuration to add
//
// Returns:
//   - error: Any error that occurred during addition
func (e *Engine) AddCheck(check *storage.Check) error {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if !e.running {
		return fmt.Errorf("engine is not running")
	}

	// Save check to storage
	if err := e.storage.DB().Create(check).Error; err != nil {
		return fmt.Errorf("failed to save check: %w", err)
	}

	// Schedule the check
	if err := e.scheduleCheck(check); err != nil {
		return fmt.Errorf("failed to schedule check: %w", err)
	}

	log.Info().Int64("check_id", check.ID).Str("name", check.Name).Msg("Check added")
	return nil
}

// scheduleCheck schedules a check for periodic execution.
//
// Parameters:
//   - check: Check to schedule
//
// Returns:
//   - error: Any error that occurred during scheduling
func (e *Engine) scheduleCheck(check *storage.Check) error {
	interval := time.Duration(check.IntervalSeconds) * time.Second

	job := &ScheduledJob{
		ID:       fmt.Sprintf("check_%d", check.ID),
		Interval: interval,
		Task: func(ctx context.Context) error {
			return e.executeCheck(ctx, check)
		},
	}

	return e.scheduler.AddJob(job)
}

// executeCheck executes a monitoring check for the given check.
//
// Parameters:
//   - ctx: Context for cancellation and timeout
//   - check: Check to execute
//
// Returns:
//   - error: Any error that occurred during check execution or persistence
func (e *Engine) executeCheck(ctx context.Context, check *storage.Check) error {
	// Create timeout context based on check configuration
	timeout := time.Duration(check.TimeoutSeconds) * time.Second
	checkCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Execute the check via the appropriate checker
	result, err := e.checker.ExecuteCheck(checkCtx, check)
	if err != nil {
		log.Error().
			Int64("check_id", check.ID).
			Str("name", check.Name).
			Err(err).
			Msg("Check execution failed")

		status := storage.CheckStatusError
		errorMsg := err.Error()

		// Special handling for timeout vs generic error
		if errors.Is(err, context.DeadlineExceeded) {
			status = storage.CheckStatusTimeout
		}

		// Create fallback result when checker fails entirely
		result = &storage.CheckHistory{
			CheckID:      check.ID,
			Status:       status,
			ErrorMessage: &errorMsg,
			CheckedAt:    time.Now(),
		}
	}

	// Validate result before saving (defensive programming)
	if err := storage.ValidateCheckHistory(result); err != nil {
		log.Error().
			Int64("check_id", check.ID).
			Err(err).
			Msg("Generated check history failed validation")
		return fmt.Errorf("invalid check history: %w", err)
	}

	// Persist result to database
	if err := e.storage.DB().Create(result).Error; err != nil {
		log.Error().
			Int64("check_id", check.ID).
			Err(err).
			Msg("Failed to save check result")
		return fmt.Errorf("failed to persist check history: %w", err)
	}

	// Trigger alerting pipeline if needed
	e.processCheckResult(check, result)

	return nil
}

// processCheckResult processes a single check result for alerting.
//
// Parameters:
//   - check: Check that was executed
//   - result: Check result to process
func (e *Engine) processCheckResult(check *storage.Check, result *storage.CheckHistory) {
	// Get all enabled alerts for this check
	var alerts []storage.Alert
	if err := e.storage.DB().
		Where("check_id = ? AND enabled = ?", check.ID, true).
		Find(&alerts).Error; err != nil {
		log.Error().Int64("check_id", check.ID).
			Str("name", check.Name).
			Err(err).
			Msg("Failed to retrieve alerts for check")
		return
	}

	// Process each alert
	for _, alertItem := range alerts {
		// Determine if this alert should be triggered
		if e.shouldTriggerAlert(&alertItem, result) {
			// Format alert data
			alertData := alert.Data{
				MonitorID:    check.ID,
				MonitorName:  check.Name,
				Status:       result.Status,
				Error:        "",
				ResponseTime: 0, // Initialize with 0
				CheckedAt:    result.CheckedAt,
				Target:       check.Target,
				Metadata:     make(map[string]interface{}),
			}

			if result.ResponseTimeMs != nil {
				alertData.ResponseTime = int64(*result.ResponseTimeMs)
			}

			if result.ErrorMessage != nil {
				alertData.Error = *result.ErrorMessage
			}

			// Send the alert
			if err := e.alerter.SendAlert(alertData); err != nil {
				log.Error().Int64("alert_id", alertItem.ID).Int64("check_id", check.ID).Err(err).Msg("Failed to send alert")
				// Create alert history record with failed status
				e.createAlertHistory(alertItem.ID, &result.ID, nil, "Alert Failed", alertData.Error, storage.AlertStatusFailed)
			} else {
				log.Info().Int64("alert_id", alertItem.ID).Int64("check_id", check.ID).Msg("Alert sent successfully")
				// Create alert history record with sent status
				title := fmt.Sprintf("Alert: %s is %s", check.Name, result.Status)
				message := alert.FormatAlertMessage(alertData)
				e.createAlertHistory(alertItem.ID, &result.ID, nil, title, message, storage.AlertStatusSent)
			}
		}
	}
}

// checkOfflineAgents performs a periodic health check for all enabled agents.
//
// This task produces a continuous monitoring timeline by recording an
// observation for each execution cycle in which an agent is expected to
// report metrics but does not.
//
// If an agent is considered offline at the time of evaluation, an offline
// agent_history record is created with IsOffline=true. These records may
// be created repeatedly and intentionally represent missed reporting
// intervals rather than state transitions.
//
// The agent's runtime status is updated to offline when applicable, but
// repeated offline observations do not cause additional status changes.
func (e *Engine) checkOfflineAgents() {
	var agents []storage.Agent
	if err := e.storage.DB().Where("enabled = ?", true).Find(&agents).Error; err != nil {
		log.Error().Err(err).Msg("failed to load enabled agents for offline check")
		return
	}

	now := time.Now()
	gracePeriod := 30 * time.Second

	for _, agent := range agents {
		isOffline := true

		if agent.LastSeenAt != nil {
			maxAllowedDelay := time.Duration(agent.IntervalSeconds)*time.Second + gracePeriod
			if now.Sub(*agent.LastSeenAt) <= maxAllowedDelay {
				isOffline = false
			}
		}

		// Agent is online at this check cycle
		if !isOffline {
			continue
		}

		// Update agent runtime status if necessary
		if agent.Status != storage.AgentStatusOffline {
			agent.Status = storage.AgentStatusOffline
			if err := e.storage.DB().Save(&agent).Error; err != nil {
				log.Error().
					Err(err).
					Int64("agent_id", agent.ID).
					Msg("failed to update agent status to offline")
			}
		}

		// Record an offline monitoring observation (intentional repetition)
		history := &storage.AgentHistory{
			AgentID:            agent.ID,
			IsOffline:          true,
			CollectDurationMs:  0,
			CPULoad1:           0,
			CPULoad5:           0,
			CPULoad15:          0,
			CPUUsagePercent:    0,
			MemoryTotalMB:      0,
			MemoryUsedMB:       0,
			MemoryAvailableMB:  0,
			MemoryUsagePercent: 0,
			DiskTotalGB:        0,
			DiskUsedGB:         0,
			DiskUsagePercent:   0,
			CollectedAt:        now,
		}

		if err := e.storage.DB().Create(history).Error; err != nil {
			log.Error().
				Err(err).
				Int64("agent_id", agent.ID).
				Msg("failed to create offline agent history")
			continue
		}

		log.Debug().
			Str("agent_name", agent.Name).
			Int64("history_id", history.ID).
			Str("status", agent.Status).
			Bool("offline", history.IsOffline).
			Msg("Created offline agent history record")

		// Trigger offline alerts (alert engine is responsible for throttling)
		var alerts []storage.Alert
		if err := e.storage.DB().
			Where("agent_id = ? AND enabled = ? AND condition_type = ?", agent.ID, true, "agent_offline").
			Find(&alerts).Error; err != nil {
			log.Error().
				Err(err).
				Int64("agent_id", agent.ID).
				Msg("failed to load offline alerts for agent")
			continue
		}

		if len(alerts) > 0 {
			e.triggerAgentOfflineAlert(agent, alerts, history)
		}
	}
}

// triggerAgentOfflineAlert triggers an alert when an agent goes offline.
func (e *Engine) triggerAgentOfflineAlert(agent storage.Agent, alerts []storage.Alert, history *storage.AgentHistory) {
	for _, alertItem := range alerts {
		// Format alert data
		alertData := alert.Data{
			MonitorID:    agent.ID,
			MonitorName:  agent.Name,
			Status:       "down",
			Error:        "",
			ResponseTime: 0, // No response time for offline detection
			CheckedAt:    history.CollectedAt,
			Target:       "Dideban Background Schedular tasks",
			Metadata:     make(map[string]interface{}),
		}

		// Add metadata about the offline event
		alertData.Metadata["interval_seconds"] = agent.IntervalSeconds + 30
		alertData.Metadata["last_seen"] = history.CollectedAt

		// Send the alert
		if err := e.alerter.SendAlert(alertData); err != nil {
			log.Error().Int64("alert_id", alertItem.ID).Int64("agent_id", agent.ID).Str("agent_name", agent.Name).Err(err).Msg("Failed to send offline agent alert")

			// Create alert history record with failed status
			e.createAlertHistory(alertItem.ID, nil, &history.ID, "Agent Offline Alert Failed", alertData.Error, storage.AlertStatusFailed)
		} else {
			log.Info().Int64("alert_id", alertItem.ID).Int64("agent_id", agent.ID).Str("agent_name", agent.Name).Msg("Offline agent alert sent successfully")

			// Create alert history record with sent status
			title := fmt.Sprintf("Agent Offline: %s", agent.Name)
			message := alert.FormatAlertMessage(alertData)
			e.createAlertHistory(alertItem.ID, nil, &history.ID, title, message, storage.AlertStatusSent)
		}
	}
}

// processResults processes check results in a separate goroutine.
// This method handles any additional result processing that needs to happen asynchronously.
//
// Parameters:
//   - ctx: Context for cancellation
func (e *Engine) processResults(ctx context.Context) {
	defer e.wg.Done()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Check for offline agents
			e.checkOfflineAgents()
		}
	}
}

// shouldTriggerAlert determines if an alert should be triggered based on the check result.
//
// Parameters:
//   - alert: Alert configuration
//   - result: Check result to evaluate
//
// Returns:
//   - bool: True if alert should be triggered, false otherwise
func (e *Engine) shouldTriggerAlert(alert *storage.Alert, result *storage.CheckHistory) bool {
	// Check if the condition matches the result status
	switch alert.ConditionType {
	case "status_down":
		return result.Status == storage.CheckStatusDown
	case "status_timeout":
		return result.Status == storage.CheckStatusTimeout
	case "status_error":
		return result.Status == storage.CheckStatusError
	default:
		return false // Unknown condition type
	}
}

// createAlertHistory creates a record in the alert history table.
//
// Parameters:
//   - alertID: ID of the alert that was triggered
//   - checkResultID: ID of the check result that triggered the alert
//   - agentMetricID: ID of the agent metric that triggered the alert (if applicable)
//   - title: Title of the alert message
//   - message: Full alert message
//   - status: Status of the alert (sent, failed, pending)
func (e *Engine) createAlertHistory(alertID int64, checkResultID *int64, agentMetricID *int64, title, message, status string) {
	history := storage.AlertHistory{
		AlertID:       alertID,
		CheckResultID: checkResultID,
		AgentMetricID: agentMetricID,
		Title:         title,
		Message:       message,
		Status:        status,
		SentAt:        time.Now(),
		CreatedAt:     time.Now(),
	}

	if err := e.storage.DB().Create(&history).Error; err != nil {
		if checkResultID != nil {
			log.Error().
				Int64("alert_id", alertID).
				Int64("check_result_id", *checkResultID).
				Err(err).Msg("Failed to create alert history")
		} else if agentMetricID != nil {
			log.Error().
				Int64("alert_id", alertID).
				Int64("alert_history_id", *agentMetricID).
				Err(err).Msg("Failed to create alert history")
		}
	}
}

// RemoveCheckFromScheduler removes a scheduled monitoring job for the given check ID.
//
// This method safely deregisters the check from the internal scheduler,
// ensuring that no further executions will occur. It is typically called
// when a check is deleted via the API or disabled permanently.
//
// The operation is idempotent: removing a non-existent job returns nil.
//
// Parameters:
//   - checkID: The unique identifier of the check to remove from scheduling.
//
// Returns:
//   - error: Any error encountered during job removal (e.g., scheduler internal failure).
//     Returns nil if the job does not exist or is successfully removed.
func (e *Engine) RemoveCheckFromScheduler(checkID int64) error {
	jobID := fmt.Sprintf("check_%d", checkID)
	return e.scheduler.RemoveJob(jobID)
}
