// Package core provides core functionality for the Dideban application.
// It provides functionality for adding, scheduling, and executing tasks.
package core

import (
	"context"
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
	id, err := e.storage.Repositories().Checks.Create(context.Background(), check)
	if err != nil {
		return fmt.Errorf("failed to save check: %w", err)
	}

	// Update the ID in the original check
	check.ID = id

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
//   - error: Any error that occurred during check execution
func (e *Engine) executeCheck(ctx context.Context, check *storage.Check) error {
	log.Debug().Int64("check_id", check.ID).Str("name", check.Name).Msg("Executing check")

	// Create timeout context
	timeout := time.Duration(check.TimeoutSeconds) * time.Second
	checkCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Execute the check
	result, err := e.checker.ExecuteCheck(checkCtx, check)
	if err != nil {
		log.Error().Int64("check_id", check.ID).Str("name", check.Name).Err(err).Msg("Check execution failed")

		// Create error result
		errorMsg := err.Error()
		result = &storage.CheckHistory{
			CheckID:      check.ID,
			Status:       storage.CheckStatusError,
			ErrorMessage: &errorMsg,
			CheckedAt:    time.Now(),
		}
	}

	// Save result to storage
	_, err = e.storage.Repositories().CheckHistory.Create(context.Background(), result)
	if err != nil {
		log.Error().Int64("check_id", check.ID).Err(err).Msg("Failed to save check result")
		return err
	}

	// Process result for alerting
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
	alerts, err := e.storage.Repositories().Alerts.Where(context.Background(), "check_id = ? AND enabled = ?", check.ID, true)
	if err != nil {
		log.Error().Int64("check_id", check.ID).Str("name", check.Name).Err(err).Msg("Failed to retrieve alerts for check")
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

// GetStatus returns the current status of all checks.
//
// Returns:
//   - map[int64]*storage.CheckHistory: Latest check results by check ID
//   - error: Any error that occurred during status retrieval
func (e *Engine) GetStatus() (map[int64]*storage.CheckHistory, error) {
	// Get all check results to find the latest for each check
	allResults, err := e.storage.Repositories().CheckHistory.GetAll(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to get all check results: %w", err)
	}

	// Group results by check ID and keep only the latest for each check
	latestResults := make(map[int64]storage.CheckHistory)
	for _, result := range allResults {
		if existing, exists := latestResults[result.CheckID]; !exists || result.CheckedAt.After(existing.CheckedAt) {
			latestResults[result.CheckID] = result
		}
	}

	statusMap := make(map[int64]*storage.CheckHistory)
	for checkID, result := range latestResults {
		resultCopy := result
		statusMap[checkID] = &resultCopy
	}

	return statusMap, nil
}

// checkOfflineAgents checks for agents that haven't reported within their expected interval
// and creates offline history records for them.
func (e *Engine) checkOfflineAgents(ctx context.Context) {
	// Get all enabled agents
	agents, err := e.storage.Repositories().Agents.Where(ctx, "enabled = ?", true)
	if err != nil {
		log.Error().Err(err).Msg("Failed to get enabled agents for offline check")
		return
	}

	for _, agent := range agents {
		// Get the latest agent history for this agent (ordered by collected_at DESC, limit 1)
		latestHistories, err := e.storage.Repositories().AgentHistory.Where(ctx, "agent_id = ? ORDER BY collected_at DESC LIMIT 1", agent.ID)
		if err != nil {
			log.Error().Err(err).Int64("agent_id", agent.ID).Msg("Failed to get latest agent history")
			continue
		}

		// If no history exists, skip this agent
		if len(latestHistories) == 0 {
			continue
		}

		latestHistory := &latestHistories[0]

		// Calculate the maximum allowed time based on the agent's interval
		maxAllowedDuration := time.Duration(agent.IntervalSeconds)*time.Second + 30

		// Check if the latest history is older than the maximum allowed duration
		if time.Since(latestHistory.CollectedAt) > maxAllowedDuration {
			// Create an offline history record for this agent with zero values for metrics
			// This indicates that the agent didn't report and is considered offline
			offlineHistory := &storage.AgentHistory{
				AgentID:            agent.ID,
				CollectDurationMs:  0, // No collection happened
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
				CollectedAt:        time.Now(),
			}

			// Save the offline history record
			if _, err := e.storage.Repositories().AgentHistory.Create(ctx, offlineHistory); err != nil {
				log.Error().Err(err).Int64("agent_id", agent.ID).Msg("Failed to create offline history record")
				continue
			}

			log.Info().Int64("agent_id", agent.ID).Str("agent_name", agent.Name).Msg("Agent marked as offline due to inactivity")

			// Trigger alert if the agent has alert configurations
			// Check if there are any enabled alerts for this agent
			alerts, err := e.storage.Repositories().Alerts.Where(context.Background(), "agent_id = ? AND enabled = ? AND condition_type = ?", agent.ID, true, "agent_offline")
			if err != nil {
				log.Error().Int64("agent_id", agent.ID).Err(err).Msg("Failed to check for alerts for agent")
			} else if len(alerts) > 0 {
				e.triggerAgentOfflineAlert(agent, alerts, offlineHistory)
			}
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
			e.checkOfflineAgents(ctx)
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

	_, err := e.storage.Repositories().AlertHistory.Create(context.Background(), &history)
	if err != nil {
		if checkResultID != nil {
			log.Error().Int64("alert_id", alertID).Int64("check_result_id", *checkResultID).Err(err).Msg("Failed to create alert history")
		} else if agentMetricID != nil {
			log.Error().Int64("alert_id", alertID).Int64("alert_history_id", *agentMetricID).Err(err).Msg("Failed to create alert history")
		}
	}
}
