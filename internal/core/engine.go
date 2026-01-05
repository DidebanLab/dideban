// Package core provides the core monitoring engine for the Dideban system.
//
// The core engine is responsible for:
//   - Managing monitoring schedules
//   - Executing checks
//   - Processing results
//   - Triggering alerts
//   - Coordinating between different components
package core

import (
	"context"
	"fmt"
	"sync"

	"dideban/internal/alert"
	"dideban/internal/checks"
	"dideban/internal/config"
	"dideban/internal/storage"

	"github.com/rs/zerolog/log"
)

// Engine represents the core monitoring engine.
// It orchestrates all monitoring activities and manages the lifecycle of checks.
type Engine struct {
	config    *config.Config
	storage   *storage.Storage
	scheduler *Scheduler
	alerter   *alert.Manager
	checker   *checks.Manager

	// Internal state
	running bool
	mu      sync.RWMutex
	cancel  context.CancelFunc
	wg      sync.WaitGroup
}

// NewEngine creates a new monitoring engine with the given configuration.
//
// Parameters:
//   - cfg: Application configuration
//   - storage: Storage instance for data persistence
//   - logger: Logger instance for structured logging
//
// Returns:
//   - *Engine: Initialized engine instance
//   - error: Any error that occurred during initialization
func NewEngine(cfg *config.Config, storage *storage.Storage) (*Engine, error) {
	// Initialize alert manager
	alertManager, err := alert.NewManager(cfg.Alert)
	if err != nil {
		return nil, fmt.Errorf("failed to create alert manager: %w", err)
	}

	// Initialize check manager
	checkManager := checks.NewManager(cfg)

	// Initialize scheduler
	scheduler := NewScheduler(cfg.Scheduler)

	engine := &Engine{
		config:    cfg,
		storage:   storage,
		scheduler: scheduler,
		alerter:   alertManager,
		checker:   checkManager,
	}

	return engine, nil
}

// Start starts the monitoring engine and all its components.
// It loads monitors from storage and begins scheduling checks.
//
// Parameters:
//   - ctx: Context for cancellation and timeout
//
// Returns:
//   - error: Any error that occurred during startup
func (e *Engine) Start(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.running {
		return fmt.Errorf("engine is already running")
	}

	// Create cancellable context
	engineCtx, cancel := context.WithCancel(ctx)
	e.cancel = cancel

	log.Info().Msg("Starting monitoring engine")

	// Load checks
	allChecks, err := e.storage.Repositories().Checks.Where(context.Background(), "enabled = ?", true)
	if err != nil {
		cancel()
		return fmt.Errorf("failed to load checks: %w", err)
	}

	log.Info().Int("count", len(allChecks)).Msg("Loaded checks")

	// Load agents
	allAgents, err := e.storage.Repositories().Agents.Where(context.Background(), "enabled = ?", true)
	if err != nil {
		cancel()
		return fmt.Errorf("failed to load agents: %w", err)
	}

	log.Info().Int("count", len(allAgents)).Msg("Loaded agents")

	// Start scheduler
	if err := e.scheduler.Start(engineCtx); err != nil {
		cancel()
		return fmt.Errorf("failed to start scheduler: %w", err)
	}

	// Schedule all checks
	for _, check := range allChecks {
		if err := e.scheduleCheck(&check); err != nil {
			log.Error().Int64("check_id", check.ID).Str("name", check.Name).Err(err).Msg("Failed to schedule check")
			continue
		}
	}

	// Start result processor
	e.wg.Add(1)
	go e.processResults(engineCtx) // Background periodic processing

	e.running = true
	log.Info().Msg("Monitoring engine started successfully")

	return nil
}

// IsRunning returns whether the engine is currently running.
//
// Returns:
//   - bool: True if engine is running, false otherwise
func (e *Engine) IsRunning() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.running
}

// Stop stops the monitoring engine and all its components gracefully.
func (e *Engine) Stop() {
	e.mu.Lock()
	defer e.mu.Unlock()

	if !e.running {
		return
	}

	log.Info().Msg("Stopping monitoring engine")

	// Cancel context to stop all goroutines
	if e.cancel != nil {
		e.cancel()
	}

	// Stop scheduler
	e.scheduler.Stop()

	// Wait for all goroutines to finish
	e.wg.Wait()
	e.running = false
	log.Info().Msg("Monitoring engine stopped")
}
