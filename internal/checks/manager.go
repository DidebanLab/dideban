// Package checks provides monitoring check implementations for the Dideban system.
//
// This package contains different types of checks (HTTP, Ping) and
// manages their execution. Each check type implements the Checker interface.
//
// Supported check types:
//   - HTTP/HTTPS: Monitor web endpoints
//   - Ping (ICMP): Monitor network connectivity
//
// Example usage:
//
//	manager := checks.NewManager(logger)
//	result, err := manager.ExecuteCheck(ctx, check)
package checks

import (
	"context"
	"fmt"

	"dideban/internal/config"
	"dideban/internal/storage"

	"github.com/rs/zerolog/log"
)

// Checker defines the interface that all check types must implement.
type Checker interface {
	// Check executes the monitoring check and returns the result.
	Check(ctx context.Context, check *storage.Check) (*storage.CheckHistory, error)

	// Type returns the check type identifier.
	Type() string
}

// Manager manages different types of monitoring checks.
// It routes check execution to the appropriate checker implementation.
type Manager struct {
	checkers map[string]Checker
	config   *config.Config
}

// NewManager creates a new check manager with all available checkers.
//
// Parameters:
//   - cfg: Application configuration
//
// Returns:
//   - *Manager: Initialized check manager
func NewManager(cfg *config.Config) *Manager {
	manager := &Manager{
		checkers: make(map[string]Checker),
		config:   cfg,
	}

	// Register all available checkers
	manager.registerChecker(NewHTTPChecker(cfg))
	manager.registerChecker(NewPingChecker(cfg))

	return manager
}

// registerChecker registers a checker with the manager.
//
// Parameters:
//   - checker: Checker implementation to register
func (m *Manager) registerChecker(checker Checker) {
	m.checkers[checker.Type()] = checker
	log.Debug().Str("type", checker.Type()).Msg("Checker registered")
}

// ExecuteCheck executes a monitoring check based on the check type.
// It routes the check to the appropriate checker implementation.
//
// Parameters:
//   - ctx: Context for cancellation and timeout
//   - check: Check configuration to execute
//
// Returns:
//   - *storage.CheckHistory: Result of the check
//   - error: Any error that occurred during check execution
func (m *Manager) ExecuteCheck(ctx context.Context, check *storage.Check) (*storage.CheckHistory, error) {
	checker, exists := m.checkers[check.Type]
	if !exists {
		return nil, fmt.Errorf("unsupported check type: %s", check.Type)
	}

	result, err := checker.Check(ctx, check)
	if err != nil {
		log.Error().Int64("check_id", check.ID).Str("type", check.Type).Err(err).Msg("Check failed")
		return result, err
	}

	log.Debug().Int64("check_id", check.ID).Str("type", check.Type).Str("name", check.Name).Str("status", result.Status).Msg("Check completed")
	return result, nil
}

// GetSupportedTypes returns a list of supported check types.
//
// Returns:
//   - []string: List of supported check type identifiers
func (m *Manager) GetSupportedTypes() []string {
	types := make([]string, 0, len(m.checkers))
	for checkType := range m.checkers {
		types = append(types, checkType)
	}
	return types
}
