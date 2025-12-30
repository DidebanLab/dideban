// Package storage provides database migration functionality for Dideban.
//
// The migration system is designed to be:
//   - Version-controlled and reproducible
//   - Rollback capable (future enhancement)
//   - Atomic (each migration runs in a transaction)
//   - Idempotent (safe to run multiple times)
//
// Migration files are embedded in the binary for deployment simplicity.
// Each migration has an up and down SQL script for forward and backward compatibility.
package storage

import (
	"database/sql"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

// Migrator handles database schema migrations.
//
// It tracks applied migrations in a dedicated table and ensures
// migrations are applied in the correct order exactly once.
type Migrator struct {
	// db is the database connection used for migrations
	db *sql.DB

	// migrations holds all registered migrations sorted by version
	migrations []Migration
}

// Migration represents a single database migration.
//
// Each migration has a version number, name, and SQL scripts
// for both forward (up) and backward (down) operations.
type Migration struct {
	// Version is the migration version number (e.g., 1, 2, 3...)
	Version int

	// Name is a human-readable description of the migration
	Name string

	// UpSQL contains the SQL commands to apply the migration
	UpSQL string

	// DownSQL contains the SQL commands to roll back the migration
	// (reserved for future rollback functionality)
	DownSQL string
}

// MigrationRecord represents a migration record in the database.
//
// This is used to track which migrations have been applied
// and when they were executed.
type MigrationRecord struct {
	Version   int       `db:"version"`
	Name      string    `db:"name"`
	AppliedAt time.Time `db:"applied_at"`
}

// NewMigrator creates a new migration manager.
//
// It automatically creates the migrations tracking table if it doesn't exist
// and registers all built-in migrations for Dideban.
func NewMigrator(db *sql.DB) (*Migrator, error) {
	migrator := &Migrator{
		db: db,
	}

	// Create migrations tracking table
	if err := migrator.createMigrationsTable(); err != nil {
		return nil, fmt.Errorf("failed to create migrations table: %w", err)
	}

	// Register built-in migrations
	migrator.registerBuiltinMigrations()

	return migrator, nil
}

// createMigrationsTable creates the table used to track applied migrations.
//
// This table stores metadata about each migration including when it was applied.
// The table is created with IF NOT EXISTS to make it idempotent.
func (m *Migrator) createMigrationsTable() error {
	query := `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version INTEGER PRIMARY KEY,
			name TEXT NOT NULL,
			applied_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)
	`

	_, err := m.db.Exec(query)
	if err != nil {
		return fmt.Errorf("failed to create schema_migrations table: %w", err)
	}

	log.Debug().Msg("Schema migrations table ready")
	return nil
}

// registerBuiltinMigrations registers all the built-in migrations for Dideban.
//
// These migrations create the core tables needed for monitoring functionality:
//   - checks: HTTP/ping monitoring targets
//   - check_history: Historical check execution results
//   - alerts: Alert configuration and state
//   - agents: System monitoring agents
//   - agent_history: System metrics collected by agents
//   - admins: System administrator
func (m *Migrator) registerBuiltinMigrations() {
	// Migration 1: Create checks table
	m.AddMigration(Migration{
		Version: 1,
		Name:    "create_checks_table",
		UpSQL: `
			CREATE TABLE checks (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				enabled BOOLEAN NOT NULL DEFAULT 1,
				name TEXT NOT NULL UNIQUE,
				type TEXT NOT NULL CHECK (type IN ('http', 'ping') AND length(type) <= 10),
				target TEXT NOT NULL,
				interval_seconds INTEGER NOT NULL DEFAULT 60,
				timeout_seconds INTEGER NOT NULL DEFAULT 30,
				created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
				updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
			);
			
			CREATE INDEX idx_checks_type ON checks(type);
			CREATE INDEX idx_checks_enabled ON checks(enabled);
		`,
		DownSQL: `DROP TABLE IF EXISTS checks;`,
	})

	// Migration 2: Create check results table
	m.AddMigration(Migration{
		Version: 2,
		Name:    "create_check_history_table",
		UpSQL: `
			CREATE TABLE check_history (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				check_id INTEGER NOT NULL,
				status TEXT NOT NULL CHECK (status IN ('up', 'down', 'error', 'timeout') AND length(status) <= 10),
				response_time_ms INTEGER,
				status_code INTEGER,
				error_message TEXT,
				checked_at DATETIME DEFAULT CURRENT_TIMESTAMP,
				FOREIGN KEY (check_id) REFERENCES checks(id) ON DELETE CASCADE
			);
			
			CREATE INDEX idx_check_history_check_id ON check_history(check_id);
			CREATE INDEX idx_check_history_checked_at ON check_history(checked_at);
			CREATE INDEX idx_check_history_status ON check_history(status);
		`,
		DownSQL: `DROP TABLE IF EXISTS check_history;`,
	})

	// Migration 3: Create agents table
	m.AddMigration(Migration{
		Version: 3,
		Name:    "create_agents_table",
		UpSQL: `
			CREATE TABLE agents (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				name TEXT NOT NULL UNIQUE,
				enabled BOOLEAN NOT NULL DEFAULT 1,
				interval_seconds INTEGER NOT NULL DEFAULT 60,
				auth_token TEXT NOT NULL UNIQUE,
				created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
				updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
			);
			
			CREATE INDEX idx_agents_enabled ON agents(enabled);
			CREATE INDEX idx_agents_auth_token ON agents(auth_token);
		`,
		DownSQL: `DROP TABLE IF EXISTS agents;`,
	})

	// Migration 4: Create agent metrics table
	m.AddMigration(Migration{
		Version: 4,
		Name:    "create_agent_history_table",
		UpSQL: `
			CREATE TABLE agent_history (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				agent_id INTEGER NOT NULL,
				collect_duration_ms INTEGER NOT NULL,
				status TEXT NOT NULL CHECK (status IN ('online', 'offline') AND length(status) <= 8),
				cpu_load_1 REAL NOT NULL,
				cpu_load_5 REAL NOT NULL,
				cpu_load_15 REAL NOT NULL,
				cpu_usage_percent REAL NOT NULL,
				memory_total_mb INTEGER NOT NULL,
				memory_used_mb INTEGER NOT NULL,
				memory_available_mb INTEGER NOT NULL,
				memory_usage_percent REAL NOT NULL,
				disk_total_gb INTEGER NOT NULL,
				disk_used_gb INTEGER NOT NULL,
				disk_usage_percent REAL NOT NULL,
				collected_at DATETIME DEFAULT CURRENT_TIMESTAMP,
				FOREIGN KEY (agent_id) REFERENCES agents(id) ON DELETE CASCADE
			);
			
			CREATE INDEX idx_agent_history_agent_id ON agent_history(agent_id);
			CREATE INDEX idx_agent_history_collected_at ON agent_history(collected_at);
		`,
		DownSQL: `DROP TABLE IF EXISTS agent_history;`,
	})

	// Migration 5: Create admins table
	m.AddMigration(Migration{
		Version: 5,
		Name:    "create_admins_table",
		UpSQL: `
			CREATE TABLE admins (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				username TEXT NOT NULL UNIQUE,
				password TEXT NOT NULL,
				full_name TEXT NOT NULL
			);
			
			CREATE INDEX idx_admins_username ON admins(username);
		`,
		DownSQL: `DROP TABLE IF EXISTS admins;`,
	})

	// Migration 6: Create alerts table
	m.AddMigration(Migration{
		Version: 6,
		Name:    "create_alerts_table",
		UpSQL: `
			CREATE TABLE alerts (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				check_id INTEGER,
				agent_id INTEGER,
				type TEXT NOT NULL CHECK (type IN ('telegram', 'bale', 'email', 'webhook') AND length(type) <= 20),
				condition_type TEXT NOT NULL,
				condition_value REAL,
				enabled BOOLEAN NOT NULL DEFAULT 1,
				created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
				FOREIGN KEY (check_id) REFERENCES checks(id) ON DELETE CASCADE,
				FOREIGN KEY (agent_id) REFERENCES agents(id) ON DELETE CASCADE
			);
			
			CREATE INDEX idx_alerts_check_id ON alerts(check_id);
			CREATE INDEX idx_alerts_agent_id ON alerts(agent_id);
			CREATE INDEX idx_alerts_type ON alerts(type);
			CREATE INDEX idx_alerts_enabled ON alerts(enabled);
		`,
		DownSQL: `DROP TABLE IF EXISTS alerts;`,
	})

	// Migration 7: Create alert history table
	m.AddMigration(Migration{
		Version: 7,
		Name:    "create_alert_history_table",
		UpSQL: `
			CREATE TABLE alert_history (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				alert_id INTEGER NOT NULL,
				check_result_id INTEGER,
				agent_metric_id INTEGER,
				title TEXT NOT NULL,
				message TEXT NOT NULL,
				status TEXT NOT NULL CHECK (status IN ('sent', 'failed', 'pending') AND length(status) <= 20),
				sent_at DATETIME NOT NULL,
				created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
				FOREIGN KEY (alert_id) REFERENCES alerts(id) ON DELETE CASCADE
			);
			
			CREATE INDEX idx_alert_history_alert_id ON alert_history(alert_id);
			CREATE INDEX idx_alert_history_check_result_id ON alert_history(check_result_id);
			CREATE INDEX idx_alert_history_agent_metric_id ON alert_history(agent_metric_id);
			CREATE INDEX idx_alert_history_status ON alert_history(status);
			CREATE INDEX idx_alert_history_sent_at ON alert_history(sent_at);
		`,
		DownSQL: `DROP TABLE IF EXISTS alert_history;`,
	})

	log.Debug().Int("count", len(m.migrations)).Msg("Built-in migrations registered")
}

// AddMigration registers a new migration.
//
// Migrations are automatically sorted by version number to ensure
// they are applied in the correct order.
func (m *Migrator) AddMigration(migration Migration) {
	m.migrations = append(m.migrations, migration)

	// Sort migrations by version to ensure correct order
	sort.Slice(m.migrations, func(i, j int) bool {
		return m.migrations[i].Version < m.migrations[j].Version
	})
}

// Migrate applies all pending migrations to the database.
//
// This method is idempotent - it only applies migrations that haven't
// been applied yet. Each migration runs in its own transaction for atomicity.
//
// Returns the number of migrations applied and any error encountered.
func (m *Migrator) Migrate() (int, error) {
	// Get list of applied migrations
	appliedVersions, err := m.getAppliedVersions()
	if err != nil {
		return 0, fmt.Errorf("failed to get applied migrations: %w", err)
	}

	appliedCount := 0

	// Apply pending migrations
	for _, migration := range m.migrations {
		if m.isMigrationApplied(migration.Version, appliedVersions) {
			log.Debug().
				Int("version", migration.Version).
				Str("name", migration.Name).
				Msg("Migration already applied, skipping")
			continue
		}

		log.Info().
			Int("version", migration.Version).
			Str("name", migration.Name).
			Msg("Applying migration")

		if err := m.applyMigration(migration); err != nil {
			return appliedCount, fmt.Errorf("failed to apply migration %d (%s): %w",
				migration.Version, migration.Name, err)
		}

		appliedCount++

		log.Info().
			Int("version", migration.Version).
			Str("name", migration.Name).
			Msg("Migration applied successfully")
	}

	if appliedCount > 0 {
		log.Info().Int("count", appliedCount).Msg("Database migrations completed")
	} else {
		log.Debug().Msg("No pending migrations")
	}

	return appliedCount, nil
}

// getAppliedVersions retrieves the list of migration versions that have been applied.
//
// This is used to determine which migrations are pending and need to be applied.
func (m *Migrator) getAppliedVersions() ([]int, error) {
	query := "SELECT version FROM schema_migrations ORDER BY version"

	rows, err := m.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query applied migrations: %w", err)
	}
	defer rows.Close()

	var versions []int
	for rows.Next() {
		var version int
		if err := rows.Scan(&version); err != nil {
			return nil, fmt.Errorf("failed to scan migration version: %w", err)
		}
		versions = append(versions, version)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating migration rows: %w", err)
	}

	return versions, nil
}

// isMigrationApplied checks if a migration version has already been applied.
func (m *Migrator) isMigrationApplied(version int, appliedVersions []int) bool {
	for _, applied := range appliedVersions {
		if applied == version {
			return true
		}
	}
	return false
}

// applyMigration applies a single migration within a database transaction.
//
// If any part of the migration fails, the entire transaction is rolled back
// to maintain database consistency.
func (m *Migrator) applyMigration(migration Migration) error {
	// Start transaction for atomic migration
	tx, err := m.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to start transaction: %w", err)
	}
	defer tx.Rollback() // Will be ignored if tx.Commit() succeeds

	// Execute migration SQL
	// Split by semicolon to handle multiple statements
	statements := m.splitSQL(migration.UpSQL)
	for i, stmt := range statements {
		stmt = strings.TrimSpace(stmt)
		if stmt == "" {
			continue
		}

		log.Debug().
			Int("version", migration.Version).
			Int("statement", i+1).
			Str("sql", stmt).
			Msg("Executing migration statement")

		if _, err := tx.Exec(stmt); err != nil {
			return fmt.Errorf("failed to execute statement %d: %w", i+1, err)
		}
	}

	// Record migration as applied
	recordQuery := `
		INSERT INTO schema_migrations (version, name, applied_at) 
		VALUES (?, ?, CURRENT_TIMESTAMP)
	`
	if _, err := tx.Exec(recordQuery, migration.Version, migration.Name); err != nil {
		return fmt.Errorf("failed to record migration: %w", err)
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit migration transaction: %w", err)
	}

	return nil
}

// splitSQL splits a SQL script into individual statements.
//
// This is a simple implementation that splits on semicolons.
// A more robust implementation might handle SQL comments and string literals.
func (m *Migrator) splitSQL(sql string) []string {
	statements := strings.Split(sql, ";")

	// Filter out empty statements
	var result []string
	for _, stmt := range statements {
		stmt = strings.TrimSpace(stmt)
		if stmt != "" {
			result = append(result, stmt)
		}
	}

	return result
}

// GetMigrationStatus returns information about migration status.
//
// This can be used for debugging or administrative purposes to see
// which migrations have been applied and when.
func (m *Migrator) GetMigrationStatus() ([]MigrationRecord, error) {
	query := `
		SELECT version, name, applied_at 
		FROM schema_migrations 
		ORDER BY version
	`

	rows, err := m.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query migration status: %w", err)
	}
	defer rows.Close()

	var records []MigrationRecord
	for rows.Next() {
		var record MigrationRecord
		if err := rows.Scan(&record.Version, &record.Name, &record.AppliedAt); err != nil {
			return nil, fmt.Errorf("failed to scan migration record: %w", err)
		}
		records = append(records, record)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating migration records: %w", err)
	}

	return records, nil
}

// GetPendingMigrations returns a list of migrations that haven't been applied yet.
//
// This is useful for showing administrators what changes will be made
// before running migrations.
func (m *Migrator) GetPendingMigrations() ([]Migration, error) {
	appliedVersions, err := m.getAppliedVersions()
	if err != nil {
		return nil, fmt.Errorf("failed to get applied migrations: %w", err)
	}

	var pending []Migration
	for _, migration := range m.migrations {
		if !m.isMigrationApplied(migration.Version, appliedVersions) {
			pending = append(pending, migration)
		}
	}

	return pending, nil
}
