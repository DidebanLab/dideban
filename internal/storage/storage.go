// Package storage provides database functionality for the Dideban monitoring system.
//
// This package implements a lightweight, high-performance mini-ORM specifically
// designed for monitoring systems. It provides SQLite-based storage with:
//   - Type-safe query building
//   - Automatic migrations
//   - Minimal memory footprint
//   - Zero reflection overhead during queries
package storage

import (
	"fmt"

	"database/sql"

	"dideban/internal/config"

	_ "github.com/mattn/go-sqlite3"
	"github.com/rs/zerolog/log"
)

// Storage represents the database storage layer.
//
// It wraps the SQL database connection and provides both direct SQL access
// and a high-level ORM interface for type-safe operations.
type Storage struct {
	// db is the underlying SQLite database connection
	db *sql.DB

	// orm provides the ORM interface for type-safe queries
	orm *ORM

	// repositories provides high-level business logic operations
	repositories *Repositories
}

// New creates a new Storage instance with the given configuration.
//
// The initialization process includes:
//  1. Opening SQLite database connection with optimized settings
//  2. Configuring connection pool parameters
//  3. Testing database connectivity
//  4. Initializing the ORM layer
//  5. Running database migrations
//
// SQLite is configured with:
//   - WAL mode for better concurrency
//   - NORMAL synchronous mode for performance
//   - Foreign key constraints enabled
//   - Optimized cache size
//
// Parameters:
//   - cfg: Storage configuration containing database path and connection settings
//
// Returns:
//   - *Storage: Initialized storage instance with ORM ready
//   - error: Any error that occurred during initialization
func New(cfg config.StorageConfig) (*Storage, error) {
	// Open SQLite database with performance optimizations
	// DSN (Data Source Name)
	dsn := fmt.Sprintf("%s?_journal_mode=WAL&_synchronous=NORMAL&_cache_size=1000&_foreign_keys=ON", cfg.Path)
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Configure connection pool for optimal performance
	db.SetMaxOpenConns(cfg.MaxOpenConns)
	db.SetMaxIdleConns(cfg.MaxIdleConns)
	db.SetConnMaxLifetime(cfg.ConnMaxLifetime)

	// Test database connectivity
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	// Initialize ORM layer
	orm, err := NewORM(db)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to initialize ORM: %w", err)
	}

	storage := &Storage{
		db:           db,
		orm:          orm,
		repositories: NewRepositories(orm),
	}

	// Run database migrations
	migrationsApplied, err := orm.migrator.Migrate()
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to run migrations: %w", err)
	}

	if migrationsApplied > 0 {
		log.Info().
			Int("applied", migrationsApplied).
			Str("database", cfg.Path).
			Msg("Database migrations completed")
	} else {
		log.Debug().
			Str("database", cfg.Path).
			Msg("Database schema up to date")
	}

	return storage, nil
}

// ORM returns the ORM instance for type-safe database operations.
//
// The ORM provides a fluent interface for building and executing queries
// with compile-time type safety and zero reflection overhead.
func (s *Storage) ORM() *ORM {
	return s.orm
}

// Repositories returns the repository container for high-level operations.
//
// Repositories provide business logic operations on top of the ORM,
// including validation, complex queries, and data consistency management.
func (s *Storage) Repositories() *Repositories {
	return s.repositories
}

// DB returns the underlying database connection for direct SQL operations.
//
// This should be used sparingly, only when the ORM doesn't provide
// the required functionality (e.g., complex joins, raw SQL, transactions).
func (s *Storage) DB() *sql.DB {
	return s.db
}

// Close closes the database connection and cleans up resources.
//
// This should be called when the storage is no longer needed,
// typically during application shutdown.
//
// Returns:
//   - error: Any error that occurred during closing
func (s *Storage) Close() error {
	log.Debug().Msg("Closing database connection")
	return s.db.Close()
}

// GetMigrationStatus returns information about applied migrations.
//
// This is useful for debugging and administrative purposes to see
// which database schema version is currently active.
//
// Returns:
//   - []MigrationRecord: List of applied migrations with timestamps
//   - error: Any error that occurred during retrieval
func (s *Storage) GetMigrationStatus() ([]MigrationRecord, error) {
	return s.orm.migrator.GetMigrationStatus()
}

// GetPendingMigrations returns migrations that haven't been applied yet.
//
// This can be used to preview what changes will be made before
// running migrations in production environments.
//
// Returns:
//   - []Migration: List of pending migrations
//   - error: Any error that occurred during retrieval
func (s *Storage) GetPendingMigrations() ([]Migration, error) {
	return s.orm.migrator.GetPendingMigrations()
}
