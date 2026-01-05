// Package server provides the main server orchestration for the Dideban monitoring system.
//
// This package coordinates the startup and shutdown of all core components:
//   - SQLite storage initialization
//   - Monitoring engine startup
//   - HTTP API server management
//   - Graceful shutdown handling
//
// The server follows a structured lifecycle:
//  1. Storage initialization
//  2. Core engine startup
//  3. HTTP API server launch
//  4. Signal handling and graceful shutdown
package server

import (
	"context"
	"fmt"
	"time"

	"dideban/internal/config"
	"dideban/internal/core"
	"dideban/internal/storage"

	"github.com/rs/zerolog/log"
)

// Server represents the main Dideban server orchestrator.
//
// It manages the lifecycle of all core components including:
//   - Database storage
//   - Monitoring engine
//   - HTTP API server
//
// The server ensures proper initialization order and handles
// graceful shutdown of all components.
type Server struct {
	// cfg holds the application configuration
	cfg *config.Config
}

// New creates a new server instance with the provided configuration.
//
// The server is not started until Start() is called.
// This allows for proper dependency injection and testing.
func New(cfg *config.Config) *Server {
	return &Server{
		cfg: cfg,
	}
}

// Start initializes and starts all server components in the correct order.
//
// The startup sequence is carefully orchestrated:
//  1. SQLite storage initialization and migration
//  2. Core monitoring engine startup (scheduler, checks, alerts)
//  3. HTTP API server launch (Gin router with embedded UI)
//  4. Graceful shutdown handling on context cancellation
//
// This method blocks until:
//   - A fatal error occurs during startup
//   - The provided context is cancelled (shutdown signal)
//   - The HTTP server encounters an unrecoverable error
//
// Returns an error if any component fails to start or stop gracefully.
func (s *Server) Start(ctx context.Context) error {
	// Phase 1: Initialize SQLite storage
	// This must happen first as all other components depend on it
	db, err := storage.New(s.cfg.Storage)
	if err != nil {
		return fmt.Errorf("failed to initialize storage: %w", err)
	}
	defer func() {
		if closeErr := db.Close(); closeErr != nil {
			log.Error().Err(closeErr).Msg("Failed to close database connection")
		}
	}()

	log.Info().Str("path", s.cfg.Storage.Path).Msg("📦 Storage initialized")

	// Phase 2: Initialize core monitoring engine
	// The engine manages schedulers, health checks, and alert dispatchers
	engine, err := core.NewEngine(s.cfg, db)
	if err != nil {
		return fmt.Errorf("failed to initialize engine: %w", err)
	}

	// Start the monitoring engine (non-blocking)
	if err := engine.Start(ctx); err != nil {
		return fmt.Errorf("failed to start engine: %w", err)
	}
	defer func() {
		engine.Stop()
	}()

	log.Info().Msg("⚙️ Monitoring engine started")

	// Phase 3: Initialize HTTP API server
	// This serves both the REST API and embedded Svelte UI

	// Start HTTP server in a separate goroutine to avoid blocking
	// We use a buffered channel to prevent goroutine leaks
	serverErrors := make(chan error, 1)
	go func() {
		log.Info().Str("addr", s.cfg.Server.Addr).Msg("🌐 Starting HTTP server")
		// ...
	}()

	// Phase 4: Wait for shutdown signal or server error
	// This is the main event loop - we block here until something happens
	select {
	case err := <-serverErrors:
		// HTTP server encountered a fatal error
		return fmt.Errorf("server error: %w", err)
	case <-ctx.Done():
		// Graceful shutdown requested (SIGINT, SIGTERM, etc.)
		log.Info().Msg("Shutdown signal received, starting graceful shutdown")
	}

	// Phase 5: Graceful shutdown sequence
	// Give components up to 30 seconds to shut down cleanly
	_, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Shutdown HTTP server first to stop accepting new requests
	// TODO : ...

	log.Info().Msg("Server stopped gracefully")
	return nil
}
