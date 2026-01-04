package config

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"path/filepath"

	"github.com/spf13/viper"
)

// Config represents the complete configuration schema for the Dideban monitoring system.
//
// Configuration sources (in order of precedence):
//  1. Defaults
//  2. Configuration file (optional)
//  3. Environment variables
type Config struct {
	Server    ServerConfig    `mapstructure:"server" yaml:"server"`
	Storage   StorageConfig   `mapstructure:"storage" yaml:"storage"`
	Alert     AlertConfig     `mapstructure:"alert" yaml:"alert"`
	Scheduler SchedulerConfig `mapstructure:"scheduler" yaml:"scheduler"`
	Checks    ChecksConfig    `mapstructure:"checks" yaml:"checks"`
	Log       LogConfig       `mapstructure:"log" yaml:"log"`
}

type ServerConfig struct {
	Addr         string        `mapstructure:"addr" yaml:"addr"`
	ReadTimeout  time.Duration `mapstructure:"read_timeout" yaml:"read_timeout"`
	WriteTimeout time.Duration `mapstructure:"write_timeout" yaml:"write_timeout"`
	IdleTimeout  time.Duration `mapstructure:"idle_timeout" yaml:"idle_timeout"`
	EnableCORS   bool          `mapstructure:"enable_cors" yaml:"enable_cors"`
}

type StorageConfig struct {
	Path            string        `mapstructure:"path" yaml:"path"`
	MaxOpenConns    int           `mapstructure:"max_open_conns" yaml:"max_open_conns"`
	MaxIdleConns    int           `mapstructure:"max_idle_conns" yaml:"max_idle_conns"`
	ConnMaxLifetime time.Duration `mapstructure:"conn_max_lifetime" yaml:"conn_max_lifetime"`
}

type AlertConfig struct {
	Telegram BotConfig `mapstructure:"telegram" yaml:"telegram"`
	Bale     BotConfig `mapstructure:"bale" yaml:"bale"`
}

type BotConfig struct {
	Enabled bool          `mapstructure:"enabled" yaml:"enabled"`
	Token   string        `mapstructure:"token" yaml:"token"`
	ChatID  string        `mapstructure:"chat_id" yaml:"chat_id"`
	Timeout time.Duration `mapstructure:"timeout" yaml:"timeout"`
}

type SchedulerConfig struct {
	WorkerCount     int           `mapstructure:"worker_count" yaml:"worker_count"`
	DefaultInterval time.Duration `mapstructure:"default_interval" yaml:"default_interval"`
	MaxRetries      int           `mapstructure:"max_retries" yaml:"max_retries"`
}

type ChecksConfig struct {
	HTTP HTTPDefaultsConfig `mapstructure:"http" yaml:"http"`
	Ping PingDefaultsConfig `mapstructure:"ping" yaml:"ping"`
}

type HTTPDefaultsConfig struct {
	Method          string            `mapstructure:"method" yaml:"method"`
	Headers         map[string]string `mapstructure:"headers" yaml:"headers"`
	Body            string            `mapstructure:"body" yaml:"body"`
	TimeoutSeconds  int               `mapstructure:"timeout_seconds" yaml:"timeout_seconds"`
	ExpectedStatus  int               `mapstructure:"expected_status" yaml:"expected_status"`
	ExpectedContent string            `mapstructure:"expected_content" yaml:"expected_content"`
	FollowRedirects bool              `mapstructure:"follow_redirects" yaml:"follow_redirects"`
	VerifySSL       bool              `mapstructure:"verify_ssl" yaml:"verify_ssl"`
}

type PingDefaultsConfig struct {
	Count          int `mapstructure:"count" yaml:"count"`
	IntervalMs     int `mapstructure:"interval_ms" yaml:"interval_ms"`
	PacketSize     int `mapstructure:"packet_size" yaml:"packet_size"`
	TimeoutSeconds int `mapstructure:"timeout_seconds" yaml:"timeout_seconds"`
}

type LogConfig struct {
	Level  string `mapstructure:"level" yaml:"level"`   // debug, info, warn, error, fatal, panic
	Pretty bool   `mapstructure:"pretty" yaml:"pretty"` // human-readable console output
}

// Load loads configuration from defaults, configuration file,
// and environment variables, then validates the result.
//
// The function fails fast on:
//   - Invalid configuration file
//   - Invalid or missing required configuration values
func Load() (*Config, error) {
	v := viper.New()

	// Register default values
	setDefaults(v)

	// Environment variable support
	v.SetEnvPrefix("DIDEBAN")
	v.AutomaticEnv()
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	// Optional configuration file
	v.SetConfigName("config")
	v.SetConfigType("yaml")
	v.AddConfigPath(".")

	// Cross-platform config directory
	if configDir := getConfigDir(); configDir != "" {
		v.AddConfigPath(configDir)
	}

	// Read configuration file if present
	if err := v.ReadInConfig(); err != nil {
		var notFound viper.ConfigFileNotFoundError
		if !errors.As(err, &notFound) {
			return nil, fmt.Errorf("config file error: %w", err)
		}
	}

	// Unmarshal configuration into struct
	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// Normalize configuration
	normalizeConfig(&cfg)

	// Validate final configuration
	if err := validateConfig(&cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// getConfigDir returns the appropriate config directory for the current OS
func getConfigDir() string {
	if runtime.GOOS == "windows" {
		if appData := os.Getenv("APPDATA"); appData != "" {
			return filepath.Join(appData, "dideban")
		}
		return ""
	}

	if home := os.Getenv("HOME"); home != "" {
		return filepath.Join(home, ".dideban")
	}
	return ""
}
