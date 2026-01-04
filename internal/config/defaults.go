package config

import "github.com/spf13/viper"

// setDefaults sets default configuration values.
func setDefaults(v *viper.Viper) {
	// Server defaults
	v.SetDefault("server.addr", ":8080")
	v.SetDefault("server.read_timeout", "30s")
	v.SetDefault("server.write_timeout", "30s")
	v.SetDefault("server.idle_timeout", "60s")
	v.SetDefault("server.enable_cors", false)

	// Storage defaults
	v.SetDefault("storage.path", "dideban.db")
	v.SetDefault("storage.max_open_conns", 32)
	v.SetDefault("storage.max_idle_conns", 8)
	v.SetDefault("storage.conn_max_lifetime", "1h")

	// Alert defaults
	v.SetDefault("alert.telegram.enabled", false)
	v.SetDefault("alert.telegram.timeout", "30s")
	v.SetDefault("alert.bale.enabled", false)
	v.SetDefault("alert.bale.timeout", "30s")

	// Scheduler defaults
	v.SetDefault("scheduler.worker_count", 8)
	v.SetDefault("scheduler.default_interval", "60s")
	v.SetDefault("scheduler.max_retries", 3)

	// Checks defaults
	v.SetDefault("checks.http.method", "GET")
	v.SetDefault("checks.http.headers", map[string]string{})
	v.SetDefault("checks.http.body", "")
	v.SetDefault("checks.http.timeout_seconds", 10)
	v.SetDefault("checks.http.expected_status", 200)
	v.SetDefault("checks.http.expected_content", "")
	v.SetDefault("checks.http.follow_redirects", true)
	v.SetDefault("checks.http.verify_ssl", true)
	v.SetDefault("checks.ping.count", 3)
	v.SetDefault("checks.ping.interval_ms", 1000)
	v.SetDefault("checks.ping.packet_size", 56)
	v.SetDefault("checks.ping.timeout_seconds", 5)

	// Log defaults
	v.SetDefault("log.level", "info")
	v.SetDefault("log.pretty", false)
}
