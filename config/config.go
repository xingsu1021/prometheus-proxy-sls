package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config represents the application configuration
type Config struct {
	Server     ServerConfig     `yaml:"server"`
	SLS        SLSConfig        `yaml:"sls"`
	RemoteRead RemoteReadConfig `yaml:"remote_read"`
	Health     HealthConfig     `yaml:"health"`
	TLS        TLSConfig        `yaml:"tls"`
	Logging    LoggingConfig    `yaml:"logging"`
}

// ServerConfig holds the HTTP server configuration
type ServerConfig struct {
	Host         string        `yaml:"host"`
	Port         int           `yaml:"port"`
	ReadTimeout  time.Duration `yaml:"read_timeout"`
	WriteTimeout time.Duration `yaml:"write_timeout"`
	IdleTimeout  time.Duration `yaml:"idle_timeout"`
}

// SLSConfig holds the Alibaba Cloud SLS configuration
type SLSConfig struct {
	Endpoint         string `yaml:"endpoint"`
	AccessKeyID      string `yaml:"access_key_id"`
	AccessKeySecret  string `yaml:"access_key_secret"`
	SecurityToken    string `yaml:"security_token"`
	Project          string `yaml:"project"`
	Logstore         string `yaml:"logstore"`
	Query            string `yaml:"query"`
	MaxResults       int    `yaml:"max_results"`
	EnablePagination bool   `yaml:"enable_pagination"`
}

// RemoteReadConfig holds the Prometheus Remote Read configuration
type RemoteReadConfig struct {
	ConcurrentRequests int           `yaml:"concurrent_requests"`
	QueryTimeout       time.Duration `yaml:"query_timeout"`
	PartialResponse    bool          `yaml:"partial_response"`
	MaxSamples         int           `yaml:"max_samples"`
}

// HealthConfig holds the health check configuration
type HealthConfig struct {
	SampleQuery     string        `yaml:"sample_query"`
	SampleTimeRange time.Duration `yaml:"sample_time_range"`
}

// TLSConfig holds the TLS configuration
type TLSConfig struct {
	Enabled  bool   `yaml:"enabled"`
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

// LoggingConfig holds the logging configuration
type LoggingConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}

// Load loads configuration from a YAML file
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	// Apply environment variable overrides
	applyEnvOverrides(&cfg)

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	return &cfg, nil
}

// applyEnvOverrides applies environment variable overrides to the configuration
func applyEnvOverrides(cfg *Config) {
	// SLS configuration overrides
	if v := os.Getenv("SLS_ENDPOINT"); v != "" {
		cfg.SLS.Endpoint = v
	}
	if v := os.Getenv("SLS_ACCESS_KEY_ID"); v != "" {
		cfg.SLS.AccessKeyID = v
	}
	if v := os.Getenv("SLS_ACCESS_KEY_SECRET"); v != "" {
		cfg.SLS.AccessKeySecret = v
	}
	if v := os.Getenv("SLS_SECURITY_TOKEN"); v != "" {
		cfg.SLS.SecurityToken = v
	}
	if v := os.Getenv("SLS_PROJECT"); v != "" {
		cfg.SLS.Project = v
	}
	if v := os.Getenv("SLS_LOGSTORE"); v != "" {
		cfg.SLS.Logstore = v
	}

	// Server configuration overrides
	if v := os.Getenv("SERVER_HOST"); v != "" {
		cfg.Server.Host = v
	}
	if v := os.Getenv("SERVER_PORT"); v != "" {
		fmt.Sscanf(v, "%d", &cfg.Server.Port)
	}
}

// Validate validates the configuration
func (c *Config) Validate() error {
	if c.Server.Port <= 0 || c.Server.Port > 65535 {
		return fmt.Errorf("invalid server port: %d", c.Server.Port)
	}

	if c.SLS.Endpoint == "" {
		return fmt.Errorf("SLS endpoint is required")
	}

	if c.SLS.Project == "" {
		return fmt.Errorf("SLS project is required")
	}

	if c.SLS.Logstore == "" {
		return fmt.Errorf("SLS logstore is required")
	}

	if c.RemoteRead.ConcurrentRequests <= 0 {
		c.RemoteRead.ConcurrentRequests = 5
	}

	if c.RemoteRead.MaxSamples <= 0 {
		c.RemoteRead.MaxSamples = 1000000
	}

	if c.RemoteRead.QueryTimeout <= 0 {
		c.RemoteRead.QueryTimeout = 180 * time.Second
	}

	// Set default server timeouts
	if c.Server.ReadTimeout <= 0 {
		c.Server.ReadTimeout = 300 * time.Second
	}
	if c.Server.WriteTimeout <= 0 {
		c.Server.WriteTimeout = 300 * time.Second
	}
	if c.Server.IdleTimeout <= 0 {
		c.Server.IdleTimeout = 120 * time.Second
	}

	// Set default health config
	if c.Health.SampleTimeRange <= 0 {
		c.Health.SampleTimeRange = 24 * time.Hour
	}
	if c.Health.SampleQuery == "" {
		c.Health.SampleQuery = "*"
	}

	// Set default logging config
	if c.Logging.Level == "" {
		c.Logging.Level = "debug"
	}

	return nil
}

// GetAddress returns the server address in host:port format
func (c *ServerConfig) GetAddress() string {
	return fmt.Sprintf("%s:%d", c.Host, c.Port)
}
