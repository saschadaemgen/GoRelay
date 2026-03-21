package config

import (
	"time"
)

// Config holds all GoRelay configuration
type Config struct {
	Server  ServerConfig
	SMP     SMPConfig
	GRP     GRPConfig
	Store   StoreConfig
	Limits  LimitsConfig
	Metrics MetricsConfig
}

// ServerConfig holds general server settings
type ServerConfig struct {
	Hostname string
	DataDir  string
}

// SMPConfig holds SMP listener settings
type SMPConfig struct {
	Enabled bool
	Address string
	TLS     TLSConfig
}

// TLSConfig holds TLS certificate paths
type TLSConfig struct {
	CertFile string
	KeyFile  string
	CAFile   string
}

// GRPConfig holds GRP listener settings
type GRPConfig struct {
	Enabled bool
	Address string
}

// StoreConfig holds queue store settings
type StoreConfig struct {
	Path       string
	DefaultTTL time.Duration
	MaxTTL     time.Duration
}

// LimitsConfig holds connection and rate limit settings
type LimitsConfig struct {
	MaxConnections      int
	CommandsPerSecond   float64
	CommandsBurst       int
	HandshakeTimeout    time.Duration
	ReadTimeout         time.Duration
	WriteTimeout        time.Duration
}

// MetricsConfig holds Prometheus metrics settings
type MetricsConfig struct {
	Enabled bool
	Address string
}

// Load returns the server configuration
// TODO: implement koanf-based config loading from YAML file
func Load() (*Config, error) {
	return DefaultConfig(), nil
}

// DefaultConfig returns sensible defaults for development
func DefaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			Hostname: "localhost",
			DataDir:  "./data",
		},
		SMP: SMPConfig{
			Enabled: true,
			Address: ":5223",
		},
		GRP: GRPConfig{
			Enabled: true,
			Address: ":7443",
		},
		Store: StoreConfig{
			Path:       "./data/store",
			DefaultTTL: 48 * time.Hour,
			MaxTTL:     7 * 24 * time.Hour,
		},
		Limits: LimitsConfig{
			MaxConnections:    10000,
			CommandsPerSecond: 50,
			CommandsBurst:     100,
			HandshakeTimeout:  30 * time.Second,
			ReadTimeout:       5 * time.Minute,
			WriteTimeout:      10 * time.Second,
		},
		Metrics: MetricsConfig{
			Enabled: true,
			Address: "127.0.0.1:9090",
		},
	}
}
