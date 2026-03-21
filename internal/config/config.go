package config

import (
	"fmt"
	"os"
	"strconv"
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

// Overrides holds CLI flag values that override defaults and env vars.
// Empty string means "not set" (use env or default).
type Overrides struct {
	Host    string
	SMPPort string
	GRPPort string
	DataDir string
}

// Load returns the server configuration with env var defaults.
// TODO: implement koanf-based config loading from YAML file
func Load() (*Config, error) {
	return LoadWithOverrides(Overrides{})
}

// LoadWithOverrides returns config applying: defaults < env vars < overrides.
func LoadWithOverrides(o Overrides) (*Config, error) {
	cfg := DefaultConfig()

	// Apply env vars
	if v := os.Getenv("GORELAY_SMP_PORT"); v != "" {
		port, err := parsePort(v, "GORELAY_SMP_PORT")
		if err != nil {
			return nil, err
		}
		cfg.SMP.Address = fmt.Sprintf(":%d", port)
	}
	if v := os.Getenv("GORELAY_GRP_PORT"); v != "" {
		port, err := parsePort(v, "GORELAY_GRP_PORT")
		if err != nil {
			return nil, err
		}
		cfg.GRP.Address = fmt.Sprintf(":%d", port)
	}

	// Apply CLI overrides (highest precedence)
	if o.Host != "" {
		cfg.Server.Hostname = o.Host
	}
	if o.SMPPort != "" {
		port, err := parsePort(o.SMPPort, "--smp-port")
		if err != nil {
			return nil, err
		}
		cfg.SMP.Address = fmt.Sprintf(":%d", port)
	}
	if o.GRPPort != "" {
		port, err := parsePort(o.GRPPort, "--grp-port")
		if err != nil {
			return nil, err
		}
		cfg.GRP.Address = fmt.Sprintf(":%d", port)
	}
	if o.DataDir != "" {
		cfg.Server.DataDir = o.DataDir
		cfg.Store.Path = o.DataDir + "/store"
	}

	return cfg, nil
}

// parsePort validates a port string and returns the port number.
func parsePort(s string, source string) (int, error) {
	port, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("invalid port for %s: %q", source, s)
	}
	if port < 1 || port > 65535 {
		return 0, fmt.Errorf("port out of range for %s: %d", source, port)
	}
	return port, nil
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
