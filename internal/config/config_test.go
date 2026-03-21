package config

import (
	"os"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.SMP.Address != ":5223" {
		t.Errorf("default SMP address = %q, want :5223", cfg.SMP.Address)
	}
	if cfg.GRP.Address != ":7443" {
		t.Errorf("default GRP address = %q, want :7443", cfg.GRP.Address)
	}
	if cfg.Server.Hostname != "localhost" {
		t.Errorf("default hostname = %q, want localhost", cfg.Server.Hostname)
	}
	if cfg.Server.DataDir != "./data" {
		t.Errorf("default data dir = %q, want ./data", cfg.Server.DataDir)
	}
	if cfg.Store.Path != "./data/store" {
		t.Errorf("default store path = %q, want ./data/store", cfg.Store.Path)
	}
}

func TestLoadWithOverrides_CLIFlags(t *testing.T) {
	o := Overrides{
		Host:    "relay.example.com",
		SMPPort: "15223",
		GRPPort: "17443",
		DataDir: "/tmp/gorelay",
	}
	cfg, err := LoadWithOverrides(o)
	if err != nil {
		t.Fatalf("LoadWithOverrides: %v", err)
	}

	if cfg.Server.Hostname != "relay.example.com" {
		t.Errorf("hostname = %q, want relay.example.com", cfg.Server.Hostname)
	}
	if cfg.SMP.Address != ":15223" {
		t.Errorf("SMP address = %q, want :15223", cfg.SMP.Address)
	}
	if cfg.GRP.Address != ":17443" {
		t.Errorf("GRP address = %q, want :17443", cfg.GRP.Address)
	}
	if cfg.Server.DataDir != "/tmp/gorelay" {
		t.Errorf("data dir = %q, want /tmp/gorelay", cfg.Server.DataDir)
	}
	if cfg.Store.Path != "/tmp/gorelay/store" {
		t.Errorf("store path = %q, want /tmp/gorelay/store", cfg.Store.Path)
	}
}

func TestLoadWithOverrides_EnvVars(t *testing.T) {
	t.Setenv("GORELAY_SMP_PORT", "25223")
	t.Setenv("GORELAY_GRP_PORT", "27443")

	cfg, err := LoadWithOverrides(Overrides{})
	if err != nil {
		t.Fatalf("LoadWithOverrides: %v", err)
	}

	if cfg.SMP.Address != ":25223" {
		t.Errorf("SMP address = %q, want :25223", cfg.SMP.Address)
	}
	if cfg.GRP.Address != ":27443" {
		t.Errorf("GRP address = %q, want :27443", cfg.GRP.Address)
	}
}

func TestLoadWithOverrides_CLIOverridesEnv(t *testing.T) {
	t.Setenv("GORELAY_SMP_PORT", "25223")

	cfg, err := LoadWithOverrides(Overrides{SMPPort: "35223"})
	if err != nil {
		t.Fatalf("LoadWithOverrides: %v", err)
	}

	if cfg.SMP.Address != ":35223" {
		t.Errorf("SMP address = %q, want :35223 (CLI should override env)", cfg.SMP.Address)
	}
}

func TestLoadWithOverrides_InvalidPort(t *testing.T) {
	tests := []struct {
		name string
		o    Overrides
		env  map[string]string
	}{
		{"CLI non-numeric", Overrides{SMPPort: "abc"}, nil},
		{"CLI port zero", Overrides{SMPPort: "0"}, nil},
		{"CLI port too high", Overrides{GRPPort: "99999"}, nil},
		{"env non-numeric", Overrides{}, map[string]string{"GORELAY_SMP_PORT": "xyz"}},
		{"env port too high", Overrides{}, map[string]string{"GORELAY_GRP_PORT": "70000"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Clean env
			os.Unsetenv("GORELAY_SMP_PORT")
			os.Unsetenv("GORELAY_GRP_PORT")
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			_, err := LoadWithOverrides(tc.o)
			if err == nil {
				t.Error("expected error for invalid port, got nil")
			}
		})
	}
}

func TestLoadWithOverrides_PartialOverrides(t *testing.T) {
	// Only override SMP port, rest should be defaults
	cfg, err := LoadWithOverrides(Overrides{SMPPort: "9999"})
	if err != nil {
		t.Fatalf("LoadWithOverrides: %v", err)
	}

	if cfg.SMP.Address != ":9999" {
		t.Errorf("SMP address = %q, want :9999", cfg.SMP.Address)
	}
	if cfg.GRP.Address != ":7443" {
		t.Errorf("GRP address = %q, want :7443 (should be default)", cfg.GRP.Address)
	}
	if cfg.Server.Hostname != "localhost" {
		t.Errorf("hostname = %q, want localhost (should be default)", cfg.Server.Hostname)
	}
}

func TestLoad_ReturnsDefaults(t *testing.T) {
	// Ensure env is clean
	os.Unsetenv("GORELAY_SMP_PORT")
	os.Unsetenv("GORELAY_GRP_PORT")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.SMP.Address != ":5223" {
		t.Errorf("SMP address = %q, want :5223", cfg.SMP.Address)
	}
	if cfg.GRP.Address != ":7443" {
		t.Errorf("GRP address = %q, want :7443", cfg.GRP.Address)
	}
}
