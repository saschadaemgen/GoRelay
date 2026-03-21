package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/saschadaemgen/GoRelay/internal/config"
	"github.com/saschadaemgen/GoRelay/internal/server"
)

var version = "dev"

func main() {
	if len(os.Args) > 1 && os.Args[1] == "version" {
		fmt.Printf("GoRelay %s (GRP/1)\n", version)
		os.Exit(0)
	}

	// Parse CLI flags
	var overrides config.Overrides
	flag.StringVar(&overrides.Host, "host", "", "server hostname (default: localhost)")
	flag.StringVar(&overrides.SMPPort, "smp-port", "", "SMP listener port (default: 5223)")
	flag.StringVar(&overrides.GRPPort, "grp-port", "", "GRP listener port (default: 7443)")
	flag.StringVar(&overrides.DataDir, "data-dir", "", "data directory path (default: ./data)")
	flag.StringVar(&overrides.AdminPort, "admin-port", "", "admin dashboard port (default: 9090)")
	flag.Parse()

	// Setup structured logging
	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})
	slog.SetDefault(slog.New(handler))

	slog.Info("starting GoRelay", "version", version)

	// Load configuration with overrides
	cfg, err := config.LoadWithOverrides(overrides)
	if err != nil {
		slog.Error("failed to load configuration", "err", err)
		os.Exit(1)
	}

	// Log effective configuration
	slog.Info("configuration",
		"hostname", cfg.Server.Hostname,
		"data_dir", cfg.Server.DataDir,
		"smp_address", cfg.SMP.Address,
		"smp_enabled", cfg.SMP.Enabled,
		"grp_address", cfg.GRP.Address,
		"grp_enabled", cfg.GRP.Enabled,
		"store_path", cfg.Store.Path,
		"store_default_ttl", cfg.Store.DefaultTTL.String(),
		"store_max_ttl", cfg.Store.MaxTTL.String(),
		"admin_address", cfg.Metrics.Address,
	)

	// Create server
	srv, err := server.New(cfg)
	if err != nil {
		slog.Error("failed to create server", "err", err)
		os.Exit(1)
	}

	// Setup graceful shutdown
	ctx, cancel := signal.NotifyContext(context.Background(),
		syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	// Start server
	if err := srv.Run(ctx); err != nil {
		slog.Error("server exited with error", "err", err)
		os.Exit(1)
	}

	slog.Info("GoRelay stopped gracefully")
}
