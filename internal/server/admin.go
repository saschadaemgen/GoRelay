package server

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"
)

//go:embed web/index.html
var dashboardFS embed.FS

// AdminConfig holds the configuration returned by the config API.
type AdminConfig struct {
	Hostname   string `json:"hostname"`
	SMPAddress string `json:"smp_address"`
	GRPAddress string `json:"grp_address"`
	SMPURI     string `json:"smp_uri"`
	StorePath  string `json:"store_path"`
	DefaultTTL string `json:"default_ttl"`
	MaxTTL     string `json:"max_ttl"`
}

// startAdmin starts the admin HTTP server on localhost only.
// It blocks until the context is cancelled.
func (s *Server) startAdmin(ctx context.Context, address string) error {
	mux := http.NewServeMux()

	// Serve embedded dashboard at /
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		data, err := dashboardFS.ReadFile("web/index.html")
		if err != nil {
			http.Error(w, "dashboard not found", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(data)
	})

	// JSON API: metrics
	mux.HandleFunc("/api/metrics", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		snap := s.metrics.Snapshot()

		// Build combined response with config
		type metricsResponse struct {
			MetricsSnapshot
			Config AdminConfig `json:"config"`
		}

		resp := metricsResponse{
			MetricsSnapshot: snap,
			Config: AdminConfig{
				Hostname:   s.config.Server.Hostname,
				SMPAddress: s.config.SMP.Address,
				GRPAddress: s.config.GRP.Address,
				SMPURI:     s.smpURI,
				StorePath:  s.config.Store.Path,
				DefaultTTL: s.config.Store.DefaultTTL.String(),
				MaxTTL:     s.config.Store.MaxTTL.String(),
			},
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	// JSON API: security events
	mux.HandleFunc("/api/events", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		events := s.metrics.SecurityEvents()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(events)
	})

	// Force localhost binding
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("invalid admin address %q: %w", address, err)
	}
	if host == "" || host == "0.0.0.0" {
		host = "127.0.0.1"
	}
	listenAddr := net.JoinHostPort(host, port)

	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("admin listen: %w", err)
	}

	srv := &http.Server{
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	slog.Info("Admin dashboard ready", "url", fmt.Sprintf("http://%s", listener.Addr()))

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(shutdownCtx)
	}()

	if err := srv.Serve(listener); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("admin serve: %w", err)
	}
	return nil
}

// AdminAddr returns the admin listen address from config.
func (s *Server) AdminAddr() string {
	return s.config.Metrics.Address
}
