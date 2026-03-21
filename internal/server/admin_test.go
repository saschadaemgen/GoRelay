package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/saschadaemgen/GoRelay/internal/config"
)

// startAdminServer starts a GoRelay server with SMP and admin dashboard
// on random ports. Returns the admin address and cleanup function.
func startAdminServer(t *testing.T) (adminAddr string, smpAddr string, cancel context.CancelFunc) {
	t.Helper()

	dataDir := t.TempDir()

	// Grab free ports
	adminLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("grab admin port: %v", err)
	}
	adminFreeAddr := adminLn.Addr().String()
	adminLn.Close()

	smpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("grab smp port: %v", err)
	}
	smpFreeAddr := smpLn.Addr().String()
	smpLn.Close()

	cfg := config.DefaultConfig()
	cfg.Server.DataDir = dataDir
	cfg.SMP.Enabled = true
	cfg.SMP.Address = smpFreeAddr
	cfg.GRP.Enabled = false
	cfg.Metrics.Enabled = true
	cfg.Metrics.Address = adminFreeAddr

	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("create server: %v", err)
	}

	ctx, cancelFn := context.WithCancel(context.Background())

	go func() {
		_ = srv.Run(ctx)
	}()

	// Wait for admin to be ready
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(fmt.Sprintf("http://%s/api/metrics", adminFreeAddr))
		if err == nil {
			resp.Body.Close()
			return adminFreeAddr, smpFreeAddr, cancelFn
		}
		time.Sleep(50 * time.Millisecond)
	}

	t.Fatalf("admin server did not become ready within 5s")
	return "", "", nil
}

func TestAdminMetricsReturnsValidJSON(t *testing.T) {
	adminAddr, _, cancel := startAdminServer(t)
	defer cancel()

	resp, err := http.Get(fmt.Sprintf("http://%s/api/metrics", adminAddr))
	if err != nil {
		t.Fatalf("GET /api/metrics: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content-type: %s", ct)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	var data map[string]interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		t.Fatalf("invalid JSON: %v\nbody: %s", err, body)
	}

	// Check expected fields exist
	expectedFields := []string{
		"uptime_seconds",
		"active_connections_smp",
		"active_connections_grp",
		"active_connections_total",
		"peak_connections",
		"active_queues",
		"messages_sent",
		"messages_received",
		"messages_discarded",
		"commands_processed",
		"mem_alloc_mb",
		"mem_sys_mb",
		"num_goroutines",
		"config",
	}
	for _, f := range expectedFields {
		if _, ok := data[f]; !ok {
			t.Errorf("missing field: %s", f)
		}
	}

	// Check config sub-fields
	cfg, ok := data["config"].(map[string]interface{})
	if !ok {
		t.Fatal("config is not an object")
	}
	for _, f := range []string{"hostname", "smp_address", "grp_address", "smp_uri"} {
		if _, ok := cfg[f]; !ok {
			t.Errorf("missing config field: %s", f)
		}
	}
}

func TestAdminEventsReturnsValidJSONArray(t *testing.T) {
	adminAddr, _, cancel := startAdminServer(t)
	defer cancel()

	resp, err := http.Get(fmt.Sprintf("http://%s/api/events", adminAddr))
	if err != nil {
		t.Fatalf("GET /api/events: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	var events []map[string]interface{}
	if err := json.Unmarshal(body, &events); err != nil {
		t.Fatalf("invalid JSON array: %v\nbody: %s", err, body)
	}
}

func TestAdminStartsOnConfiguredPort(t *testing.T) {
	adminAddr, _, cancel := startAdminServer(t)
	defer cancel()

	// Dashboard should be served at /
	resp, err := http.Get(fmt.Sprintf("http://%s/", adminAddr))
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("dashboard status: %d", resp.StatusCode)
	}
	ct := resp.Header.Get("Content-Type")
	if ct != "text/html; charset=utf-8" {
		t.Fatalf("content-type: %s", ct)
	}
}

func TestAdminOnlyListensOnLocalhost(t *testing.T) {
	adminAddr, _, cancel := startAdminServer(t)
	defer cancel()

	// Verify the address is 127.0.0.1
	host, _, err := net.SplitHostPort(adminAddr)
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}
	if host != "127.0.0.1" {
		t.Fatalf("admin host: %s, want 127.0.0.1", host)
	}
}

func TestMetricsIncrementOnQueueCreate(t *testing.T) {
	adminAddr, smpAddr, cancel := startAdminServer(t)
	defer cancel()

	// Wait for SMP to be ready
	time.Sleep(100 * time.Millisecond)

	// Create a queue via SMP
	conn := dialSMP(t, smpAddr)
	defer conn.Close()

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	createQueueOnConn(t, conn, pub)

	// Small delay for metrics to update
	time.Sleep(50 * time.Millisecond)

	// Check metrics
	resp, err := http.Get(fmt.Sprintf("http://%s/api/metrics", adminAddr))
	if err != nil {
		t.Fatalf("GET /api/metrics: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	var data map[string]interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	queues, ok := data["active_queues"].(float64)
	if !ok {
		t.Fatal("active_queues not a number")
	}
	if queues < 1 {
		t.Fatalf("active_queues: %v, want >= 1", queues)
	}

	cmds, ok := data["commands_processed"].(float64)
	if !ok {
		t.Fatal("commands_processed not a number")
	}
	if cmds < 1 {
		t.Fatalf("commands_processed: %v, want >= 1", cmds)
	}

	// Connection should be counted
	totalSMP, ok := data["total_connections_smp"].(float64)
	if !ok {
		t.Fatal("total_connections_smp not a number")
	}
	if totalSMP < 1 {
		t.Fatalf("total_connections_smp: %v, want >= 1", totalSMP)
	}
}
