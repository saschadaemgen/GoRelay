package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/saschadaemgen/GoRelay/internal/config"
	"github.com/saschadaemgen/GoRelay/internal/server"
)

// startTestServer creates a GoRelay server on a random port and returns
// its TLS address plus a cancel function.
func startTestServer(t *testing.T) (addr string, cancel context.CancelFunc) {
	t.Helper()

	dataDir := t.TempDir()

	// Grab a free port
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("grab port: %v", err)
	}
	freeAddr := ln.Addr().String()
	ln.Close()

	cfg := config.DefaultConfig()
	cfg.Server.DataDir = dataDir
	cfg.SMP.Enabled = true
	cfg.SMP.Address = freeAddr
	cfg.GRP.Enabled = false

	srv, err := server.New(cfg)
	if err != nil {
		t.Fatalf("create server: %v", err)
	}

	ctx, cancelFn := context.WithCancel(context.Background())

	go func() {
		_ = srv.Run(ctx)
	}()

	// Wait for server to accept TLS connections
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		conn, dialErr := tls.DialWithDialer(
			&net.Dialer{Timeout: 500 * time.Millisecond},
			"tcp",
			freeAddr,
			&tls.Config{
				InsecureSkipVerify: true,
				MaxVersion:         tls.VersionTLS12,
			},
		)
		if dialErr == nil {
			conn.Close()
			return freeAddr, cancelFn
		}
		time.Sleep(50 * time.Millisecond)
	}

	t.Fatalf("server did not become ready within 5s")
	return "", nil
}

func TestPingSubcommand(t *testing.T) {
	addr, cancel := startTestServer(t)
	defer cancel()

	client, err := ConnectSMP(addr, true, false)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer client.Close()

	cmd, err := client.SendPING()
	if err != nil {
		t.Fatalf("PING: %v", err)
	}
	if cmd.Type != 0x0E {
		t.Fatalf("expected PONG (0x0E), got 0x%02x", cmd.Type)
	}
}

func TestFullTestSubcommand(t *testing.T) {
	addr, cancel := startTestServer(t)
	defer cancel()

	// Step 1: recipient creates queue
	recipientClient, err := ConnectSMP(addr, true, false)
	if err != nil {
		t.Fatalf("connect recipient: %v", err)
	}
	defer recipientClient.Close()

	recipientPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}

	recipientID, senderID, _, err := recipientClient.SendNEW(recipientPub)
	if err != nil {
		t.Fatalf("NEW: %v", err)
	}

	// Step 2: sender connects and sets key
	senderClient, err := ConnectSMP(addr, true, false)
	if err != nil {
		t.Fatalf("connect sender: %v", err)
	}
	defer senderClient.Close()

	senderPub, senderPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}

	if err := senderClient.SendKEY(recipientID, senderPub); err != nil {
		t.Fatalf("KEY: %v", err)
	}

	// Step 3: send message
	testMsg := "full-test message from test"
	if err := senderClient.SendSEND(senderID, senderPriv, []byte(testMsg)); err != nil {
		t.Fatalf("SEND: %v", err)
	}

	// Step 4: receive MSG (body is NaCl encrypted, verify receipt only)
	msgID, _, _, body, err := recipientClient.ReadMSG()
	if err != nil {
		t.Fatalf("read MSG: %v", err)
	}
	// Body is encrypted (16122 bytes: 16 tag + 16106 padded ciphertext)
	if len(body) != 16122 {
		t.Fatalf("MSG encrypted body length: got %d, want 16122", len(body))
	}

	// Step 5: ACK
	if err := recipientClient.SendACK(recipientID, msgID); err != nil {
		t.Fatalf("ACK: %v", err)
	}

	// Step 6: PING to verify connection still alive
	cmd, err := recipientClient.SendPING()
	if err != nil {
		t.Fatalf("PING: %v", err)
	}
	if cmd.Type != 0x0E {
		t.Fatalf("expected PONG, got 0x%02x", cmd.Type)
	}
}
