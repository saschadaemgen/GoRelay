package server

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/saschadaemgen/GoRelay/internal/config"
	"github.com/saschadaemgen/GoRelay/internal/protocol/common"
	"github.com/saschadaemgen/GoRelay/internal/protocol/smp"
)

// startTestServer spins up an SMP server on a random port and returns
// the TLS address and a cancel function for cleanup.
func startTestServer(t *testing.T) (addr string, cancel context.CancelFunc) {
	t.Helper()

	dataDir := t.TempDir()

	cfg := config.DefaultConfig()
	cfg.Server.DataDir = dataDir
	cfg.SMP.Enabled = true
	cfg.SMP.Address = "127.0.0.1:0" // random port
	cfg.GRP.Enabled = false

	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("create server: %v", err)
	}

	// Start the TLS listener manually so we can grab the actual address
	tlsConfig := srv.certManager.TLSConfig()
	listener, err := tls.Listen("tcp", cfg.SMP.Address, tlsConfig)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	ctx, cancelFn := context.WithCancel(context.Background())

	// Accept loop in background
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				select {
				case <-ctx.Done():
					return
				default:
					continue
				}
			}
			go srv.handleSMPConnection(ctx, conn)
		}
	}()

	// Close listener on context cancel
	go func() {
		<-ctx.Done()
		listener.Close()
	}()

	return listener.Addr().String(), cancelFn
}

// dialSMP connects via TLS with ALPN smp/1, performs the SMP handshake,
// and returns the raw TLS connection for block I/O.
func dialSMP(t *testing.T, addr string) net.Conn {
	t.Helper()

	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 5 * time.Second},
		"tcp",
		addr,
		&tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{"smp/1"},
		},
	)
	if err != nil {
		t.Fatalf("dial TLS: %v", err)
	}

	// Perform SMP version handshake
	_, err = smp.ClientHandshake(conn, smp.SMPVersionMin, smp.SMPVersionMax)
	if err != nil {
		conn.Close()
		t.Fatalf("client handshake: %v", err)
	}

	return conn
}

// buildPINGBlock constructs a full 16384-byte block containing one PING
// command with the given correlation ID.
func buildPINGBlock(corrID [24]byte) [common.BlockSize]byte {
	// Build transmission: sig(0) + sessID(0) + corrID(24) + entityID(0) + PING
	transmission := make([]byte, 0, 28)
	transmission = append(transmission, 0x00)       // signature length = 0
	transmission = append(transmission, 0x00)       // session_id length = 0
	transmission = append(transmission, corrID[:]...) // correlation ID
	transmission = append(transmission, 0x00)       // entity_id length = 0
	transmission = append(transmission, common.CmdPING)

	// Build payload: batchCount(1) + tLen(2) + transmission
	payload := make([]byte, 0, 3+len(transmission))
	payload = append(payload, 0x01) // batch count = 1
	tLen := uint16(len(transmission))
	payload = append(payload, byte(tLen>>8), byte(tLen))
	payload = append(payload, transmission...)

	// Build block
	var block [common.BlockSize]byte
	binary.BigEndian.PutUint16(block[:2], uint16(len(payload)))
	copy(block[2:], payload)
	for i := 2 + len(payload); i < common.BlockSize; i++ {
		block[i] = common.PaddingByte
	}
	return block
}

// readRawBlock reads exactly 16384 bytes from the connection using io.ReadFull.
func readRawBlock(t *testing.T, conn net.Conn) [common.BlockSize]byte {
	t.Helper()
	var block [common.BlockSize]byte
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err := io.ReadFull(conn, block[:])
	if err != nil {
		t.Fatalf("read raw block: %v", err)
	}
	return block
}

func TestPingPongSingleRoundTrip(t *testing.T) {
	addr, cancel := startTestServer(t)
	defer cancel()

	conn := dialSMP(t, addr)
	defer conn.Close()

	// Build and send PING
	var corrID [24]byte
	if _, err := rand.Read(corrID[:]); err != nil {
		t.Fatalf("generate corrID: %v", err)
	}

	block := buildPINGBlock(corrID)
	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	n, err := conn.Write(block[:])
	if err != nil {
		t.Fatalf("write PING block: %v", err)
	}
	if n != common.BlockSize {
		t.Fatalf("wrote %d bytes, want %d", n, common.BlockSize)
	}

	// Read raw PONG response
	resp := readRawBlock(t, conn)

	// Verify block is exactly 16384 bytes (guaranteed by readRawBlock)
	// Verify payload length
	payloadLen := binary.BigEndian.Uint16(resp[:2])
	if payloadLen == 0 || int(payloadLen) > common.MaxPayloadSize {
		t.Fatalf("invalid payload length: %d", payloadLen)
	}

	// Verify padding is all '#'
	for i := 2 + int(payloadLen); i < common.BlockSize; i++ {
		if resp[i] != common.PaddingByte {
			t.Fatalf("padding byte at offset %d: got 0x%02x, want 0x%02x", i, resp[i], common.PaddingByte)
		}
	}

	// Parse the payload to verify PONG
	payload := resp[2 : 2+payloadLen]
	cmds, err := common.ParsePayload(payload)
	if err != nil {
		t.Fatalf("parse PONG payload: %v", err)
	}

	if len(cmds) != 1 {
		t.Fatalf("expected 1 response, got %d", len(cmds))
	}

	if cmds[0].Type != common.CmdPONG {
		t.Fatalf("expected PONG (0x%02x), got 0x%02x", common.CmdPONG, cmds[0].Type)
	}

	if cmds[0].CorrelationID != corrID {
		t.Fatalf("correlation ID mismatch in PONG")
	}
}

func TestPingPongMultipleSequential(t *testing.T) {
	addr, cancel := startTestServer(t)
	defer cancel()

	conn := dialSMP(t, addr)
	defer conn.Close()

	for i := 0; i < 10; i++ {
		var corrID [24]byte
		if _, err := rand.Read(corrID[:]); err != nil {
			t.Fatalf("iteration %d: generate corrID: %v", i, err)
		}

		// Send PING
		block := buildPINGBlock(corrID)
		conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if _, err := conn.Write(block[:]); err != nil {
			t.Fatalf("iteration %d: write PING: %v", i, err)
		}

		// Read PONG
		resp := readRawBlock(t, conn)

		payloadLen := binary.BigEndian.Uint16(resp[:2])
		payload := resp[2 : 2+payloadLen]

		cmds, err := common.ParsePayload(payload)
		if err != nil {
			t.Fatalf("iteration %d: parse PONG: %v", i, err)
		}

		if len(cmds) != 1 {
			t.Fatalf("iteration %d: expected 1 response, got %d", i, len(cmds))
		}

		if cmds[0].Type != common.CmdPONG {
			t.Fatalf("iteration %d: expected PONG, got 0x%02x", i, cmds[0].Type)
		}

		if cmds[0].CorrelationID != corrID {
			t.Fatalf("iteration %d: correlation ID mismatch", i)
		}
	}
}

func TestPingPongBlockSize(t *testing.T) {
	addr, cancel := startTestServer(t)
	defer cancel()

	conn := dialSMP(t, addr)
	defer conn.Close()

	var corrID [24]byte
	if _, err := rand.Read(corrID[:]); err != nil {
		t.Fatalf("generate corrID: %v", err)
	}

	// Verify sent block is exactly 16384
	block := buildPINGBlock(corrID)
	if len(block) != common.BlockSize {
		t.Fatalf("PING block size: got %d, want %d", len(block), common.BlockSize)
	}

	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(block[:]); err != nil {
		t.Fatalf("write PING: %v", err)
	}

	// Read response - readRawBlock reads exactly BlockSize bytes via io.ReadFull
	resp := readRawBlock(t, conn)
	if len(resp) != common.BlockSize {
		t.Fatalf("PONG block size: got %d, want %d", len(resp), common.BlockSize)
	}
}

func TestPingPongPaddingCharacter(t *testing.T) {
	addr, cancel := startTestServer(t)
	defer cancel()

	conn := dialSMP(t, addr)
	defer conn.Close()

	var corrID [24]byte
	if _, err := rand.Read(corrID[:]); err != nil {
		t.Fatalf("generate corrID: %v", err)
	}

	block := buildPINGBlock(corrID)

	// Verify PING block padding
	pingPayloadLen := binary.BigEndian.Uint16(block[:2])
	for i := 2 + int(pingPayloadLen); i < common.BlockSize; i++ {
		if block[i] != '#' {
			t.Fatalf("PING padding at %d: got 0x%02x, want '#'", i, block[i])
		}
	}

	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(block[:]); err != nil {
		t.Fatalf("write PING: %v", err)
	}

	// Verify PONG block padding
	resp := readRawBlock(t, conn)
	pongPayloadLen := binary.BigEndian.Uint16(resp[:2])
	for i := 2 + int(pongPayloadLen); i < common.BlockSize; i++ {
		if resp[i] != '#' {
			t.Fatalf("PONG padding at %d: got 0x%02x, want '#'", i, resp[i])
		}
	}
}
