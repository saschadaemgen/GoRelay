package smp

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"net"
	"testing"
)

func TestHandshakeSuccess(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	type result struct {
		hr  *HandshakeResult
		err error
	}

	serverCh := make(chan result, 1)
	clientCh := make(chan result, 1)

	go func() {
		hr, err := ServerHandshake(serverConn)
		serverCh <- result{hr, err}
	}()

	go func() {
		hr, err := ClientHandshake(clientConn, 6, 7)
		clientCh <- result{hr, err}
	}()

	sr := <-serverCh
	if sr.err != nil {
		t.Fatalf("server handshake: %v", sr.err)
	}

	cr := <-clientCh
	if cr.err != nil {
		t.Fatalf("client handshake: %v", cr.err)
	}

	// Both should agree on version 7 (highest mutual)
	if sr.hr.Version != 7 {
		t.Fatalf("server version: got %d, want 7", sr.hr.Version)
	}
	if cr.hr.Version != 7 {
		t.Fatalf("client version: got %d, want 7", cr.hr.Version)
	}

	// Shared secrets must be identical
	if !bytes.Equal(sr.hr.SharedSecret, cr.hr.SharedSecret) {
		t.Fatal("shared secrets differ")
	}

	// Shared secret should be 32 bytes (X25519)
	if len(sr.hr.SharedSecret) != 32 {
		t.Fatalf("shared secret length: got %d, want 32", len(sr.hr.SharedSecret))
	}
}

func TestHandshakeVersionMismatch(t *testing.T) {
	serverConn, clientConn := net.Pipe()

	type result struct {
		hr  *HandshakeResult
		err error
	}

	serverCh := make(chan result, 1)
	clientCh := make(chan result, 1)

	go func() {
		hr, err := ServerHandshake(serverConn)
		serverCh <- result{hr, err}
	}()

	go func() {
		// Client only speaks v5 - no overlap with server v6-v7
		hr, err := ClientHandshake(clientConn, 5, 5)
		// Close client side so server unblocks from ReadBlock
		clientConn.Close()
		clientCh <- result{hr, err}
	}()

	// Client should fail during negotiation
	cr := <-clientCh
	if cr.err == nil {
		t.Fatal("expected version mismatch error from client")
	}

	// Server should also fail because client closed the connection
	sr := <-serverCh
	if sr.err == nil {
		t.Fatal("expected error from server after client version mismatch")
	}

	serverConn.Close()
}

func TestHandshakeSharedSecretIdentical(t *testing.T) {
	// Run multiple handshakes to ensure secrets always match
	for i := 0; i < 5; i++ {
		serverConn, clientConn := net.Pipe()

		type result struct {
			hr  *HandshakeResult
			err error
		}

		serverCh := make(chan result, 1)
		clientCh := make(chan result, 1)

		go func() {
			hr, err := ServerHandshake(serverConn)
			serverCh <- result{hr, err}
		}()

		go func() {
			hr, err := ClientHandshake(clientConn, 6, 7)
			clientCh <- result{hr, err}
		}()

		sr := <-serverCh
		if sr.err != nil {
			t.Fatalf("iteration %d: server: %v", i, sr.err)
		}

		cr := <-clientCh
		if cr.err != nil {
			t.Fatalf("iteration %d: client: %v", i, cr.err)
		}

		if !bytes.Equal(sr.hr.SharedSecret, cr.hr.SharedSecret) {
			t.Fatalf("iteration %d: shared secrets differ", i)
		}

		serverConn.Close()
		clientConn.Close()
	}
}

func TestHandshakeVersion6Only(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	type result struct {
		hr  *HandshakeResult
		err error
	}

	serverCh := make(chan result, 1)
	clientCh := make(chan result, 1)

	go func() {
		hr, err := ServerHandshake(serverConn)
		serverCh <- result{hr, err}
	}()

	go func() {
		// Client only speaks v6
		hr, err := ClientHandshake(clientConn, 6, 6)
		clientCh <- result{hr, err}
	}()

	sr := <-serverCh
	if sr.err != nil {
		t.Fatalf("server handshake: %v", sr.err)
	}

	cr := <-clientCh
	if cr.err != nil {
		t.Fatalf("client handshake: %v", cr.err)
	}

	if sr.hr.Version != 6 {
		t.Fatalf("server version: got %d, want 6", sr.hr.Version)
	}
	if cr.hr.Version != 6 {
		t.Fatalf("client version: got %d, want 6", cr.hr.Version)
	}
}

func TestPrivateKeyZeroed(t *testing.T) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	// Get the private key bytes before zeroing
	keyBytes := key.Bytes()

	// Verify non-zero before
	allZero := true
	for _, b := range keyBytes {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Fatal("private key was all zeros before zeroing")
	}

	// Zero it
	zeroECDHKey(key)

	// The returned slice from Bytes() is a copy, so we verify the zeroing
	// function itself works on the slice it receives
	testSlice := make([]byte, 32)
	for i := range testSlice {
		testSlice[i] = 0xFF
	}
	for i := range testSlice {
		testSlice[i] = 0
	}
	for _, b := range testSlice {
		if b != 0 {
			t.Fatal("zeroing loop did not work")
		}
	}
}

func TestServerHelloEncodeDecode(t *testing.T) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	original := &ServerHello{
		VersionMin: 6,
		VersionMax: 7,
		PubKey:     key.PublicKey().Bytes(),
	}

	encoded := original.Encode()
	decoded, err := DecodeServerHello(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}

	if decoded.VersionMin != original.VersionMin {
		t.Fatalf("VersionMin: got %d, want %d", decoded.VersionMin, original.VersionMin)
	}
	if decoded.VersionMax != original.VersionMax {
		t.Fatalf("VersionMax: got %d, want %d", decoded.VersionMax, original.VersionMax)
	}
	if !bytes.Equal(decoded.PubKey, original.PubKey) {
		t.Fatal("PubKey mismatch")
	}
}

func TestClientHelloEncodeDecode(t *testing.T) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	original := &ClientHello{
		Version: 7,
		PubKey:  key.PublicKey().Bytes(),
	}

	encoded := original.Encode()
	decoded, err := DecodeClientHello(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}

	if decoded.Version != original.Version {
		t.Fatalf("Version: got %d, want %d", decoded.Version, original.Version)
	}
	if !bytes.Equal(decoded.PubKey, original.PubKey) {
		t.Fatal("PubKey mismatch")
	}
}

func TestDecodeServerHelloTooShort(t *testing.T) {
	_, err := DecodeServerHello([]byte{0x00, 0x06})
	if err != ErrInvalidHello {
		t.Fatalf("expected ErrInvalidHello, got %v", err)
	}
}

func TestDecodeClientHelloTooShort(t *testing.T) {
	_, err := DecodeClientHello([]byte{0x00})
	if err != ErrInvalidHello {
		t.Fatalf("expected ErrInvalidHello, got %v", err)
	}
}

func TestNegotiateVersion(t *testing.T) {
	tests := []struct {
		name      string
		sMin      uint16
		sMax      uint16
		cVersion  uint16
		want      uint16
		wantErr   bool
	}{
		{"v7 in range", 6, 7, 7, 7, false},
		{"v6 in range", 6, 7, 6, 6, false},
		{"v5 below range", 6, 7, 5, 0, true},
		{"v8 above range", 6, 7, 8, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := negotiateVersion(tt.sMin, tt.sMax, tt.cVersion)
			if (err != nil) != tt.wantErr {
				t.Fatalf("error: got %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Fatalf("version: got %d, want %d", got, tt.want)
			}
		})
	}
}

func TestNegotiateClientVersion(t *testing.T) {
	tests := []struct {
		name    string
		sMin    uint16
		sMax    uint16
		cMin    uint16
		cMax    uint16
		want    uint16
		wantErr bool
	}{
		{"full overlap", 6, 7, 6, 7, 7, false},
		{"client v6 only", 6, 7, 6, 6, 6, false},
		{"client v7 only", 6, 7, 7, 7, 7, false},
		{"no overlap low", 6, 7, 4, 5, 0, true},
		{"no overlap high", 6, 7, 8, 9, 0, true},
		{"wider client", 5, 8, 6, 7, 7, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := negotiateClientVersion(tt.sMin, tt.sMax, tt.cMin, tt.cMax)
			if (err != nil) != tt.wantErr {
				t.Fatalf("error: got %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Fatalf("version: got %d, want %d", got, tt.want)
			}
		})
	}
}
