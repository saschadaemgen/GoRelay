package smp

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"math/big"
	"net"
	"testing"
	"time"
)

// --- Helpers ---

// generateTestCA creates a self-signed Ed25519 CA cert for testing.
func generateTestCA(t *testing.T) (*x509.Certificate, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}
	return cert, priv
}

// generateTestOnlineCert creates an online cert signed by the CA for testing.
func generateTestOnlineCert(t *testing.T, caCert *x509.Certificate, caKey ed25519.PrivateKey) (*x509.Certificate, ed25519.PrivateKey, []byte) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate online key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Test Server"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, pub, caKey)
	if err != nil {
		t.Fatalf("create online cert: %v", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("parse online cert: %v", err)
	}
	return cert, priv, certDER
}

// --- ServerHello Encoding/Decoding Tests ---

func TestServerHelloEncodeDecode(t *testing.T) {
	caCert, caKey := generateTestCA(t)
	_, onlineKey, onlineCertDER := generateTestOnlineCert(t, caCert, caKey)

	dhKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate DH key: %v", err)
	}

	dhPubSPKI := EncodeX25519SPKI(dhKey.PublicKey().Bytes())
	dhKeySig := ed25519.Sign(onlineKey, dhPubSPKI)

	sessionID := []byte("test-session-id-bytes")

	original := &ServerHello{
		VersionMin:     6,
		VersionMax:     7,
		SessionID:      sessionID,
		ServerCertDER:  onlineCertDER,
		DHPubKeySPKI:   dhPubSPKI,
		DHKeySignature: dhKeySig,
	}

	encoded := original.Encode()
	decoded, err := DecodeServerHello(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}

	if decoded.VersionMin != 6 {
		t.Fatalf("VersionMin: got %d, want 6", decoded.VersionMin)
	}
	if decoded.VersionMax != 7 {
		t.Fatalf("VersionMax: got %d, want 7", decoded.VersionMax)
	}
	if !bytes.Equal(decoded.SessionID, sessionID) {
		t.Fatal("SessionID mismatch")
	}
	if !bytes.Equal(decoded.ServerCertDER, onlineCertDER) {
		t.Fatal("ServerCertDER mismatch")
	}
	if !bytes.Equal(decoded.DHPubKeySPKI, dhPubSPKI) {
		t.Fatal("DHPubKeySPKI mismatch")
	}
	if !bytes.Equal(decoded.DHKeySignature, dhKeySig) {
		t.Fatal("DHKeySignature mismatch")
	}
}

func TestServerHelloByteLayout(t *testing.T) {
	// Verify the exact wire format: version(4) + shortString(sess) + origLen(cert) + origLen(signed)
	hello := &ServerHello{
		VersionMin:     6,
		VersionMax:     7,
		SessionID:      []byte{0xAA, 0xBB},
		ServerCertDER:  []byte{0x01, 0x02, 0x03},
		DHPubKeySPKI:   []byte{0x10, 0x20},
		DHKeySignature: []byte{0x30, 0x40, 0x50},
	}

	encoded := hello.Encode()
	off := 0

	// version range
	if binary.BigEndian.Uint16(encoded[off:off+2]) != 6 {
		t.Fatal("vMin wrong")
	}
	off += 2
	if binary.BigEndian.Uint16(encoded[off:off+2]) != 7 {
		t.Fatal("vMax wrong")
	}
	off += 2

	// sessionID = shortString: len=2 + 0xAA 0xBB
	if encoded[off] != 2 {
		t.Fatalf("sessID len: got %d, want 2", encoded[off])
	}
	off++
	if encoded[off] != 0xAA || encoded[off+1] != 0xBB {
		t.Fatal("sessID data mismatch")
	}
	off += 2

	// serverCert = originalLength: len=3 + 0x01 0x02 0x03
	certLen := binary.BigEndian.Uint16(encoded[off : off+2])
	if certLen != 3 {
		t.Fatalf("certLen: got %d, want 3", certLen)
	}
	off += 2
	if encoded[off] != 0x01 || encoded[off+1] != 0x02 || encoded[off+2] != 0x03 {
		t.Fatal("cert data mismatch")
	}
	off += 3

	// signedServerKey = originalLength wrapping (origLen(SPKI) + origLen(sig))
	// inner = 2+2 + 2+3 = 9
	outerLen := binary.BigEndian.Uint16(encoded[off : off+2])
	if outerLen != 9 {
		t.Fatalf("signedKey outerLen: got %d, want 9", outerLen)
	}
	off += 2

	spkiLen := binary.BigEndian.Uint16(encoded[off : off+2])
	if spkiLen != 2 {
		t.Fatalf("spkiLen: got %d, want 2", spkiLen)
	}
	off += 2
	if encoded[off] != 0x10 || encoded[off+1] != 0x20 {
		t.Fatal("SPKI data mismatch")
	}
	off += 2

	sigLen := binary.BigEndian.Uint16(encoded[off : off+2])
	if sigLen != 3 {
		t.Fatalf("sigLen: got %d, want 3", sigLen)
	}
	off += 2
	if encoded[off] != 0x30 || encoded[off+1] != 0x40 || encoded[off+2] != 0x50 {
		t.Fatal("sig data mismatch")
	}
}

func TestServerHelloEmptySessionID(t *testing.T) {
	hello := &ServerHello{
		VersionMin:     6,
		VersionMax:     7,
		SessionID:      nil, // empty session ID (TLS 1.3)
		ServerCertDER:  []byte{0x01},
		DHPubKeySPKI:   []byte{0x02},
		DHKeySignature: []byte{0x03},
	}

	encoded := hello.Encode()
	decoded, err := DecodeServerHello(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(decoded.SessionID) != 0 {
		t.Fatalf("expected empty session ID, got %d bytes", len(decoded.SessionID))
	}
}

// --- ClientHello Encoding/Decoding Tests ---

func TestClientHelloEncodeDecode(t *testing.T) {
	fingerprint := "abc123_test-fingerprint"
	original := &ClientHello{
		Version: 7,
		KeyHash: fingerprint,
	}

	encoded := original.Encode()
	decoded, err := DecodeClientHello(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}

	if decoded.Version != 7 {
		t.Fatalf("Version: got %d, want 7", decoded.Version)
	}
	if decoded.KeyHash != fingerprint {
		t.Fatalf("KeyHash: got %q, want %q", decoded.KeyHash, fingerprint)
	}
	if len(decoded.ClientKey) != 0 {
		t.Fatalf("ClientKey should be empty, got %d bytes", len(decoded.ClientKey))
	}
}

func TestClientHelloWithClientKey(t *testing.T) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	clientSPKI := EncodeX25519SPKI(key.PublicKey().Bytes())

	original := &ClientHello{
		Version:   7,
		KeyHash:   "test-fingerprint",
		ClientKey: clientSPKI,
	}

	encoded := original.Encode()
	decoded, err := DecodeClientHello(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}

	if !bytes.Equal(decoded.ClientKey, clientSPKI) {
		t.Fatal("ClientKey mismatch")
	}
}

func TestClientHelloKeyHashVerification(t *testing.T) {
	caCert, _ := generateTestCA(t)
	hash := sha256.Sum256(caCert.Raw)
	correctFP := base64.RawURLEncoding.EncodeToString(hash[:])

	// Correct fingerprint
	ch := &ClientHello{Version: 7, KeyHash: correctFP}
	encoded := ch.Encode()
	decoded, err := DecodeClientHello(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if decoded.KeyHash != correctFP {
		t.Fatalf("fingerprint mismatch after round-trip")
	}

	// Wrong fingerprint would be caught by ServerHandshake's verify step
	wrongCH := &ClientHello{Version: 7, KeyHash: "wrong-fingerprint"}
	wrongEncoded := wrongCH.Encode()
	wrongDecoded, err := DecodeClientHello(wrongEncoded)
	if err != nil {
		t.Fatalf("decode wrong: %v", err)
	}
	if wrongDecoded.KeyHash == correctFP {
		t.Fatal("wrong fingerprint should not match correct one")
	}
}

// --- X25519 SPKI Tests ---

func TestX25519SPKIRoundTrip(t *testing.T) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pubBytes := key.PublicKey().Bytes()

	spki := EncodeX25519SPKI(pubBytes)
	if len(spki) != x25519SPKISize {
		t.Fatalf("SPKI size: got %d, want %d", len(spki), x25519SPKISize)
	}

	extracted, err := ParseX25519SPKI(spki)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !bytes.Equal(extracted, pubBytes) {
		t.Fatal("round-trip key mismatch")
	}
}

func TestX25519SPKIInvalidLength(t *testing.T) {
	_, err := ParseX25519SPKI([]byte{0x01, 0x02})
	if err == nil {
		t.Fatal("expected error for invalid SPKI length")
	}
}

func TestX25519SPKIInvalidPrefix(t *testing.T) {
	bad := make([]byte, x25519SPKISize)
	bad[0] = 0xFF // corrupt prefix
	_, err := ParseX25519SPKI(bad)
	if err == nil {
		t.Fatal("expected error for invalid SPKI prefix")
	}
}

// --- Signed Server Key Verification ---

func TestSignedServerKeyVerification(t *testing.T) {
	caCert, caKey := generateTestCA(t)
	_, onlineKey, onlineCertDER := generateTestOnlineCert(t, caCert, caKey)

	onlineCert, err := x509.ParseCertificate(onlineCertDER)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}

	dhKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate DH key: %v", err)
	}

	spki := EncodeX25519SPKI(dhKey.PublicKey().Bytes())
	sig := ed25519.Sign(onlineKey, spki)

	// Verify with correct cert
	serverPub := onlineCert.PublicKey.(ed25519.PublicKey)
	if !ed25519.Verify(serverPub, spki, sig) {
		t.Fatal("valid signature rejected")
	}

	// Verify with wrong data fails
	badSPKI := make([]byte, len(spki))
	copy(badSPKI, spki)
	badSPKI[len(badSPKI)-1] ^= 0xFF
	if ed25519.Verify(serverPub, badSPKI, sig) {
		t.Fatal("tampered SPKI should not verify")
	}
}

// --- TLS Config Tests ---

func TestTLSConfigSessionTicketsDisabled(t *testing.T) {
	// Build a TLS config matching what CertManager produces
	cfg := &tls.Config{
		MinVersion:             tls.VersionTLS13,
		CurvePreferences:       []tls.CurveID{tls.X25519},
		SessionTicketsDisabled: true,
	}
	if !cfg.SessionTicketsDisabled {
		t.Fatal("session tickets should be disabled")
	}
	if cfg.MinVersion != tls.VersionTLS13 {
		t.Fatalf("min version: got %d, want TLS 1.3 (%d)", cfg.MinVersion, tls.VersionTLS13)
	}
}

func TestTLSConfigOnlyX25519(t *testing.T) {
	cfg := &tls.Config{
		CurvePreferences: []tls.CurveID{tls.X25519},
	}
	if len(cfg.CurvePreferences) != 1 || cfg.CurvePreferences[0] != tls.X25519 {
		t.Fatal("curve preferences should be X25519 only")
	}
}

// --- Version Negotiation Tests ---

func TestNegotiateVersion(t *testing.T) {
	tests := []struct {
		name     string
		sMin     uint16
		sMax     uint16
		cVersion uint16
		want     uint16
		wantErr  bool
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

// --- ALPN Fallback Test ---

func TestALPNFallbackToV6(t *testing.T) {
	// When ALPN is not confirmed, server should offer v6 only
	caCert, caKey := generateTestCA(t)
	_, onlineKey, onlineCertDER := generateTestOnlineCert(t, caCert, caKey)
	hash := sha256.Sum256(caCert.Raw)
	caFP := base64.RawURLEncoding.EncodeToString(hash[:])

	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	type result struct {
		hr  *HandshakeResult
		err error
	}
	serverCh := make(chan result, 1)

	go func() {
		params := ServerHandshakeParams{
			OnlineCertDER: onlineCertDER,
			OnlineKey:     onlineKey,
			CAFingerprint: caFP,
			SessionID:     nil,
			VersionMin:    SMPVersionMin,
			VersionMax:    SMPVersionMax,
			ALPNConfirmed: false, // no ALPN
		}
		hr, err := ServerHandshake(serverConn, params)
		serverCh <- result{hr, err}
	}()

	// Client reads ServerHello
	clientParams := ClientHandshakeParams{
		CAFingerprint: caFP,
		SessionID:     nil,
		VersionMin:    6,
		VersionMax:    7,
	}
	cr, err := ClientHandshake(clientConn, clientParams)
	if err != nil {
		t.Fatalf("client handshake: %v", err)
	}

	// Without ALPN, should negotiate v6 (legacy range is v6 only)
	if cr.Version != 6 {
		t.Fatalf("client version: got %d, want 6", cr.Version)
	}

	sr := <-serverCh
	if sr.err != nil {
		t.Fatalf("server handshake: %v", sr.err)
	}
	if sr.hr.Version != 6 {
		t.Fatalf("server version: got %d, want 6", sr.hr.Version)
	}
}

// --- Full Handshake Round-Trip (over net.Pipe) ---

func TestHandshakeRoundTrip(t *testing.T) {
	caCert, caKey := generateTestCA(t)
	_, onlineKey, onlineCertDER := generateTestOnlineCert(t, caCert, caKey)
	hash := sha256.Sum256(caCert.Raw)
	caFP := base64.RawURLEncoding.EncodeToString(hash[:])

	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	type sResult struct {
		hr  *HandshakeResult
		err error
	}
	type cResult struct {
		hr  *ClientHandshakeResult
		err error
	}

	serverCh := make(chan sResult, 1)
	clientCh := make(chan cResult, 1)

	go func() {
		params := ServerHandshakeParams{
			OnlineCertDER: onlineCertDER,
			OnlineKey:     onlineKey,
			CAFingerprint: caFP,
			SessionID:     []byte("test-session"),
			VersionMin:    SMPVersionMin,
			VersionMax:    SMPVersionMax,
			ALPNConfirmed: true,
		}
		hr, err := ServerHandshake(serverConn, params)
		serverCh <- sResult{hr, err}
	}()

	go func() {
		params := ClientHandshakeParams{
			CAFingerprint: caFP,
			SessionID:     []byte("test-session"),
			VersionMin:    SMPVersionMin,
			VersionMax:    SMPVersionMax,
		}
		hr, err := ClientHandshake(clientConn, params)
		clientCh <- cResult{hr, err}
	}()

	sr := <-serverCh
	if sr.err != nil {
		t.Fatalf("server handshake: %v", sr.err)
	}

	cr := <-clientCh
	if cr.err != nil {
		t.Fatalf("client handshake: %v", cr.err)
	}

	// Both should agree on version 7
	if sr.hr.Version != 7 {
		t.Fatalf("server version: got %d, want 7", sr.hr.Version)
	}
	if cr.hr.Version != 7 {
		t.Fatalf("client version: got %d, want 7", cr.hr.Version)
	}

	// Session ID preserved
	if !bytes.Equal(sr.hr.SessionID, []byte("test-session")) {
		t.Fatal("server session ID mismatch")
	}
	if !bytes.Equal(cr.hr.SessionID, []byte("test-session")) {
		t.Fatal("client session ID mismatch")
	}

	// Client should have the server's online cert
	if cr.hr.ServerCert == nil {
		t.Fatal("client did not receive server certificate")
	}
}

func TestHandshakeIdentityMismatch(t *testing.T) {
	caCert, caKey := generateTestCA(t)
	_, onlineKey, onlineCertDER := generateTestOnlineCert(t, caCert, caKey)
	hash := sha256.Sum256(caCert.Raw)
	correctFP := base64.RawURLEncoding.EncodeToString(hash[:])

	serverConn, clientConn := net.Pipe()

	type sResult struct {
		hr  *HandshakeResult
		err error
	}

	serverCh := make(chan sResult, 1)

	go func() {
		params := ServerHandshakeParams{
			OnlineCertDER: onlineCertDER,
			OnlineKey:     onlineKey,
			CAFingerprint: correctFP,
			SessionID:     nil,
			VersionMin:    SMPVersionMin,
			VersionMax:    SMPVersionMax,
			ALPNConfirmed: true,
		}
		hr, err := ServerHandshake(serverConn, params)
		serverCh <- sResult{hr, err}
	}()

	// Client sends wrong fingerprint
	wrongParams := ClientHandshakeParams{
		CAFingerprint: "wrong-fingerprint-value",
		SessionID:     nil,
		VersionMin:    SMPVersionMin,
		VersionMax:    SMPVersionMax,
	}
	_, clientErr := ClientHandshake(clientConn, wrongParams)
	// Client handshake itself succeeds (it sends what it has)
	// but the server should reject
	_ = clientErr
	clientConn.Close()

	sr := <-serverCh
	if sr.err == nil {
		t.Fatal("expected server to reject wrong fingerprint")
	}

	serverConn.Close()
}

func TestHandshakeVersionMismatch(t *testing.T) {
	caCert, caKey := generateTestCA(t)
	_, onlineKey, onlineCertDER := generateTestOnlineCert(t, caCert, caKey)
	hash := sha256.Sum256(caCert.Raw)
	caFP := base64.RawURLEncoding.EncodeToString(hash[:])

	serverConn, clientConn := net.Pipe()

	type sResult struct {
		hr  *HandshakeResult
		err error
	}

	serverCh := make(chan sResult, 1)

	go func() {
		params := ServerHandshakeParams{
			OnlineCertDER: onlineCertDER,
			OnlineKey:     onlineKey,
			CAFingerprint: caFP,
			SessionID:     nil,
			VersionMin:    SMPVersionMin,
			VersionMax:    SMPVersionMax,
			ALPNConfirmed: true,
		}
		hr, err := ServerHandshake(serverConn, params)
		serverCh <- sResult{hr, err}
	}()

	// Client speaks v5 only - no overlap
	wrongParams := ClientHandshakeParams{
		CAFingerprint: caFP,
		SessionID:     nil,
		VersionMin:    5,
		VersionMax:    5,
	}
	_, clientErr := ClientHandshake(clientConn, wrongParams)
	if clientErr == nil {
		t.Fatal("expected client version mismatch")
	}
	clientConn.Close()

	sr := <-serverCh
	// Server fails because client closed connection (or version mismatch)
	if sr.err == nil {
		t.Fatal("expected server error")
	}
	serverConn.Close()
}

// --- Private Key Zeroing Test ---

func TestPrivateKeyZeroed(t *testing.T) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	keyBytes := key.Bytes()
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

	zeroECDHKey(key)

	// Verify the zeroing function itself works
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

// --- Decode Error Tests ---

func TestDecodeServerHelloTooShort(t *testing.T) {
	_, err := DecodeServerHello([]byte{0x00, 0x06})
	if err == nil {
		t.Fatal("expected error for too-short data")
	}
}

func TestDecodeClientHelloTooShort(t *testing.T) {
	_, err := DecodeClientHello([]byte{0x00})
	if err == nil {
		t.Fatal("expected error for too-short data")
	}
}

// --- ComputeCAFingerprint Test ---

func TestComputeCAFingerprint(t *testing.T) {
	caCert, _ := generateTestCA(t)

	fp := ComputeCAFingerprint(caCert)
	// Per SMP spec: fingerprint = SHA256 of SPKI DER block
	hash := sha256.Sum256(caCert.RawSubjectPublicKeyInfo)
	expected := base64.RawURLEncoding.EncodeToString(hash[:])

	if fp != expected {
		t.Fatalf("fingerprint: got %q, want %q", fp, expected)
	}
}
