package server

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestCertManagerGeneratesCA(t *testing.T) {
	dir := t.TempDir()

	cm, err := NewCertManager(dir)
	if err != nil {
		t.Fatalf("NewCertManager: %v", err)
	}

	// CA cert should exist on disk
	if _, err := os.Stat(filepath.Join(dir, "ca.key")); err != nil {
		t.Fatalf("ca.key not found: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "ca.pem")); err != nil {
		t.Fatalf("ca.pem not found: %v", err)
	}

	// Online cert should exist on disk
	if _, err := os.Stat(filepath.Join(dir, "server.key")); err != nil {
		t.Fatalf("server.key not found: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "server.pem")); err != nil {
		t.Fatalf("server.pem not found: %v", err)
	}

	// CA should be Ed25519
	if cm.CACert().PublicKeyAlgorithm != x509.Ed25519 {
		t.Fatalf("CA key algorithm: got %v, want Ed25519", cm.CACert().PublicKeyAlgorithm)
	}

	// CA should be a CA
	if !cm.CACert().IsCA {
		t.Fatal("CA cert IsCA should be true")
	}

	// Fingerprint should be non-empty and stable
	fp := cm.Fingerprint()
	if fp == "" {
		t.Fatal("fingerprint is empty")
	}
	if len(fp) != 43 {
		// SHA256 (32 bytes) base64url no-padding = 43 chars
		t.Fatalf("fingerprint length: got %d, want 43", len(fp))
	}
}

func TestCertManagerFingerprintStableAcrossLoads(t *testing.T) {
	dir := t.TempDir()

	cm1, err := NewCertManager(dir)
	if err != nil {
		t.Fatalf("first NewCertManager: %v", err)
	}
	fp1 := cm1.Fingerprint()

	cm2, err := NewCertManager(dir)
	if err != nil {
		t.Fatalf("second NewCertManager: %v", err)
	}
	fp2 := cm2.Fingerprint()

	if fp1 != fp2 {
		t.Fatalf("fingerprint changed across loads: %q != %q", fp1, fp2)
	}
}

func TestOnlineCertSignedByCA(t *testing.T) {
	dir := t.TempDir()

	cm, err := NewCertManager(dir)
	if err != nil {
		t.Fatalf("NewCertManager: %v", err)
	}

	// Parse the online cert from the tls.Certificate chain
	tlsCfg := cm.TLSConfig()
	if len(tlsCfg.Certificates) != 1 {
		t.Fatalf("expected 1 certificate, got %d", len(tlsCfg.Certificates))
	}

	chain := tlsCfg.Certificates[0].Certificate
	if len(chain) != 2 {
		t.Fatalf("expected chain of 2 (server + CA), got %d", len(chain))
	}

	serverCert, err := x509.ParseCertificate(chain[0])
	if err != nil {
		t.Fatalf("parse server cert: %v", err)
	}

	// Server cert should be Ed25519
	if serverCert.PublicKeyAlgorithm != x509.Ed25519 {
		t.Fatalf("server cert algorithm: got %v, want Ed25519", serverCert.PublicKeyAlgorithm)
	}

	// Verify server cert against CA
	roots := x509.NewCertPool()
	roots.AddCert(cm.CACert())

	opts := x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	if _, err := serverCert.Verify(opts); err != nil {
		t.Fatalf("server cert verification failed: %v", err)
	}
}

func TestOnlineCertReloadedFromDisk(t *testing.T) {
	dir := t.TempDir()

	cm1, err := NewCertManager(dir)
	if err != nil {
		t.Fatalf("first NewCertManager: %v", err)
	}

	// Get the server cert from first load
	chain1 := cm1.TLSConfig().Certificates[0].Certificate[0]

	// Load again - should reload from disk
	cm2, err := NewCertManager(dir)
	if err != nil {
		t.Fatalf("second NewCertManager: %v", err)
	}

	chain2 := cm2.TLSConfig().Certificates[0].Certificate[0]

	// Should be the same cert bytes
	if len(chain1) != len(chain2) {
		t.Fatal("online cert changed across loads")
	}
	for i := range chain1 {
		if chain1[i] != chain2[i] {
			t.Fatal("online cert bytes differ across loads")
		}
	}
}

func TestCACertNeverRegenerated(t *testing.T) {
	dir := t.TempDir()

	_, err := NewCertManager(dir)
	if err != nil {
		t.Fatalf("first NewCertManager: %v", err)
	}

	// Read the CA cert PEM from disk
	caPEM1, err := os.ReadFile(filepath.Join(dir, "ca.pem"))
	if err != nil {
		t.Fatalf("read ca.pem: %v", err)
	}

	// Create a second manager - should load, not regenerate
	_, err = NewCertManager(dir)
	if err != nil {
		t.Fatalf("second NewCertManager: %v", err)
	}

	caPEM2, err := os.ReadFile(filepath.Join(dir, "ca.pem"))
	if err != nil {
		t.Fatalf("read ca.pem again: %v", err)
	}

	if string(caPEM1) != string(caPEM2) {
		t.Fatal("CA cert PEM changed - CA was regenerated")
	}
}

func TestSMPURI(t *testing.T) {
	dir := t.TempDir()

	cm, err := NewCertManager(dir)
	if err != nil {
		t.Fatalf("NewCertManager: %v", err)
	}

	uri := cm.SMPURI("relay.example.com", "5223")
	expected := "smp://" + cm.Fingerprint() + "@relay.example.com:5223"
	if uri != expected {
		t.Fatalf("SMPURI: got %q, want %q", uri, expected)
	}
}

func TestFingerprintMatchesSPKIHash(t *testing.T) {
	dir := t.TempDir()

	cm, err := NewCertManager(dir)
	if err != nil {
		t.Fatalf("NewCertManager: %v", err)
	}

	// Per SMP spec: fingerprint = SHA256 of the certificate's SubjectPublicKeyInfo DER
	hash := sha256.Sum256(cm.CACert().RawSubjectPublicKeyInfo)
	expected := base64.RawURLEncoding.EncodeToString(hash[:])

	if cm.Fingerprint() != expected {
		t.Fatalf("fingerprint mismatch: got %q, want %q", cm.Fingerprint(), expected)
	}

	// Verify it does NOT equal SHA256 of the full certificate DER
	certHash := sha256.Sum256(cm.CACert().Raw)
	certHashStr := base64.RawURLEncoding.EncodeToString(certHash[:])
	if cm.Fingerprint() == certHashStr {
		t.Fatal("fingerprint should not equal full cert DER hash")
	}
}

func TestCAKeyPermissions(t *testing.T) {
	dir := t.TempDir()

	_, err := NewCertManager(dir)
	if err != nil {
		t.Fatalf("NewCertManager: %v", err)
	}

	// Verify PEM format of CA key
	keyPEM, err := os.ReadFile(filepath.Join(dir, "ca.key"))
	if err != nil {
		t.Fatalf("read ca.key: %v", err)
	}

	block, _ := pem.Decode(keyPEM)
	if block == nil {
		t.Fatal("ca.key is not valid PEM")
	}
	if block.Type != "PRIVATE KEY" {
		t.Fatalf("ca.key PEM type: got %q, want PRIVATE KEY", block.Type)
	}

	parsedKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse ca.key: %v", err)
	}

	if _, ok := parsedKey.(ed25519.PrivateKey); !ok {
		t.Fatal("ca.key is not Ed25519")
	}
}
