package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// CertManager handles the SMP two-certificate chain:
// an offline CA (server identity) and an online TLS certificate signed by it.
type CertManager struct {
	dataDir     string
	caCert      *x509.Certificate
	caKey       ed25519.PrivateKey
	tlsCert     tls.Certificate
	fingerprint string
}

// NewCertManager loads or generates the CA and online TLS certificate.
// On first run it creates both; on subsequent runs it loads the CA from disk
// and regenerates the online cert if missing.
func NewCertManager(dataDir string) (*CertManager, error) {
	cm := &CertManager{dataDir: dataDir}

	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}

	caExists, err := fileExists(cm.caKeyPath())
	if err != nil {
		return nil, fmt.Errorf("check ca key: %w", err)
	}

	if caExists {
		if err := cm.loadCA(); err != nil {
			return nil, fmt.Errorf("load ca: %w", err)
		}
		slog.Info("loaded existing CA", "fingerprint", cm.fingerprint)
	} else {
		if err := cm.generateCA(); err != nil {
			return nil, fmt.Errorf("generate ca: %w", err)
		}
		slog.Info("generated new CA", "fingerprint", cm.fingerprint)
	}

	if err := cm.ensureOnlineCert(); err != nil {
		return nil, fmt.Errorf("online cert: %w", err)
	}

	return cm, nil
}

// Fingerprint returns the base64url-encoded (no padding) SHA-256 hash
// of the full DER-encoded CA certificate, matching SimpleX Chat expectations.
func (cm *CertManager) Fingerprint() string {
	return cm.fingerprint
}

// SMPURI returns the SMP URI string: smp://<fingerprint>@<host>:<port>
func (cm *CertManager) SMPURI(host string, port string) string {
	return fmt.Sprintf("smp://%s@%s:%s", cm.fingerprint, host, port)
}

// TLSConfig returns a tls.Config suitable for the SMP listener.
func (cm *CertManager) TLSConfig() *tls.Config {
	certPool := x509.NewCertPool()
	certPool.AddCert(cm.caCert)

	return &tls.Config{
		Certificates: []tls.Certificate{cm.tlsCert},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"smp/1"},
	}
}

// CACert returns the loaded CA certificate.
func (cm *CertManager) CACert() *x509.Certificate {
	return cm.caCert
}

// --- paths ---

func (cm *CertManager) caKeyPath() string {
	return filepath.Join(cm.dataDir, "ca.key")
}

func (cm *CertManager) caCertPath() string {
	return filepath.Join(cm.dataDir, "ca.pem")
}

func (cm *CertManager) serverKeyPath() string {
	return filepath.Join(cm.dataDir, "server.key")
}

func (cm *CertManager) serverCertPath() string {
	return filepath.Join(cm.dataDir, "server.pem")
}

// --- CA generation and loading ---

func (cm *CertManager) generateCA() error {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate ed25519 key: %w", err)
	}

	serialNumber, err := randomSerial()
	if err != nil {
		return err
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      pkix.Name{CommonName: "GoRelay CA"},
		NotBefore:    time.Now().Add(-1 * time.Minute),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:         true,
		BasicConstraintsValid: true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	if err != nil {
		return fmt.Errorf("create ca cert: %w", err)
	}

	caCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("parse ca cert: %w", err)
	}

	// Write CA private key
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return fmt.Errorf("marshal ca key: %w", err)
	}

	if err := writePEM(cm.caKeyPath(), "PRIVATE KEY", privBytes, 0600); err != nil {
		return fmt.Errorf("write ca key: %w", err)
	}

	// Write CA certificate
	if err := writePEM(cm.caCertPath(), "CERTIFICATE", certDER, 0644); err != nil {
		return fmt.Errorf("write ca cert: %w", err)
	}

	cm.caCert = caCert
	cm.caKey = priv
	cm.fingerprint = computeCertFingerprint(caCert)

	pubKeyHash := computePubKeyFingerprint(pub)
	slog.Info("fingerprint debug", "cert_hash", cm.fingerprint, "pubkey_hash", pubKeyHash)

	return nil
}

func (cm *CertManager) loadCA() error {
	// Load CA private key
	keyPEM, err := os.ReadFile(cm.caKeyPath())
	if err != nil {
		return fmt.Errorf("read ca key: %w", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return fmt.Errorf("decode ca key PEM: no PEM block found")
	}

	parsedKey, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return fmt.Errorf("parse ca key: %w", err)
	}

	edKey, ok := parsedKey.(ed25519.PrivateKey)
	if !ok {
		return fmt.Errorf("ca key is not Ed25519")
	}

	// Load CA certificate
	certPEM, err := os.ReadFile(cm.caCertPath())
	if err != nil {
		return fmt.Errorf("read ca cert: %w", err)
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return fmt.Errorf("decode ca cert PEM: no PEM block found")
	}

	caCert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return fmt.Errorf("parse ca cert: %w", err)
	}

	cm.caCert = caCert
	cm.caKey = edKey
	cm.fingerprint = computeCertFingerprint(caCert)

	pubKeyHash := computePubKeyFingerprint(edKey.Public().(ed25519.PublicKey))
	slog.Info("fingerprint debug", "cert_hash", cm.fingerprint, "pubkey_hash", pubKeyHash)

	return nil
}

// --- Online TLS certificate ---

func (cm *CertManager) ensureOnlineCert() error {
	serverCertExists, err := fileExists(cm.serverCertPath())
	if err != nil {
		return fmt.Errorf("check server cert: %w", err)
	}

	serverKeyExists, err := fileExists(cm.serverKeyPath())
	if err != nil {
		return fmt.Errorf("check server key: %w", err)
	}

	if serverCertExists && serverKeyExists {
		return cm.loadOnlineCert()
	}

	return cm.generateOnlineCert()
}

func (cm *CertManager) generateOnlineCert() error {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate server key: %w", err)
	}

	serialNumber, err := randomSerial()
	if err != nil {
		return err
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      pkix.Name{CommonName: "GoRelay Server"},
		NotBefore:    time.Now().Add(-1 * time.Minute),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, cm.caCert, pub, cm.caKey)
	if err != nil {
		return fmt.Errorf("create server cert: %w", err)
	}

	// Write server private key
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return fmt.Errorf("marshal server key: %w", err)
	}

	if err := writePEM(cm.serverKeyPath(), "PRIVATE KEY", privBytes, 0600); err != nil {
		return fmt.Errorf("write server key: %w", err)
	}

	// Write server certificate
	if err := writePEM(cm.serverCertPath(), "CERTIFICATE", certDER, 0644); err != nil {
		return fmt.Errorf("write server cert: %w", err)
	}

	// Build tls.Certificate with CA chain
	cm.tlsCert = tls.Certificate{
		Certificate: [][]byte{certDER, cm.caCert.Raw},
		PrivateKey:  priv,
	}

	return nil
}

func (cm *CertManager) loadOnlineCert() error {
	// Load server private key
	keyPEM, err := os.ReadFile(cm.serverKeyPath())
	if err != nil {
		return fmt.Errorf("read server key: %w", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return fmt.Errorf("decode server key PEM: no PEM block found")
	}

	parsedKey, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return fmt.Errorf("parse server key: %w", err)
	}

	edKey, ok := parsedKey.(ed25519.PrivateKey)
	if !ok {
		return fmt.Errorf("server key is not Ed25519")
	}

	// Load server certificate
	certPEM, err := os.ReadFile(cm.serverCertPath())
	if err != nil {
		return fmt.Errorf("read server cert: %w", err)
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return fmt.Errorf("decode server cert PEM: no PEM block found")
	}

	cm.tlsCert = tls.Certificate{
		Certificate: [][]byte{certBlock.Bytes, cm.caCert.Raw},
		PrivateKey:  edKey,
	}

	return nil
}

// --- helpers ---

// computeCertFingerprint returns SHA256 of the full DER-encoded certificate,
// base64url-encoded without padding. This matches the SimpleX Chat / SimplexMQ
// fingerprint computation (X509.Validation.Fingerprint.getFingerprint).
func computeCertFingerprint(cert *x509.Certificate) string {
	hash := sha256.Sum256(cert.Raw)
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

// computePubKeyFingerprint returns SHA256 of the raw Ed25519 public key bytes,
// base64url-encoded without padding. Used only for debug logging.
func computePubKeyFingerprint(pub ed25519.PublicKey) string {
	hash := sha256.Sum256([]byte(pub))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

func randomSerial() (*big.Int, error) {
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate serial number: %w", err)
	}
	return serialNumber, nil
}

func writePEM(path string, blockType string, data []byte, perm os.FileMode) error {
	block := &pem.Block{
		Type:  blockType,
		Bytes: data,
	}
	return os.WriteFile(path, pem.EncodeToMemory(block), perm)
}

func fileExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}
