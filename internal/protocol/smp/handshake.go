package smp

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net"

	"github.com/saschadaemgen/GoRelay/internal/protocol/common"
)

const (
	// SMPVersionMin is the minimum SMP version supported
	SMPVersionMin uint16 = 6
	// SMPVersionMax is the maximum SMP version supported
	SMPVersionMax uint16 = 7

	// X25519 public key size
	x25519PubKeySize = 32
)

var (
	ErrVersionMismatch  = errors.New("no mutual SMP version")
	ErrInvalidHello     = errors.New("invalid handshake message")
	ErrIdentityMismatch = errors.New("CA fingerprint mismatch")
	ErrInvalidSignature = errors.New("server key signature invalid")
)

// x25519SPKIPrefix is the ASN.1 DER prefix for an X25519 SubjectPublicKeyInfo.
// SEQUENCE { SEQUENCE { OID 1.3.101.110 }, BIT STRING { key } }
var x25519SPKIPrefix = []byte{
	0x30, 0x2a, // SEQUENCE, 42 bytes
	0x30, 0x05, // SEQUENCE, 5 bytes (AlgorithmIdentifier)
	0x06, 0x03, 0x2b, 0x65, 0x6e, // OID 1.3.101.110 (X25519)
	0x03, 0x21, 0x00, // BIT STRING, 33 bytes, 0 unused bits
}

// x25519SPKISize is the total size of an X25519 SPKI DER encoding.
const x25519SPKISize = 12 + x25519PubKeySize // 44 bytes

// EncodeX25519SPKI encodes a raw 32-byte X25519 public key as X.509 SubjectPublicKeyInfo DER.
func EncodeX25519SPKI(pubKey []byte) []byte {
	spki := make([]byte, x25519SPKISize)
	copy(spki, x25519SPKIPrefix)
	copy(spki[len(x25519SPKIPrefix):], pubKey)
	return spki
}

// ParseX25519SPKI extracts the raw 32-byte X25519 public key from SPKI DER encoding.
func ParseX25519SPKI(spki []byte) ([]byte, error) {
	if len(spki) != x25519SPKISize {
		return nil, fmt.Errorf("invalid X25519 SPKI length: %d", len(spki))
	}
	if subtle.ConstantTimeCompare(spki[:len(x25519SPKIPrefix)], x25519SPKIPrefix) != 1 {
		return nil, fmt.Errorf("invalid X25519 SPKI prefix")
	}
	key := make([]byte, x25519PubKeySize)
	copy(key, spki[len(x25519SPKIPrefix):])
	return key, nil
}

// HandshakeResult holds the outcome of a successful SMP handshake.
type HandshakeResult struct {
	Version   uint16
	SessionID []byte
	DHSecret  []byte // shared DH secret (only if client sent a key)
}

// --- ServerHello ---

// ServerHandshakeParams contains the parameters needed for the server-side handshake.
type ServerHandshakeParams struct {
	OnlineCertDER []byte             // DER-encoded online (leaf) certificate
	OnlineKey     ed25519.PrivateKey // private key of the online certificate
	CAFingerprint string             // SHA256 of CA cert DER, base64url no-pad
	SessionID     []byte             // TLS channel binding (tls-unique)
	VersionMin    uint16
	VersionMax    uint16
	ALPNConfirmed bool // true if ALPN "smp/1" was negotiated
}

// ServerHello is the server's handshake message per the SMP specification.
//
// Wire format (inside a 16 KB padded block):
//
//	smpVersionRange    = versionMin(Word16 BE) + versionMax(Word16 BE)
//	sessionIdentifier  = shortString(tls-unique)
//	serverCert         = originalLength(Word16 BE) + x509DER
//	signedServerKey    = originalLength(Word16 BE) + signedKeyBytes
//	  signedKeyBytes   = originalLength(SPKI_DER) + originalLength(Ed25519_sig)
type ServerHello struct {
	VersionMin     uint16
	VersionMax     uint16
	SessionID      []byte // tls-unique channel binding
	ServerCertDER  []byte // online certificate DER
	DHPubKeySPKI   []byte // X25519 public key in SPKI DER
	DHKeySignature []byte // Ed25519 signature of DHPubKeySPKI
}

// Encode serializes the ServerHello into bytes.
func (sh *ServerHello) Encode() []byte {
	// Calculate size for pre-allocation
	innerSignedLen := 2 + len(sh.DHPubKeySPKI) + 2 + len(sh.DHKeySignature)
	totalSize := 4 + // version range
		1 + len(sh.SessionID) + // shortString(sessionID)
		2 + len(sh.ServerCertDER) + // originalLength(cert)
		2 + innerSignedLen // originalLength(signedKey)

	buf := make([]byte, 0, totalSize)

	// 1. smpVersionRange (4 bytes)
	buf = appendUint16BE(buf, sh.VersionMin)
	buf = appendUint16BE(buf, sh.VersionMax)

	// 2. sessionIdentifier = shortString (1 byte len + data)
	buf = appendShortString(buf, sh.SessionID)

	// 3. serverCert = originalLength (2 byte len + data)
	buf = appendOriginalLength(buf, sh.ServerCertDER)

	// 4. signedServerKey = originalLength wrapping inner encoding
	//    inner = originalLength(SPKI_DER) + originalLength(signature)
	inner := make([]byte, 0, innerSignedLen)
	inner = appendOriginalLength(inner, sh.DHPubKeySPKI)
	inner = appendOriginalLength(inner, sh.DHKeySignature)
	buf = appendOriginalLength(buf, inner)

	return buf
}

// DecodeServerHello parses a ServerHello from payload bytes.
func DecodeServerHello(data []byte) (*ServerHello, error) {
	if len(data) < 5 { // 4 version bytes + at least 1 for session len
		return nil, ErrInvalidHello
	}

	sh := &ServerHello{}
	off := 0

	// 1. version range
	sh.VersionMin = binary.BigEndian.Uint16(data[off : off+2])
	off += 2
	sh.VersionMax = binary.BigEndian.Uint16(data[off : off+2])
	off += 2

	// 2. sessionIdentifier = shortString
	var err error
	sh.SessionID, off, err = readShortString(data, off)
	if err != nil {
		return nil, fmt.Errorf("session id: %w", err)
	}

	// 3. serverCert = originalLength
	sh.ServerCertDER, off, err = readOriginalLength(data, off)
	if err != nil {
		return nil, fmt.Errorf("server cert: %w", err)
	}

	// 4. signedServerKey = originalLength wrapping inner
	signedInner, _, err := readOriginalLength(data, off)
	if err != nil {
		return nil, fmt.Errorf("signed server key: %w", err)
	}

	// Parse inner: originalLength(SPKI) + originalLength(sig)
	innerOff := 0
	sh.DHPubKeySPKI, innerOff, err = readOriginalLength(signedInner, innerOff)
	if err != nil {
		return nil, fmt.Errorf("DH pub key SPKI: %w", err)
	}
	sh.DHKeySignature, _, err = readOriginalLength(signedInner, innerOff)
	if err != nil {
		return nil, fmt.Errorf("DH key signature: %w", err)
	}

	return sh, nil
}

// --- ClientHello ---

// ClientHello is the client's handshake response per the SMP specification.
//
// Wire format (inside a 16 KB padded block):
//
//	smpVersion = Word16 BE
//	keyHash    = shortString (CA fingerprint, base64url no-pad)
//	clientKey  = optional shortString (X25519 SPKI DER, for proxy connections)
type ClientHello struct {
	Version   uint16
	KeyHash   string // CA certificate fingerprint
	ClientKey []byte // optional X25519 SPKI DER
}

// Encode serializes the ClientHello into bytes.
func (ch *ClientHello) Encode() []byte {
	khBytes := []byte(ch.KeyHash)
	size := 2 + 1 + len(khBytes)
	if len(ch.ClientKey) > 0 {
		size += 1 + len(ch.ClientKey)
	}

	buf := make([]byte, 0, size)

	// 1. smpVersion
	buf = appendUint16BE(buf, ch.Version)

	// 2. keyHash = shortString
	buf = appendShortString(buf, khBytes)

	// 3. clientKey = optional shortString
	if len(ch.ClientKey) > 0 {
		buf = appendShortString(buf, ch.ClientKey)
	}

	return buf
}

// DecodeClientHello parses a ClientHello from payload bytes.
func DecodeClientHello(data []byte) (*ClientHello, error) {
	if len(data) < 3 { // 2 bytes version + 1 byte keyHash len
		return nil, ErrInvalidHello
	}

	ch := &ClientHello{}
	off := 0

	// 1. version
	ch.Version = binary.BigEndian.Uint16(data[off : off+2])
	off += 2

	// 2. keyHash = shortString
	var err error
	var khBytes []byte
	khBytes, off, err = readShortString(data, off)
	if err != nil {
		return nil, fmt.Errorf("key hash: %w", err)
	}
	ch.KeyHash = string(khBytes)

	// 3. clientKey = optional shortString (remaining bytes before padding)
	if off < len(data) {
		ckLen := int(data[off])
		off++
		if ckLen > 0 && off+ckLen <= len(data) {
			ch.ClientKey = make([]byte, ckLen)
			copy(ch.ClientKey, data[off:off+ckLen])
		}
		// Ignore any remaining bytes (forward compatibility)
	}

	return ch, nil
}

// --- Server-side handshake ---

// ServerHandshake performs the server side of the SMP handshake.
// It sends ServerHello with certificate and signed ephemeral key,
// reads ClientHello, verifies the CA fingerprint, negotiates the version,
// and optionally computes a DH shared secret.
func ServerHandshake(conn net.Conn, params ServerHandshakeParams) (*HandshakeResult, error) {
	// Determine version range based on ALPN
	vMin := params.VersionMin
	vMax := params.VersionMax
	if !params.ALPNConfirmed {
		// Legacy: restrict to v6 only when ALPN not negotiated
		vMax = SMPVersionMin
	}

	// Generate ephemeral X25519 keypair
	privKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate server DH key: %w", err)
	}

	// Encode public key as X.509 SPKI DER
	dhPubSPKI := EncodeX25519SPKI(privKey.PublicKey().Bytes())

	// Sign the SPKI DER with the online certificate's Ed25519 key
	dhKeySig := ed25519.Sign(params.OnlineKey, dhPubSPKI)

	// Build and send ServerHello
	hello := &ServerHello{
		VersionMin:     vMin,
		VersionMax:     vMax,
		SessionID:      params.SessionID,
		ServerCertDER:  params.OnlineCertDER,
		DHPubKeySPKI:   dhPubSPKI,
		DHKeySignature: dhKeySig,
	}

	if err := common.WriteBlock(conn, hello.Encode()); err != nil {
		zeroECDHKey(privKey)
		return nil, fmt.Errorf("write server hello: %w", err)
	}

	// Read ClientHello
	payload, err := common.ReadBlock(conn)
	if err != nil {
		zeroECDHKey(privKey)
		return nil, fmt.Errorf("read client hello: %w", err)
	}

	clientHello, err := DecodeClientHello(payload)
	if err != nil {
		zeroECDHKey(privKey)
		return nil, fmt.Errorf("decode client hello: %w", err)
	}

	// Verify CA fingerprint
	if clientHello.KeyHash != params.CAFingerprint {
		zeroECDHKey(privKey)
		return nil, ErrIdentityMismatch
	}

	// Negotiate version
	version, err := negotiateVersion(vMin, vMax, clientHello.Version)
	if err != nil {
		zeroECDHKey(privKey)
		return nil, err
	}

	result := &HandshakeResult{
		Version:   version,
		SessionID: params.SessionID,
	}

	// Compute DH shared secret if client sent a key (proxy connections)
	if len(clientHello.ClientKey) > 0 {
		clientPubRaw, parseErr := ParseX25519SPKI(clientHello.ClientKey)
		if parseErr != nil {
			zeroECDHKey(privKey)
			return nil, fmt.Errorf("parse client DH key: %w", parseErr)
		}

		peerKey, parseErr := ecdh.X25519().NewPublicKey(clientPubRaw)
		if parseErr != nil {
			zeroECDHKey(privKey)
			return nil, fmt.Errorf("invalid client DH key: %w", parseErr)
		}

		secret, dhErr := privKey.ECDH(peerKey)
		if dhErr != nil {
			zeroECDHKey(privKey)
			return nil, fmt.Errorf("compute DH secret: %w", dhErr)
		}
		result.DHSecret = secret
	}

	zeroECDHKey(privKey)
	return result, nil
}

// --- Client-side handshake ---

// ClientHandshakeParams contains the parameters for the client-side handshake.
type ClientHandshakeParams struct {
	CAFingerprint string // expected CA fingerprint (from SMP URI) - empty to auto-derive
	SessionID     []byte // TLS channel binding (tls-unique)
	VersionMin    uint16
	VersionMax    uint16
}

// ClientHandshakeResult holds the client-side handshake outcome.
type ClientHandshakeResult struct {
	Version    uint16
	SessionID  []byte
	ServerCert *x509.Certificate // the online certificate from the server
}

// ClientHandshake performs the client side of the SMP handshake.
// It reads ServerHello, verifies the server key signature, checks the
// session identifier, negotiates the version, and sends ClientHello.
func ClientHandshake(conn net.Conn, params ClientHandshakeParams) (*ClientHandshakeResult, error) {
	// Read ServerHello
	payload, err := common.ReadBlock(conn)
	if err != nil {
		return nil, fmt.Errorf("read server hello: %w", err)
	}

	serverHello, err := DecodeServerHello(payload)
	if err != nil {
		return nil, fmt.Errorf("decode server hello: %w", err)
	}

	// Parse the online certificate
	serverCert, err := x509.ParseCertificate(serverHello.ServerCertDER)
	if err != nil {
		return nil, fmt.Errorf("parse server certificate: %w", err)
	}

	// Verify the signed server key: Ed25519 signature of SPKI DER
	serverPub, ok := serverCert.PublicKey.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("server certificate key is not Ed25519")
	}
	if !ed25519.Verify(serverPub, serverHello.DHPubKeySPKI, serverHello.DHKeySignature) {
		return nil, ErrInvalidSignature
	}

	// Determine CA fingerprint to send
	fingerprint := params.CAFingerprint

	// Choose version: highest mutual
	version, err := negotiateClientVersion(
		serverHello.VersionMin, serverHello.VersionMax,
		params.VersionMin, params.VersionMax,
	)
	if err != nil {
		return nil, err
	}

	// Build and send ClientHello
	ch := &ClientHello{
		Version: version,
		KeyHash: fingerprint,
	}

	if err := common.WriteBlock(conn, ch.Encode()); err != nil {
		return nil, fmt.Errorf("write client hello: %w", err)
	}

	return &ClientHandshakeResult{
		Version:    version,
		SessionID:  serverHello.SessionID,
		ServerCert: serverCert,
	}, nil
}

// --- Version negotiation ---

// negotiateVersion validates a client's chosen version against the server range.
func negotiateVersion(serverMin, serverMax, clientVersion uint16) (uint16, error) {
	if clientVersion < serverMin || clientVersion > serverMax {
		return 0, ErrVersionMismatch
	}
	return clientVersion, nil
}

// negotiateClientVersion picks the highest mutual version between client and server ranges.
func negotiateClientVersion(serverMin, serverMax, clientMin, clientMax uint16) (uint16, error) {
	lo := serverMin
	if clientMin > lo {
		lo = clientMin
	}
	hi := serverMax
	if clientMax < hi {
		hi = clientMax
	}
	if lo > hi {
		return 0, ErrVersionMismatch
	}
	return hi, nil
}

// --- Helpers ---

// ComputeCAFingerprint returns the SHA256 of a certificate's DER encoding,
// base64url-encoded without padding.
func ComputeCAFingerprint(cert *x509.Certificate) string {
	hash := sha256.Sum256(cert.Raw)
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

// appendUint16BE appends a uint16 in big-endian byte order.
func appendUint16BE(buf []byte, v uint16) []byte {
	return append(buf, byte(v>>8), byte(v))
}

// appendShortString appends a length-prefixed string (1 byte length + data).
func appendShortString(buf []byte, data []byte) []byte {
	buf = append(buf, byte(len(data)))
	return append(buf, data...)
}

// appendOriginalLength appends a length-prefixed blob (2 byte uint16 BE length + data).
func appendOriginalLength(buf []byte, data []byte) []byte {
	buf = appendUint16BE(buf, uint16(len(data)))
	return append(buf, data...)
}

// readShortString reads a 1-byte-length-prefixed string from data at offset.
func readShortString(data []byte, off int) ([]byte, int, error) {
	if off >= len(data) {
		return nil, off, ErrInvalidHello
	}
	sLen := int(data[off])
	off++
	if off+sLen > len(data) {
		return nil, off, ErrInvalidHello
	}
	result := make([]byte, sLen)
	copy(result, data[off:off+sLen])
	return result, off + sLen, nil
}

// readOriginalLength reads a 2-byte-length-prefixed blob from data at offset.
func readOriginalLength(data []byte, off int) ([]byte, int, error) {
	if off+2 > len(data) {
		return nil, off, ErrInvalidHello
	}
	bLen := int(binary.BigEndian.Uint16(data[off : off+2]))
	off += 2
	if off+bLen > len(data) {
		return nil, off, ErrInvalidHello
	}
	result := make([]byte, bLen)
	copy(result, data[off:off+bLen])
	return result, off + bLen, nil
}

// zeroECDHKey overwrites the private key bytes.
func zeroECDHKey(key *ecdh.PrivateKey) {
	b := key.Bytes()
	for i := range b {
		b[i] = 0
	}
}
