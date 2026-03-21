package smp

import (
	"crypto/ecdh"
	"crypto/rand"
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
	ErrVersionMismatch = errors.New("no mutual SMP version")
	ErrInvalidHello    = errors.New("invalid handshake message")
)

// HandshakeResult holds the outcome of a successful SMP handshake.
type HandshakeResult struct {
	Version      uint16
	SharedSecret []byte
}

// ServerHello is the server's handshake message.
//
// Wire format (inside a 16KB block payload):
//
//	versionMin (2 bytes, uint16 BE)
//	versionMax (2 bytes, uint16 BE)
//	serverPubKey (32 bytes, X25519)
type ServerHello struct {
	VersionMin uint16
	VersionMax uint16
	PubKey     []byte // 32-byte X25519 public key
}

// Encode serializes the ServerHello into bytes.
func (sh *ServerHello) Encode() []byte {
	buf := make([]byte, 4+x25519PubKeySize)
	binary.BigEndian.PutUint16(buf[0:2], sh.VersionMin)
	binary.BigEndian.PutUint16(buf[2:4], sh.VersionMax)
	copy(buf[4:], sh.PubKey)
	return buf
}

// DecodeServerHello parses a ServerHello from bytes.
func DecodeServerHello(data []byte) (*ServerHello, error) {
	if len(data) < 4+x25519PubKeySize {
		return nil, ErrInvalidHello
	}
	return &ServerHello{
		VersionMin: binary.BigEndian.Uint16(data[0:2]),
		VersionMax: binary.BigEndian.Uint16(data[2:4]),
		PubKey:     data[4 : 4+x25519PubKeySize],
	}, nil
}

// ClientHello is the client's handshake response.
//
// Wire format (inside a 16KB block payload):
//
//	version (2 bytes, uint16 BE)
//	clientPubKey (32 bytes, X25519)
type ClientHello struct {
	Version uint16
	PubKey  []byte // 32-byte X25519 public key
}

// Encode serializes the ClientHello into bytes.
func (ch *ClientHello) Encode() []byte {
	buf := make([]byte, 2+x25519PubKeySize)
	binary.BigEndian.PutUint16(buf[0:2], ch.Version)
	copy(buf[2:], ch.PubKey)
	return buf
}

// DecodeClientHello parses a ClientHello from bytes.
func DecodeClientHello(data []byte) (*ClientHello, error) {
	if len(data) < 2+x25519PubKeySize {
		return nil, ErrInvalidHello
	}
	return &ClientHello{
		Version: binary.BigEndian.Uint16(data[0:2]),
		PubKey:  data[2 : 2+x25519PubKeySize],
	}, nil
}

// ServerHandshake performs the server side of the SMP handshake.
// It generates an ephemeral X25519 keypair, sends ServerHello,
// reads ClientHello, negotiates the version, computes the shared secret,
// and zeroes the private key.
func ServerHandshake(conn net.Conn) (*HandshakeResult, error) {
	privKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate server DH key: %w", err)
	}

	// Send ServerHello
	hello := &ServerHello{
		VersionMin: SMPVersionMin,
		VersionMax: SMPVersionMax,
		PubKey:     privKey.PublicKey().Bytes(),
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

	// Negotiate version
	version, err := negotiateVersion(SMPVersionMin, SMPVersionMax, clientHello.Version)
	if err != nil {
		zeroECDHKey(privKey)
		return nil, err
	}

	// Compute shared secret
	peerKey, err := ecdh.X25519().NewPublicKey(clientHello.PubKey)
	if err != nil {
		zeroECDHKey(privKey)
		return nil, fmt.Errorf("parse client public key: %w", err)
	}

	secret, err := privKey.ECDH(peerKey)
	if err != nil {
		zeroECDHKey(privKey)
		return nil, fmt.Errorf("compute shared secret: %w", err)
	}

	zeroECDHKey(privKey)

	return &HandshakeResult{
		Version:      version,
		SharedSecret: secret,
	}, nil
}

// ClientHandshake performs the client side of the SMP handshake.
// It reads ServerHello, chooses the highest mutual version,
// generates an ephemeral X25519 keypair, sends ClientHello,
// computes the shared secret, and zeroes the private key.
func ClientHandshake(conn net.Conn, clientMin, clientMax uint16) (*HandshakeResult, error) {
	// Read ServerHello
	payload, err := common.ReadBlock(conn)
	if err != nil {
		return nil, fmt.Errorf("read server hello: %w", err)
	}

	serverHello, err := DecodeServerHello(payload)
	if err != nil {
		return nil, fmt.Errorf("decode server hello: %w", err)
	}

	// Choose version: highest mutual
	version, err := negotiateClientVersion(serverHello.VersionMin, serverHello.VersionMax, clientMin, clientMax)
	if err != nil {
		return nil, err
	}

	// Generate ephemeral keypair
	privKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate client DH key: %w", err)
	}

	// Send ClientHello
	ch := &ClientHello{
		Version: version,
		PubKey:  privKey.PublicKey().Bytes(),
	}

	if err := common.WriteBlock(conn, ch.Encode()); err != nil {
		zeroECDHKey(privKey)
		return nil, fmt.Errorf("write client hello: %w", err)
	}

	// Compute shared secret
	peerKey, err := ecdh.X25519().NewPublicKey(serverHello.PubKey)
	if err != nil {
		zeroECDHKey(privKey)
		return nil, fmt.Errorf("parse server public key: %w", err)
	}

	secret, err := privKey.ECDH(peerKey)
	if err != nil {
		zeroECDHKey(privKey)
		return nil, fmt.Errorf("compute shared secret: %w", err)
	}

	zeroECDHKey(privKey)

	return &HandshakeResult{
		Version:      version,
		SharedSecret: secret,
	}, nil
}

// negotiateVersion validates a client's chosen version against the server range.
func negotiateVersion(serverMin, serverMax, clientVersion uint16) (uint16, error) {
	if clientVersion < serverMin || clientVersion > serverMax {
		return 0, ErrVersionMismatch
	}
	return clientVersion, nil
}

// negotiateClientVersion picks the highest mutual version between client and server ranges.
func negotiateClientVersion(serverMin, serverMax, clientMin, clientMax uint16) (uint16, error) {
	// Overlap: max of mins to min of maxes
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

// zeroECDHKey overwrites the private key bytes. The ecdh.PrivateKey stores
// the scalar in its Bytes() return. We request the bytes, zero them, and
// discard the key reference so it becomes eligible for GC.
func zeroECDHKey(key *ecdh.PrivateKey) {
	b := key.Bytes()
	for i := range b {
		b[i] = 0
	}
}
