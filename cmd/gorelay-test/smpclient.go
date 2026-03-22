package main

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/saschadaemgen/GoRelay/internal/protocol/common"
	"github.com/saschadaemgen/GoRelay/internal/protocol/smp"
)

// SMPClient wraps a TLS connection to an SMP server with block-level I/O.
type SMPClient struct {
	conn      net.Conn
	sessionID []byte // TLS channel binding for signature computation
	verbose   bool
}

// ConnectSMP establishes a TLS connection, performs the SMP handshake,
// and returns an SMPClient ready for command exchange.
func ConnectSMP(addr string, skipVerify bool, verbose bool) (*SMPClient, error) {
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 10 * time.Second},
		"tcp",
		addr,
		&tls.Config{
			InsecureSkipVerify: skipVerify,
			NextProtos:         []string{"smp/1"},
			MinVersion:         tls.VersionTLS12,
			MaxVersion:         tls.VersionTLS12,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("TLS dial: %w", err)
	}

	state := conn.ConnectionState()
	if verbose {
		fmt.Printf("  TLS connected to %s (ALPN: %s)\n", addr, state.NegotiatedProtocol)
	}

	// Derive CA fingerprint from TLS peer certificate chain.
	caFingerprint := ""
	if len(state.PeerCertificates) >= 2 {
		caFingerprint = smp.ComputeCAFingerprint(state.PeerCertificates[1])
	} else if len(state.PeerCertificates) >= 1 {
		caFingerprint = smp.ComputeCAFingerprint(state.PeerCertificates[0])
	}

	params := smp.ClientHandshakeParams{
		CAFingerprint: caFingerprint,
		SessionID:     state.TLSUnique,
		VersionMin:    smp.SMPVersionMin,
		VersionMax:    smp.SMPVersionMax,
	}

	result, err := smp.ClientHandshake(conn, params)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("SMP handshake: %w", err)
	}

	if verbose {
		fmt.Printf("  SMP handshake OK (version %d)\n", result.Version)
	}

	return &SMPClient{conn: conn, sessionID: state.TLSUnique, verbose: verbose}, nil
}

// Close closes the underlying connection.
func (c *SMPClient) Close() error {
	return c.conn.Close()
}

// SendPING sends a PING and returns the parsed PONG response.
func (c *SMPClient) SendPING() (common.Command, error) {
	var corrID [24]byte
	if _, err := rand.Read(corrID[:]); err != nil {
		return common.Command{}, fmt.Errorf("generate corrID: %w", err)
	}

	t := common.BuildTransmission(nil, corrID, nil, common.TagPING, nil)
	block := common.WrapTransmissionBlock(t)
	if err := c.writeBlock(block); err != nil {
		return common.Command{}, err
	}

	return c.readResponse()
}

// SendNEW creates a queue and returns (recipientID, senderID, dhPubKey).
func (c *SMPClient) SendNEW(recipientPub ed25519.PublicKey) (recipientID, senderID [24]byte, dhPubKey []byte, err error) {
	var corrID [24]byte
	if _, err = rand.Read(corrID[:]); err != nil {
		return
	}

	// Build NEW body for v7: authKey(shortString SPKI) + dhKey(shortString SPKI) + subscribeMode("S")
	// v7 does not include basicAuth or sndSecure
	authKeySPKI := smp.EncodeEd25519SPKI(recipientPub)
	// Generate ephemeral X25519 DH key
	dhPriv, dhGenErr := ecdh.X25519().GenerateKey(rand.Reader)
	if dhGenErr != nil {
		err = fmt.Errorf("generate DH key: %w", dhGenErr)
		return
	}
	dhKeySPKI := smp.EncodeX25519SPKI(dhPriv.PublicKey().Bytes())

	body := make([]byte, 0, 2+len(authKeySPKI)+len(dhKeySPKI)+1)
	body = append(body, byte(len(authKeySPKI)))
	body = append(body, authKeySPKI...)
	body = append(body, byte(len(dhKeySPKI)))
	body = append(body, dhKeySPKI...)
	body = append(body, 'S') // subscribeMode only for v7

	t := common.BuildTransmission(nil, corrID, nil, common.TagNEW, body)
	block := common.WrapTransmissionBlock(t)
	if err = c.writeBlock(block); err != nil {
		return
	}

	resp, err := c.readResponseRaw()
	if err != nil {
		return
	}

	cmd := parseResponseRaw(resp)
	if cmd.Type == common.CmdERR {
		err = fmt.Errorf("server returned ERR (code=0x%02x)", errorCode(cmd))
		return
	}
	if cmd.Type != common.CmdIDS {
		err = fmt.Errorf("expected IDS (0x%02x), got 0x%02x", common.CmdIDS, cmd.Type)
		return
	}

	// Parse IDS body: recipientId(shortString) + senderId(shortString) + dhKey(shortString) + sndSecure
	idsBody := cmd.Body
	off := 0

	// recipientId
	if off >= len(idsBody) {
		err = fmt.Errorf("IDS body too short")
		return
	}
	rLen := int(idsBody[off])
	off++
	if off+rLen > len(idsBody) || rLen < 24 {
		err = fmt.Errorf("IDS recipientId invalid")
		return
	}
	copy(recipientID[:], idsBody[off:off+24])
	off += rLen

	// senderId
	if off >= len(idsBody) {
		err = fmt.Errorf("IDS body too short for senderId")
		return
	}
	sLen := int(idsBody[off])
	off++
	if off+sLen > len(idsBody) || sLen < 24 {
		err = fmt.Errorf("IDS senderId invalid")
		return
	}
	copy(senderID[:], idsBody[off:off+24])
	off += sLen

	// srvDhPublicKey = shortString(SPKI)
	if off >= len(idsBody) {
		err = fmt.Errorf("IDS body too short for dhKey")
		return
	}
	dhLen := int(idsBody[off])
	off++
	if off+dhLen > len(idsBody) {
		err = fmt.Errorf("IDS dhKey invalid")
		return
	}
	dhSPKI := idsBody[off : off+dhLen]

	rawDH, parseErr := smp.ParseX25519SPKI(dhSPKI)
	if parseErr != nil {
		err = fmt.Errorf("parse DH SPKI: %w", parseErr)
		return
	}
	dhPubKey = rawDH
	return
}

// SendKEY sets the sender key for a queue.
// KEY is a recipient command - entityID = recipientID.
func (c *SMPClient) SendKEY(recipientID [24]byte, senderPub ed25519.PublicKey) error {
	var corrID [24]byte
	if _, err := rand.Read(corrID[:]); err != nil {
		return fmt.Errorf("generate corrID: %w", err)
	}

	keySPKI := smp.EncodeEd25519SPKI(senderPub)
	body := make([]byte, 0, 1+len(keySPKI))
	body = append(body, byte(len(keySPKI)))
	body = append(body, keySPKI...)

	t := common.BuildTransmission(nil, corrID, recipientID[:], common.TagKEY, body)
	block := common.WrapTransmissionBlock(t)
	if err := c.writeBlock(block); err != nil {
		return err
	}

	cmd, err := c.readResponse()
	if err != nil {
		return err
	}
	if cmd.Type == common.CmdERR {
		return fmt.Errorf("KEY returned ERR (code=0x%02x)", errorCode(cmd))
	}
	if cmd.Type != common.CmdOK {
		return fmt.Errorf("KEY: expected OK, got 0x%02x", cmd.Type)
	}
	return nil
}

// SendSEND sends a signed message to a queue. Returns nil on OK.
func (c *SMPClient) SendSEND(senderID [24]byte, privKey ed25519.PrivateKey, msg []byte) error {
	var corrID [24]byte
	if _, err := rand.Read(corrID[:]); err != nil {
		return fmt.Errorf("generate corrID: %w", err)
	}

	// Sign: shortString(sessionID) + corrId + entityId + "SEND " + msg
	signedData := common.BuildSignedData(c.sessionID, corrID, senderID[:], common.TagSEND, msg)
	sig := ed25519.Sign(privKey, signedData)

	t := common.BuildTransmission(sig, corrID, senderID[:], common.TagSEND, msg)
	block := common.WrapTransmissionBlock(t)
	if err := c.writeBlock(block); err != nil {
		return err
	}

	cmd, err := c.readResponse()
	if err != nil {
		return err
	}
	if cmd.Type == common.CmdERR {
		return fmt.Errorf("SEND returned ERR (code=0x%02x)", errorCode(cmd))
	}
	if cmd.Type != common.CmdOK {
		return fmt.Errorf("SEND: expected OK, got 0x%02x", cmd.Type)
	}
	return nil
}

// SendSUB subscribes to a queue with a signed SUB command.
func (c *SMPClient) SendSUB(recipientID [24]byte, privKey ed25519.PrivateKey) error {
	var corrID [24]byte
	if _, err := rand.Read(corrID[:]); err != nil {
		return fmt.Errorf("generate corrID: %w", err)
	}

	// Sign with sessionID
	signedData := common.BuildSignedData(c.sessionID, corrID, recipientID[:], common.TagSUB, nil)
	sig := ed25519.Sign(privKey, signedData)

	t := common.BuildTransmission(sig, corrID, recipientID[:], common.TagSUB, nil)
	block := common.WrapTransmissionBlock(t)
	if err := c.writeBlock(block); err != nil {
		return err
	}
	return nil
}

// SendACK acknowledges a message.
func (c *SMPClient) SendACK(recipientID, msgID [24]byte) error {
	var corrID [24]byte
	if _, err := rand.Read(corrID[:]); err != nil {
		return fmt.Errorf("generate corrID: %w", err)
	}

	body := make([]byte, 0, 25)
	body = append(body, 24) // shortString length
	body = append(body, msgID[:]...)

	t := common.BuildTransmission(nil, corrID, recipientID[:], common.TagACK, body)
	block := common.WrapTransmissionBlock(t)
	if err := c.writeBlock(block); err != nil {
		return err
	}

	cmd, err := c.readResponse()
	if err != nil {
		return err
	}
	if cmd.Type == common.CmdERR {
		return fmt.Errorf("ACK returned ERR (code=0x%02x)", errorCode(cmd))
	}
	if cmd.Type != common.CmdOK {
		return fmt.Errorf("ACK: expected OK, got 0x%02x", cmd.Type)
	}
	return nil
}

// ReadMSG reads a raw block and parses it as a MSG response.
func (c *SMPClient) ReadMSG() (msgID [24]byte, timestamp uint64, flags byte, body []byte, err error) {
	resp, err := c.readResponseRaw()
	if err != nil {
		return
	}
	cmd := parseResponseRaw(resp)
	if cmd.Type == common.CmdERR {
		err = fmt.Errorf("expected MSG, got ERR (code=0x%02x)", errorCode(cmd))
		return
	}
	if cmd.Type == common.CmdOK {
		err = fmt.Errorf("expected MSG, got OK (no pending messages)")
		return
	}
	if cmd.Type != common.CmdMSG {
		err = fmt.Errorf("expected MSG (0x%02x), got 0x%02x", common.CmdMSG, cmd.Type)
		return
	}
	// MSG body: shortString(msgId) + encryptedRcvMsgBody
	// The body is NaCl secretbox encrypted; timestamp and flags are inside the ciphertext.
	mBody := cmd.Body
	if len(mBody) < 1 {
		err = fmt.Errorf("MSG body too short")
		return
	}
	mIDLen := int(mBody[0])
	if 1+mIDLen > len(mBody) || mIDLen < 24 {
		err = fmt.Errorf("MSG body invalid: len=%d mIDLen=%d", len(mBody), mIDLen)
		return
	}
	copy(msgID[:], mBody[1:1+24])
	// Body is the encrypted blob (cannot decrypt without shared key)
	body = mBody[1+mIDLen:]
	// timestamp and flags are inside the encrypted body, set to 0
	timestamp = 0
	flags = 0
	return
}

// ReadAnyResponse reads the next response block and returns the parsed command.
func (c *SMPClient) ReadAnyResponse() (common.Command, error) {
	return c.readResponse()
}

// --- internal helpers ---

func (c *SMPClient) writeBlock(block [common.BlockSize]byte) error {
	c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	_, err := c.conn.Write(block[:])
	return err
}

func (c *SMPClient) readResponseRaw() ([common.BlockSize]byte, error) {
	var block [common.BlockSize]byte
	c.conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	_, err := io.ReadFull(c.conn, block[:])
	return block, err
}

func (c *SMPClient) readResponse() (common.Command, error) {
	block, err := c.readResponseRaw()
	if err != nil {
		return common.Command{}, fmt.Errorf("read block: %w", err)
	}
	return parseResponseRaw(block), nil
}

func parseResponseRaw(block [common.BlockSize]byte) common.Command {
	payloadLen := binary.BigEndian.Uint16(block[:2])
	payload := block[2 : 2+payloadLen]
	cmds, err := common.ParsePayload(payload)
	if err != nil || len(cmds) == 0 {
		return common.Command{Type: 0xFF} // sentinel for parse error
	}
	return cmds[0]
}

func errorCode(cmd common.Command) byte {
	if len(cmd.Body) > 0 {
		return cmd.Body[0]
	}
	return 0
}

// --- formatting ---

func hexID(id [24]byte) string {
	return hex.EncodeToString(id[:])
}

func cmdName(b byte) string {
	names := map[byte]string{
		common.CmdNEW:  "NEW",
		common.CmdIDS:  "IDS",
		common.CmdSUB:  "SUB",
		common.CmdKEY:  "KEY",
		common.CmdSKEY: "SKEY",
		common.CmdSEND: "SEND",
		common.CmdMSG:  "MSG",
		common.CmdACK:  "ACK",
		common.CmdOFF:  "OFF",
		common.CmdDEL:  "DEL",
		common.CmdOK:   "OK",
		common.CmdERR:  "ERR",
		common.CmdPING: "PING",
		common.CmdPONG: "PONG",
		common.CmdEND:  "END",
	}
	if n, ok := names[b]; ok {
		return n
	}
	return fmt.Sprintf("0x%02x", b)
}
