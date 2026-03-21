package main

import (
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
	conn    net.Conn
	verbose bool
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
		},
	)
	if err != nil {
		return nil, fmt.Errorf("TLS dial: %w", err)
	}

	if verbose {
		fmt.Printf("  TLS connected to %s (ALPN: %s)\n", addr, conn.ConnectionState().NegotiatedProtocol)
	}

	result, err := smp.ClientHandshake(conn, smp.SMPVersionMin, smp.SMPVersionMax)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("SMP handshake: %w", err)
	}

	if verbose {
		fmt.Printf("  SMP handshake OK (version %d)\n", result.Version)
	}

	// Zero shared secret - not needed for this tool
	for i := range result.SharedSecret {
		result.SharedSecret[i] = 0
	}

	return &SMPClient{conn: conn, verbose: verbose}, nil
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

	block := buildPINGBlockCli(corrID)
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

	block := buildNEWBlockCli(corrID, recipientPub)
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

	body := cmd.Body
	if len(body) < 80 {
		err = fmt.Errorf("IDS body too short: %d bytes", len(body))
		return
	}
	copy(recipientID[:], body[0:24])
	copy(senderID[:], body[24:48])
	dhPubKey = make([]byte, 32)
	copy(dhPubKey, body[48:80])
	return
}

// SendKEY sets the sender key for a queue.
func (c *SMPClient) SendKEY(senderID [24]byte, senderPub ed25519.PublicKey) error {
	var corrID [24]byte
	if _, err := rand.Read(corrID[:]); err != nil {
		return fmt.Errorf("generate corrID: %w", err)
	}

	block := buildKEYBlockCli(corrID, senderID, senderPub)
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

	block := buildSignedSENDBlockCli(corrID, senderID, privKey, msg)
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

	block := buildSUBBlockCli(corrID, recipientID, privKey)
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

	block := buildACKBlockCli(corrID, recipientID, msgID)
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
// Returns msgID, timestamp, flags, body.
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
	if len(cmd.Body) < 33 {
		err = fmt.Errorf("MSG body too short: %d", len(cmd.Body))
		return
	}
	copy(msgID[:], cmd.Body[0:24])
	timestamp = uint64(cmd.Body[24])<<56 | uint64(cmd.Body[25])<<48 |
		uint64(cmd.Body[26])<<40 | uint64(cmd.Body[27])<<32 |
		uint64(cmd.Body[28])<<24 | uint64(cmd.Body[29])<<16 |
		uint64(cmd.Body[30])<<8 | uint64(cmd.Body[31])
	flags = cmd.Body[32]
	body = cmd.Body[33:]
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

// --- block builders (mirrors test helpers but non-test) ---

func wrapTransmission(transmission []byte) [common.BlockSize]byte {
	payload := make([]byte, 0, 3+len(transmission))
	payload = append(payload, 0x01) // batch count = 1
	tLen := uint16(len(transmission))
	payload = append(payload, byte(tLen>>8), byte(tLen))
	payload = append(payload, transmission...)

	var block [common.BlockSize]byte
	binary.BigEndian.PutUint16(block[:2], uint16(len(payload)))
	copy(block[2:], payload)
	for i := 2 + len(payload); i < common.BlockSize; i++ {
		block[i] = common.PaddingByte
	}
	return block
}

func buildPINGBlockCli(corrID [24]byte) [common.BlockSize]byte {
	t := make([]byte, 0, 28)
	t = append(t, 0x00)          // sig len = 0
	t = append(t, 0x00)          // sess len = 0
	t = append(t, corrID[:]...)  // corrID
	t = append(t, 0x00)          // entity len = 0
	t = append(t, common.CmdPING)
	return wrapTransmission(t)
}

func buildNEWBlockCli(corrID [24]byte, recipientKey ed25519.PublicKey) [common.BlockSize]byte {
	t := make([]byte, 0, 60)
	t = append(t, 0x00)
	t = append(t, 0x00)
	t = append(t, corrID[:]...)
	t = append(t, 0x00)
	t = append(t, common.CmdNEW)
	t = append(t, recipientKey...)
	return wrapTransmission(t)
}

func buildKEYBlockCli(corrID [24]byte, senderID [24]byte, senderPubKey ed25519.PublicKey) [common.BlockSize]byte {
	t := make([]byte, 0, 90)
	t = append(t, 0x00)
	t = append(t, 0x00)
	t = append(t, corrID[:]...)
	t = append(t, 24)
	t = append(t, senderID[:]...)
	t = append(t, common.CmdKEY)
	t = append(t, senderPubKey...)
	return wrapTransmission(t)
}

func buildSignedSENDBlockCli(corrID [24]byte, senderID [24]byte, privKey ed25519.PrivateKey, msgBody []byte) [common.BlockSize]byte {
	signedData := make([]byte, 0, 1+24+1+24+1+len(msgBody))
	signedData = append(signedData, 0x00)
	signedData = append(signedData, corrID[:]...)
	signedData = append(signedData, 24)
	signedData = append(signedData, senderID[:]...)
	signedData = append(signedData, common.CmdSEND)
	signedData = append(signedData, msgBody...)

	sig := ed25519.Sign(privKey, signedData)

	t := make([]byte, 0, 1+len(sig)+len(signedData))
	t = append(t, byte(len(sig)))
	t = append(t, sig...)
	t = append(t, signedData...)
	return wrapTransmission(t)
}

func buildSUBBlockCli(corrID [24]byte, recipientID [24]byte, privKey ed25519.PrivateKey) [common.BlockSize]byte {
	signedData := make([]byte, 0, 1+24+1+24+1)
	signedData = append(signedData, 0x00)
	signedData = append(signedData, corrID[:]...)
	signedData = append(signedData, 24)
	signedData = append(signedData, recipientID[:]...)
	signedData = append(signedData, common.CmdSUB)

	sig := ed25519.Sign(privKey, signedData)

	t := make([]byte, 0, 1+len(sig)+len(signedData))
	t = append(t, byte(len(sig)))
	t = append(t, sig...)
	t = append(t, signedData...)
	return wrapTransmission(t)
}

func buildACKBlockCli(corrID [24]byte, recipientID [24]byte, msgID [24]byte) [common.BlockSize]byte {
	t := make([]byte, 0, 80)
	t = append(t, 0x00)
	t = append(t, 0x00)
	t = append(t, corrID[:]...)
	t = append(t, 24)
	t = append(t, recipientID[:]...)
	t = append(t, common.CmdACK)
	t = append(t, msgID[:]...)
	return wrapTransmission(t)
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
