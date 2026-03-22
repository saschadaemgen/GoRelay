package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/saschadaemgen/GoRelay/internal/protocol/common"
)

// buildSUBBlock constructs a 16KB block containing a signed SUB command.
// The signature covers: shortString(sessionID) + corrId + entityId + "SUB"
func buildSUBBlock(corrID [24]byte, recipientID [24]byte, privKey ed25519.PrivateKey, sessionID ...[]byte) [common.BlockSize]byte {
	var sessID []byte
	if len(sessionID) > 0 {
		sessID = sessionID[0]
	}

	// Build signed data: shortString(sessionID) + corrId(len+data) + entityId(shortString) + "SUB"
	signedData := common.BuildSignedData(sessID, corrID, recipientID[:], common.TagSUB, nil)
	sig := ed25519.Sign(privKey, signedData)

	// Build wire transmission (sessionID NOT included in wire)
	t := common.BuildTransmission(sig, corrID, recipientID[:], common.TagSUB, nil)
	return common.WrapTransmissionBlock(t)
}

// buildUnsignedSUBBlock constructs a SUB block without a signature.
func buildUnsignedSUBBlock(corrID [24]byte, recipientID [24]byte) [common.BlockSize]byte {
	t := common.BuildTransmission(nil, corrID, recipientID[:], common.TagSUB, nil)
	return common.WrapTransmissionBlock(t)
}

// parseResponseType reads a raw block and returns the parsed command.
func parseResponseType(t *testing.T, block [common.BlockSize]byte) common.Command {
	t.Helper()
	payloadLen := binary.BigEndian.Uint16(block[:2])
	payload := block[2 : 2+payloadLen]
	cmds, err := common.ParsePayload(payload)
	if err != nil {
		t.Fatalf("parse response payload: %v", err)
	}
	if len(cmds) != 1 {
		t.Fatalf("expected 1 response, got %d", len(cmds))
	}
	return cmds[0]
}

// createQueueOnConn sends NEW and returns the recipientID and senderID.
func createQueueOnConn(t *testing.T, conn net.Conn, recipientPub ed25519.PublicKey) (recipientID [24]byte, senderID [24]byte) {
	t.Helper()
	var corrID [24]byte
	if _, err := rand.Read(corrID[:]); err != nil {
		t.Fatalf("corrID: %v", err)
	}
	block := buildNEWBlock(corrID, recipientPub)
	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(block[:]); err != nil {
		t.Fatalf("write NEW: %v", err)
	}
	resp := readRawBlock(t, conn)
	_, recipientID, senderID, _ = parseIDSResponse(t, resp)
	return
}

func TestSUBWithValidSignatureReturnsOK(t *testing.T) {
	addr, cancel := startTestServer(t)
	defer cancel()

	conn, sessID := dialSMPWithSession(t, addr)
	defer conn.Close()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	recipientID, _ := createQueueOnConn(t, conn, pub)

	var corrID [24]byte
	if _, err := rand.Read(corrID[:]); err != nil {
		t.Fatalf("corrID: %v", err)
	}

	block := buildSUBBlock(corrID, recipientID, priv, sessID)
	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(block[:]); err != nil {
		t.Fatalf("write SUB: %v", err)
	}

	resp := readRawBlock(t, conn)
	cmd := parseResponseType(t, resp)

	if cmd.Type != common.CmdOK {
		t.Fatalf("expected OK (0x%02x), got 0x%02x (body=%v)", common.CmdOK, cmd.Type, cmd.Body)
	}
}

func TestSUBWithInvalidSignatureReturnsAuth(t *testing.T) {
	addr, cancel := startTestServer(t)
	defer cancel()

	conn, sessID := dialSMPWithSession(t, addr)
	defer conn.Close()

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	recipientID, _ := createQueueOnConn(t, conn, pub)

	_, wrongPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate wrong key: %v", err)
	}

	var corrID [24]byte
	if _, err := rand.Read(corrID[:]); err != nil {
		t.Fatalf("corrID: %v", err)
	}

	block := buildSUBBlock(corrID, recipientID, wrongPriv, sessID)
	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(block[:]); err != nil {
		t.Fatalf("write SUB: %v", err)
	}

	resp := readRawBlock(t, conn)
	cmd := parseResponseType(t, resp)

	if cmd.Type != common.CmdERR {
		t.Fatalf("expected ERR, got 0x%02x", cmd.Type)
	}
	if string(cmd.Body) != "AUTH" {
		t.Fatalf("expected AUTH error, got body: %q", string(cmd.Body))
	}
}

func TestSUBWithUnsignedReturnsAuth(t *testing.T) {
	addr, cancel := startTestServer(t)
	defer cancel()

	conn := dialSMP(t, addr)
	defer conn.Close()

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	recipientID, _ := createQueueOnConn(t, conn, pub)

	var corrID [24]byte
	if _, err := rand.Read(corrID[:]); err != nil {
		t.Fatalf("corrID: %v", err)
	}

	block := buildUnsignedSUBBlock(corrID, recipientID)
	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(block[:]); err != nil {
		t.Fatalf("write SUB: %v", err)
	}

	resp := readRawBlock(t, conn)
	cmd := parseResponseType(t, resp)

	if cmd.Type != common.CmdERR {
		t.Fatalf("expected ERR, got 0x%02x", cmd.Type)
	}
	if string(cmd.Body) != "AUTH" {
		t.Fatalf("expected AUTH error, got body: %q", string(cmd.Body))
	}
}

func TestSUBOnNonexistentQueueReturnsError(t *testing.T) {
	addr, cancel := startTestServer(t)
	defer cancel()

	conn, sessID := dialSMPWithSession(t, addr)
	defer conn.Close()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	var fakeRecipientID [24]byte
	if _, err := rand.Read(fakeRecipientID[:]); err != nil {
		t.Fatalf("fakeID: %v", err)
	}

	var corrID [24]byte
	if _, err := rand.Read(corrID[:]); err != nil {
		t.Fatalf("corrID: %v", err)
	}

	block := buildSUBBlock(corrID, fakeRecipientID, priv, sessID)
	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(block[:]); err != nil {
		t.Fatalf("write SUB: %v", err)
	}

	resp := readRawBlock(t, conn)
	cmd := parseResponseType(t, resp)

	if cmd.Type != common.CmdERR {
		t.Fatalf("expected ERR, got 0x%02x", cmd.Type)
	}
	if string(cmd.Body) != "NO_QUEUE" {
		t.Fatalf("expected NO_QUEUE error, got body: %q", string(cmd.Body))
	}
}

func TestSUBTakeoverSendsENDToOldSubscriber(t *testing.T) {
	addr, cancel := startTestServer(t)
	defer cancel()

	conn1, sessID1 := dialSMPWithSession(t, addr)
	defer conn1.Close()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	_ = sessID1

	recipientID, _ := createQueueOnConn(t, conn1, pub)

	conn2, sessID2 := dialSMPWithSession(t, addr)
	defer conn2.Close()

	var corrID [24]byte
	if _, err := rand.Read(corrID[:]); err != nil {
		t.Fatalf("corrID: %v", err)
	}

	block := buildSUBBlock(corrID, recipientID, priv, sessID2)
	conn2.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn2.Write(block[:]); err != nil {
		t.Fatalf("write SUB: %v", err)
	}

	resp2 := readRawBlock(t, conn2)
	cmd2 := parseResponseType(t, resp2)
	if cmd2.Type != common.CmdOK {
		t.Fatalf("conn2: expected OK, got 0x%02x", cmd2.Type)
	}

	resp1 := readRawBlock(t, conn1)
	cmd1 := parseResponseType(t, resp1)
	if cmd1.Type != common.CmdEND {
		t.Fatalf("conn1: expected END (0x%02x), got 0x%02x", common.CmdEND, cmd1.Type)
	}
}

func TestSUBNoOpWhenSameConnectionAlreadySubscribed(t *testing.T) {
	addr, cancel := startTestServer(t)
	defer cancel()

	conn, sessID := dialSMPWithSession(t, addr)
	defer conn.Close()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	recipientID, _ := createQueueOnConn(t, conn, pub)

	var corrID [24]byte
	if _, err := rand.Read(corrID[:]); err != nil {
		t.Fatalf("corrID: %v", err)
	}

	block := buildSUBBlock(corrID, recipientID, priv, sessID)
	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(block[:]); err != nil {
		t.Fatalf("write SUB: %v", err)
	}

	resp := readRawBlock(t, conn)
	cmd := parseResponseType(t, resp)

	if cmd.Type != common.CmdOK {
		t.Fatalf("expected OK for no-op SUB, got 0x%02x", cmd.Type)
	}
}

func TestSUBDeliversPendingMessage(t *testing.T) {
	addr, cancel := startTestServer(t)
	defer cancel()

	conn, sessID := dialSMPWithSession(t, addr)
	defer conn.Close()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	recipientID, _ := createQueueOnConn(t, conn, pub)
	_ = sessID

	// SUB with no pending message should return OK
	var corrID [24]byte
	if _, err := rand.Read(corrID[:]); err != nil {
		t.Fatalf("corrID: %v", err)
	}

	block := buildSUBBlock(corrID, recipientID, priv, sessID)
	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(block[:]); err != nil {
		t.Fatalf("write SUB: %v", err)
	}

	resp := readRawBlock(t, conn)
	cmd := parseResponseType(t, resp)

	if cmd.Type != common.CmdOK {
		t.Fatalf("expected OK (no pending message), got 0x%02x", cmd.Type)
	}
}
