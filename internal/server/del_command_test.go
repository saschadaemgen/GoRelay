package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/saschadaemgen/GoRelay/internal/protocol/common"
)

// buildSignedDELBlock constructs a signed DEL command block.
// DEL is a recipient command - entityID = recipientID.
// DEL has no body, just the tag "DEL" (no trailing space).
func buildSignedDELBlock(corrID [24]byte, recipientID [24]byte, privKey ed25519.PrivateKey, sessionID ...[]byte) [common.BlockSize]byte {
	var sessID []byte
	if len(sessionID) > 0 {
		sessID = sessionID[0]
	}

	signedData := common.BuildSignedData(sessID, corrID, recipientID[:], common.TagDEL, nil)
	sig := ed25519.Sign(privKey, signedData)

	t := common.BuildTransmission(sig, corrID, recipientID[:], common.TagDEL, nil)
	return common.WrapTransmissionBlock(t)
}

func TestDELRemovesQueue(t *testing.T) {
	addr, cancel := startTestServer(t)
	defer cancel()

	conn, sessID := dialSMPWithSession(t, addr)
	defer conn.Close()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	recipientID, _ := createQueueOnConn(t, conn, pub)

	// Delete queue
	var corrID [24]byte
	if _, err := rand.Read(corrID[:]); err != nil {
		t.Fatal(err)
	}

	block := buildSignedDELBlock(corrID, recipientID, priv, sessID)
	cmd := sendAndReadResponse(t, conn, block)
	if cmd.Type != common.CmdOK {
		t.Fatalf("DEL: expected OK, got 0x%02x (body: %q)", cmd.Type, string(cmd.Body))
	}

	// Verify entityId is echoed back
	if !cmd.HasEntityID {
		t.Fatal("DEL OK response must include entityId")
	}
	if cmd.EntityID != recipientID {
		t.Fatalf("DEL OK entityId mismatch: got %x, want %x", cmd.EntityID, recipientID)
	}

	// Verify queue is gone - SUB should return ERR NO_QUEUE
	var corrID2 [24]byte
	if _, err := rand.Read(corrID2[:]); err != nil {
		t.Fatal(err)
	}
	block2 := buildSUBBlock(corrID2, recipientID, priv, sessID)
	cmd2 := sendAndReadResponse(t, conn, block2)
	if cmd2.Type != common.CmdERR {
		t.Fatalf("SUB after DEL: expected ERR, got 0x%02x", cmd2.Type)
	}
	if string(cmd2.Body) != "NO_QUEUE" {
		t.Fatalf("SUB after DEL: expected NO_QUEUE, got %q", string(cmd2.Body))
	}
}

func TestDELNonexistentQueueReturnsOK(t *testing.T) {
	addr, cancel := startTestServer(t)
	defer cancel()

	conn, sessID := dialSMPWithSession(t, addr)
	defer conn.Close()

	// Generate a key but don't create a queue
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	var fakeRecipientID [24]byte
	if _, err := rand.Read(fakeRecipientID[:]); err != nil {
		t.Fatal(err)
	}

	var corrID [24]byte
	if _, err := rand.Read(corrID[:]); err != nil {
		t.Fatal(err)
	}

	// DEL on nonexistent queue should return OK (idempotent)
	block := buildSignedDELBlock(corrID, fakeRecipientID, priv, sessID)
	cmd := sendAndReadResponse(t, conn, block)
	if cmd.Type != common.CmdOK {
		t.Fatalf("DEL nonexistent: expected OK, got 0x%02x (body: %q)", cmd.Type, string(cmd.Body))
	}
}

func TestDELRequiresValidSignature(t *testing.T) {
	addr, cancel := startTestServer(t)
	defer cancel()

	conn, sessID := dialSMPWithSession(t, addr)
	defer conn.Close()

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	recipientID, _ := createQueueOnConn(t, conn, pub)

	// Try DEL with wrong key
	_, wrongPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	var corrID [24]byte
	if _, err := rand.Read(corrID[:]); err != nil {
		t.Fatal(err)
	}

	block := buildSignedDELBlock(corrID, recipientID, wrongPriv, sessID)
	cmd := sendAndReadResponse(t, conn, block)
	if cmd.Type != common.CmdERR {
		t.Fatalf("DEL wrong sig: expected ERR, got 0x%02x", cmd.Type)
	}
	if string(cmd.Body) != "AUTH" {
		t.Fatalf("DEL wrong sig: expected AUTH, got %q", string(cmd.Body))
	}
}

func TestDELWithoutSignatureReturnsAuth(t *testing.T) {
	addr, cancel := startTestServer(t)
	defer cancel()

	conn := dialSMP(t, addr)
	defer conn.Close()

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	recipientID, _ := createQueueOnConn(t, conn, pub)

	// Send unsigned DEL
	var corrID [24]byte
	if _, err := rand.Read(corrID[:]); err != nil {
		t.Fatal(err)
	}

	t2 := common.BuildTransmission(nil, corrID, recipientID[:], common.TagDEL, nil)
	block := common.WrapTransmissionBlock(t2)
	cmd := sendAndReadResponse(t, conn, block)
	if cmd.Type != common.CmdERR {
		t.Fatalf("DEL unsigned: expected ERR, got 0x%02x", cmd.Type)
	}
	if string(cmd.Body) != "AUTH" {
		t.Fatalf("DEL unsigned: expected AUTH, got %q", string(cmd.Body))
	}
}

func TestDELTwiceIsIdempotent(t *testing.T) {
	addr, cancel := startTestServer(t)
	defer cancel()

	conn, sessID := dialSMPWithSession(t, addr)
	defer conn.Close()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	recipientID, _ := createQueueOnConn(t, conn, pub)

	// First DEL
	var corrID1 [24]byte
	if _, err := rand.Read(corrID1[:]); err != nil {
		t.Fatal(err)
	}
	block1 := buildSignedDELBlock(corrID1, recipientID, priv, sessID)
	cmd1 := sendAndReadResponse(t, conn, block1)
	if cmd1.Type != common.CmdOK {
		t.Fatalf("DEL 1: expected OK, got 0x%02x (body: %q)", cmd1.Type, string(cmd1.Body))
	}

	// Second DEL - queue already gone, should still return OK
	var corrID2 [24]byte
	if _, err := rand.Read(corrID2[:]); err != nil {
		t.Fatal(err)
	}
	block2 := buildSignedDELBlock(corrID2, recipientID, priv, sessID)
	cmd2 := sendAndReadResponse(t, conn, block2)
	if cmd2.Type != common.CmdOK {
		t.Fatalf("DEL 2: expected OK (idempotent), got 0x%02x (body: %q)", cmd2.Type, string(cmd2.Body))
	}
}
