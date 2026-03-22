package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/saschadaemgen/GoRelay/internal/protocol/common"
	"github.com/saschadaemgen/GoRelay/internal/protocol/smp"
)

// buildSKEYBlock constructs a SKEY command block.
// SKEY uses senderID as entityID and carries a shortString(SPKI) sender key.
func buildSKEYBlock(corrID [24]byte, senderID [24]byte, senderPubKey ed25519.PublicKey) [common.BlockSize]byte {
	keySPKI := smp.EncodeEd25519SPKI(senderPubKey)
	body := make([]byte, 0, 1+len(keySPKI))
	body = append(body, byte(len(keySPKI)))
	body = append(body, keySPKI...)

	t := common.BuildTransmission(nil, corrID, senderID[:], common.TagSKEY, body)
	return common.WrapTransmissionBlock(t)
}

func TestSKEYSetsSenderKey(t *testing.T) {
	addr, cancel := startTestServer(t)
	defer cancel()

	conn := dialSMP(t, addr)
	defer conn.Close()

	recipientPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate recipient key: %v", err)
	}

	_, senderID := createQueueOnConn(t, conn, recipientPub)

	senderPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate sender key: %v", err)
	}

	var corrID [24]byte
	if _, err := rand.Read(corrID[:]); err != nil {
		t.Fatalf("corrID: %v", err)
	}

	cmd := sendAndReadResponse(t, conn, buildSKEYBlock(corrID, senderID, senderPub))
	if cmd.Type != common.CmdOK {
		t.Fatalf("SKEY: expected OK, got 0x%02x (body: %q)", cmd.Type, string(cmd.Body))
	}
}

func TestSKEYDuplicateReturnsAuthError(t *testing.T) {
	addr, cancel := startTestServer(t)
	defer cancel()

	conn := dialSMP(t, addr)
	defer conn.Close()

	recipientPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate recipient key: %v", err)
	}

	_, senderID := createQueueOnConn(t, conn, recipientPub)

	senderPub1, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate sender key 1: %v", err)
	}

	// First SKEY should succeed
	var corrID1 [24]byte
	if _, err := rand.Read(corrID1[:]); err != nil {
		t.Fatalf("corrID: %v", err)
	}
	cmd1 := sendAndReadResponse(t, conn, buildSKEYBlock(corrID1, senderID, senderPub1))
	if cmd1.Type != common.CmdOK {
		t.Fatalf("SKEY 1: expected OK, got 0x%02x (body: %q)", cmd1.Type, string(cmd1.Body))
	}

	// Second SKEY should return ERR AUTH
	senderPub2, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate sender key 2: %v", err)
	}
	var corrID2 [24]byte
	if _, err := rand.Read(corrID2[:]); err != nil {
		t.Fatalf("corrID: %v", err)
	}
	cmd2 := sendAndReadResponse(t, conn, buildSKEYBlock(corrID2, senderID, senderPub2))
	if cmd2.Type != common.CmdERR {
		t.Fatalf("SKEY 2: expected ERR, got 0x%02x", cmd2.Type)
	}
	if string(cmd2.Body) != "AUTH" {
		t.Fatalf("SKEY 2: expected AUTH error, got body: %q", string(cmd2.Body))
	}
}

func TestSKEYNonexistentQueueReturnsNoQueue(t *testing.T) {
	addr, cancel := startTestServer(t)
	defer cancel()

	conn := dialSMP(t, addr)
	defer conn.Close()

	senderPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate sender key: %v", err)
	}

	var fakeSenderID [24]byte
	if _, err := rand.Read(fakeSenderID[:]); err != nil {
		t.Fatalf("fakeSenderID: %v", err)
	}

	var corrID [24]byte
	if _, err := rand.Read(corrID[:]); err != nil {
		t.Fatalf("corrID: %v", err)
	}

	cmd := sendAndReadResponse(t, conn, buildSKEYBlock(corrID, fakeSenderID, senderPub))
	if cmd.Type != common.CmdERR {
		t.Fatalf("SKEY nonexistent: expected ERR, got 0x%02x", cmd.Type)
	}
	if string(cmd.Body) != "NO_QUEUE" {
		t.Fatalf("SKEY nonexistent: expected NO_QUEUE error, got body: %q", string(cmd.Body))
	}
}

func TestErrorResponseTextFormat(t *testing.T) {
	// Verify error responses use text format ("ERR AUTH") not binary bytes
	addr, cancel := startTestServer(t)
	defer cancel()

	conn, sessID := dialSMPWithSession(t, addr)
	defer conn.Close()

	recipientPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	recipientID, _ := createQueueOnConn(t, conn, recipientPub)

	// SUB with wrong key should return ERR with text "AUTH"
	_, wrongPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate wrong key: %v", err)
	}

	var corrID [24]byte
	if _, err := rand.Read(corrID[:]); err != nil {
		t.Fatalf("corrID: %v", err)
	}

	block := buildSUBBlock(corrID, recipientID, wrongPriv, sessID)
	cmd := sendAndReadResponse(t, conn, block)
	if cmd.Type != common.CmdERR {
		t.Fatalf("expected ERR, got 0x%02x", cmd.Type)
	}

	// Error body must be readable ASCII text, not a binary byte
	bodyStr := string(cmd.Body)
	if bodyStr != "AUTH" {
		t.Fatalf("error body should be text 'AUTH', got %q (bytes: %v)", bodyStr, cmd.Body)
	}

	// Verify the body is printable ASCII (not a single binary byte like 0x01)
	for i, b := range cmd.Body {
		if b < 0x20 || b > 0x7E {
			t.Fatalf("error body byte %d is non-printable: 0x%02x", i, b)
		}
	}
}
