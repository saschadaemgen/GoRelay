package server

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"testing"

	"github.com/saschadaemgen/GoRelay/internal/protocol/common"
	"github.com/saschadaemgen/GoRelay/internal/queue"
)

// buildNEWBlock constructs a 16KB block containing a NEW command
// with the given correlation ID and recipient public key.
func buildNEWBlock(corrID [24]byte, recipientKey ed25519.PublicKey) [common.BlockSize]byte {
	// transmission: sig(0) + sessID(0) + corrID(24) + entityID(0) + NEW + recipientKey
	transmission := make([]byte, 0, 60)
	transmission = append(transmission, 0x00)          // signature length = 0
	transmission = append(transmission, 0x00)          // session_id length = 0
	transmission = append(transmission, corrID[:]...)  // correlation ID
	transmission = append(transmission, 0x00)          // entity_id length = 0
	transmission = append(transmission, common.CmdNEW) // command
	transmission = append(transmission, recipientKey...) // body: recipient public key

	// payload: batchCount(1) + tLen(2) + transmission
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

// parseIDSResponse parses the IDS body from a raw response block.
// Returns recipientID, senderID, serverDHPubKey.
func parseIDSResponse(t *testing.T, block [common.BlockSize]byte) (corrID [24]byte, recipientID [24]byte, senderID [24]byte, dhPubKey []byte) {
	t.Helper()

	payloadLen := binary.BigEndian.Uint16(block[:2])
	payload := block[2 : 2+payloadLen]

	cmds, err := common.ParsePayload(payload)
	if err != nil {
		t.Fatalf("parse IDS payload: %v", err)
	}
	if len(cmds) != 1 {
		t.Fatalf("expected 1 response, got %d", len(cmds))
	}
	if cmds[0].Type != common.CmdIDS {
		t.Fatalf("expected IDS (0x%02x), got 0x%02x", common.CmdIDS, cmds[0].Type)
	}

	body := cmds[0].Body
	if len(body) < 24+24+32 {
		t.Fatalf("IDS body too short: %d bytes", len(body))
	}

	copy(recipientID[:], body[0:24])
	copy(senderID[:], body[24:48])
	dhPubKey = make([]byte, 32)
	copy(dhPubKey, body[48:80])
	corrID = cmds[0].CorrelationID
	return
}

func TestNEWCreatesQueueWithValidIDS(t *testing.T) {
	addr, cancel := startTestServer(t)
	defer cancel()

	conn := dialSMP(t, addr)
	defer conn.Close()

	// Generate a recipient key
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	var corrID [24]byte
	if _, err := rand.Read(corrID[:]); err != nil {
		t.Fatalf("generate corrID: %v", err)
	}

	// Send NEW
	block := buildNEWBlock(corrID, pub)
	conn.SetWriteDeadline(common.WriteDeadline())
	if _, err := conn.Write(block[:]); err != nil {
		t.Fatalf("write NEW: %v", err)
	}

	// Read IDS response
	resp := readRawBlock(t, conn)
	respCorrID, recipientID, senderID, dhPubKey := parseIDSResponse(t, resp)

	// Verify correlation ID matches
	if respCorrID != corrID {
		t.Fatal("correlation ID mismatch")
	}

	// Verify IDs are 24 bytes and non-zero
	var zeroID [24]byte
	if recipientID == zeroID {
		t.Fatal("recipientID is all zeros")
	}
	if senderID == zeroID {
		t.Fatal("senderID is all zeros")
	}

	// Verify recipientID != senderID
	if recipientID == senderID {
		t.Fatal("recipientID and senderID must be different")
	}

	// Verify DH public key is valid X25519 (32 bytes, parseable)
	if len(dhPubKey) != 32 {
		t.Fatalf("DH public key length: %d, want 32", len(dhPubKey))
	}
	_, err = ecdh.X25519().NewPublicKey(dhPubKey)
	if err != nil {
		t.Fatalf("invalid X25519 public key: %v", err)
	}
}

func TestNEWIsIdempotent(t *testing.T) {
	addr, cancel := startTestServer(t)
	defer cancel()

	conn := dialSMP(t, addr)
	defer conn.Close()

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	// First NEW
	var corrID1 [24]byte
	if _, err := rand.Read(corrID1[:]); err != nil {
		t.Fatalf("generate corrID1: %v", err)
	}
	block1 := buildNEWBlock(corrID1, pub)
	conn.SetWriteDeadline(common.WriteDeadline())
	if _, err := conn.Write(block1[:]); err != nil {
		t.Fatalf("write NEW 1: %v", err)
	}
	resp1 := readRawBlock(t, conn)
	_, recipientID1, senderID1, dhPubKey1 := parseIDSResponse(t, resp1)

	// Second NEW with same key
	var corrID2 [24]byte
	if _, err := rand.Read(corrID2[:]); err != nil {
		t.Fatalf("generate corrID2: %v", err)
	}
	block2 := buildNEWBlock(corrID2, pub)
	conn.SetWriteDeadline(common.WriteDeadline())
	if _, err := conn.Write(block2[:]); err != nil {
		t.Fatalf("write NEW 2: %v", err)
	}
	resp2 := readRawBlock(t, conn)
	_, recipientID2, senderID2, dhPubKey2 := parseIDSResponse(t, resp2)

	// Same queue should be returned
	if recipientID1 != recipientID2 {
		t.Fatal("idempotent NEW returned different recipientID")
	}
	if senderID1 != senderID2 {
		t.Fatal("idempotent NEW returned different senderID")
	}
	if !bytes.Equal(dhPubKey1, dhPubKey2) {
		t.Fatal("idempotent NEW returned different DH public key")
	}
}

func TestNEWDifferentKeysCreateDifferentQueues(t *testing.T) {
	addr, cancel := startTestServer(t)
	defer cancel()

	conn := dialSMP(t, addr)
	defer conn.Close()

	// Create two queues with different keys
	pub1, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key 1: %v", err)
	}
	pub2, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key 2: %v", err)
	}

	var corrID1, corrID2 [24]byte
	if _, err := rand.Read(corrID1[:]); err != nil {
		t.Fatalf("corrID1: %v", err)
	}
	if _, err := rand.Read(corrID2[:]); err != nil {
		t.Fatalf("corrID2: %v", err)
	}

	// First NEW
	conn.SetWriteDeadline(common.WriteDeadline())
	b1 := buildNEWBlock(corrID1, pub1)
	if _, err := conn.Write(b1[:]); err != nil {
		t.Fatalf("write NEW 1: %v", err)
	}
	resp1 := readRawBlock(t, conn)
	_, rid1, sid1, _ := parseIDSResponse(t, resp1)

	// Second NEW
	conn.SetWriteDeadline(common.WriteDeadline())
	b2 := buildNEWBlock(corrID2, pub2)
	if _, err := conn.Write(b2[:]); err != nil {
		t.Fatalf("write NEW 2: %v", err)
	}
	resp2 := readRawBlock(t, conn)
	_, rid2, sid2, _ := parseIDSResponse(t, resp2)

	if rid1 == rid2 {
		t.Fatal("different keys produced same recipientID")
	}
	if sid1 == sid2 {
		t.Fatal("different keys produced same senderID")
	}
}

func TestNEWServerDHKeyIsValidX25519(t *testing.T) {
	addr, cancel := startTestServer(t)
	defer cancel()

	conn := dialSMP(t, addr)
	defer conn.Close()

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	var corrID [24]byte
	if _, err := rand.Read(corrID[:]); err != nil {
		t.Fatalf("corrID: %v", err)
	}

	block := buildNEWBlock(corrID, pub)
	conn.SetWriteDeadline(common.WriteDeadline())
	if _, err := conn.Write(block[:]); err != nil {
		t.Fatalf("write NEW: %v", err)
	}

	resp := readRawBlock(t, conn)
	_, _, _, dhPubKey := parseIDSResponse(t, resp)

	// Verify we can do a DH exchange with this key
	clientPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate client DH: %v", err)
	}
	serverPub, err := ecdh.X25519().NewPublicKey(dhPubKey)
	if err != nil {
		t.Fatalf("parse server DH key: %v", err)
	}
	secret, err := clientPriv.ECDH(serverPub)
	if err != nil {
		t.Fatalf("ECDH failed: %v", err)
	}
	if len(secret) != 32 {
		t.Fatalf("shared secret length: %d, want 32", len(secret))
	}
}

func TestNEWQueueStoredInStore(t *testing.T) {
	// Direct unit test against MemoryStore
	store := queue.NewMemoryStore()

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	q, err := store.CreateQueue(pub)
	if err != nil {
		t.Fatalf("CreateQueue: %v", err)
	}

	// Verify queue is retrievable
	got, err := store.GetQueue(q.RecipientID)
	if err != nil {
		t.Fatalf("GetQueue: %v", err)
	}

	if got.RecipientID != q.RecipientID {
		t.Fatal("recipientID mismatch after retrieval")
	}
	if got.SenderID != q.SenderID {
		t.Fatal("senderID mismatch after retrieval")
	}

	var zeroID [24]byte
	if got.RecipientID == zeroID {
		t.Fatal("stored queue has zero recipientID")
	}
	if got.SenderID == zeroID {
		t.Fatal("stored queue has zero senderID")
	}
}

func TestNEWImplicitSubscription(t *testing.T) {
	addr, cancel := startTestServer(t)
	defer cancel()

	conn := dialSMP(t, addr)
	defer conn.Close()

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	var corrID [24]byte
	if _, err := rand.Read(corrID[:]); err != nil {
		t.Fatalf("corrID: %v", err)
	}

	block := buildNEWBlock(corrID, pub)
	conn.SetWriteDeadline(common.WriteDeadline())
	if _, err := conn.Write(block[:]); err != nil {
		t.Fatalf("write NEW: %v", err)
	}

	resp := readRawBlock(t, conn)
	_, _, _, _ = parseIDSResponse(t, resp)

	// Verify the connection is still alive by sending PING
	var pingCorrID [24]byte
	if _, err := rand.Read(pingCorrID[:]); err != nil {
		t.Fatalf("corrID: %v", err)
	}
	pingBlock := buildPINGBlock(pingCorrID)
	conn.SetWriteDeadline(common.WriteDeadline())
	if _, err := conn.Write(pingBlock[:]); err != nil {
		t.Fatalf("write PING: %v", err)
	}

	pongResp := readRawBlock(t, conn)
	payloadLen := binary.BigEndian.Uint16(pongResp[:2])
	payload := pongResp[2 : 2+payloadLen]
	cmds, err := common.ParsePayload(payload)
	if err != nil {
		t.Fatalf("parse PONG: %v", err)
	}
	if cmds[0].Type != common.CmdPONG {
		t.Fatalf("expected PONG, got 0x%02x", cmds[0].Type)
	}
}

func TestNEWStoreIdempotency(t *testing.T) {
	// Direct unit test for MemoryStore idempotency
	store := queue.NewMemoryStore()

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	q1, err := store.CreateQueue(pub)
	if err != nil {
		t.Fatalf("CreateQueue 1: %v", err)
	}

	q2, err := store.CreateQueue(pub)
	if err != nil {
		t.Fatalf("CreateQueue 2: %v", err)
	}

	if q1.RecipientID != q2.RecipientID {
		t.Fatal("idempotent CreateQueue returned different recipientIDs")
	}
	if q1.SenderID != q2.SenderID {
		t.Fatal("idempotent CreateQueue returned different senderIDs")
	}
}

func TestNEWRecipientIDDifferentFromSenderID(t *testing.T) {
	store := queue.NewMemoryStore()

	// Create multiple queues and verify IDs never match
	for i := 0; i < 20; i++ {
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("generate key %d: %v", i, err)
		}
		q, err := store.CreateQueue(pub)
		if err != nil {
			t.Fatalf("CreateQueue %d: %v", i, err)
		}
		if q.RecipientID == q.SenderID {
			t.Fatalf("queue %d: recipientID == senderID", i)
		}
	}
}
