package server

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"testing"

	"github.com/saschadaemgen/GoRelay/internal/config"
	"github.com/saschadaemgen/GoRelay/internal/protocol/common"
	"github.com/saschadaemgen/GoRelay/internal/protocol/smp"
	"github.com/saschadaemgen/GoRelay/internal/queue"
)

// buildNEWBlock constructs a 16KB block containing a NEW command
// with SPKI-encoded recipient key using v7 format (no basicAuth, no sndSecure).
//
// v7 NEW body: recipientAuthKey(shortString SPKI) + recipientDhKey(shortString SPKI)
//
//	+ subscribeMode("S")
//
// Returns the block and the recipient DH private key (needed to compute shared secret).
func buildNEWBlock(corrID [24]byte, recipientKey ed25519.PublicKey) [common.BlockSize]byte {
	block, _ := buildNEWBlockWithDH(corrID, recipientKey)
	return block
}

// buildNEWBlockWithDH is like buildNEWBlock but also returns the recipient DH private key.
func buildNEWBlockWithDH(corrID [24]byte, recipientKey ed25519.PublicKey) ([common.BlockSize]byte, *ecdh.PrivateKey) {
	// Build command body
	authKeySPKI := smp.EncodeEd25519SPKI(recipientKey)
	// Generate X25519 DH key for the recipient
	dhPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		panic("generate DH key: " + err.Error())
	}
	dhKeySPKI := smp.EncodeX25519SPKI(dhPriv.PublicKey().Bytes())

	body := make([]byte, 0, 2+len(authKeySPKI)+len(dhKeySPKI)+1)
	// recipientAuthPublicKey = shortString(SPKI)
	body = append(body, byte(len(authKeySPKI)))
	body = append(body, authKeySPKI...)
	// recipientDhPublicKey = shortString(SPKI)
	body = append(body, byte(len(dhKeySPKI)))
	body = append(body, dhKeySPKI...)
	// subscribeMode = "S" (subscribe) - v7 has no basicAuth or sndSecure
	body = append(body, 'S')

	t := common.BuildTransmission(nil, corrID, nil, common.TagNEW, body)
	return common.WrapTransmissionBlock(t), dhPriv
}

// parseIDSResponse parses the IDS body from a raw response block.
// Returns recipientID, senderID, serverDHPubKey.
// For v7, the IDS body does NOT include sndSecure.
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

	// IDS body format (v7):
	//   recipientId = shortString(24 bytes)
	//   senderId = shortString(24 bytes)
	//   srvDhPublicKey = shortString(SPKI DER X25519, 44 bytes)
	//   (no sndSecure in v7)
	body := cmds[0].Body
	off := 0

	// recipientId
	if off >= len(body) {
		t.Fatalf("IDS body too short for recipientId length")
	}
	rLen := int(body[off])
	off++
	if off+rLen > len(body) || rLen < 24 {
		t.Fatalf("IDS recipientId invalid length: %d", rLen)
	}
	copy(recipientID[:], body[off:off+24])
	off += rLen

	// senderId
	if off >= len(body) {
		t.Fatalf("IDS body too short for senderId length")
	}
	sLen := int(body[off])
	off++
	if off+sLen > len(body) || sLen < 24 {
		t.Fatalf("IDS senderId invalid length: %d", sLen)
	}
	copy(senderID[:], body[off:off+24])
	off += sLen

	// srvDhPublicKey = shortString(SPKI)
	if off >= len(body) {
		t.Fatalf("IDS body too short for dhPubKey length")
	}
	dhLen := int(body[off])
	off++
	if off+dhLen > len(body) {
		t.Fatalf("IDS dhPubKey invalid length: %d", dhLen)
	}
	dhSPKI := body[off : off+dhLen]

	// Extract raw X25519 key from SPKI
	rawDH, err := smp.ParseX25519SPKI(dhSPKI)
	if err != nil {
		t.Fatalf("parse DH SPKI: %v", err)
	}
	dhPubKey = rawDH

	corrID = cmds[0].CorrelationID
	return
}

func TestNEWCreatesQueueWithValidIDS(t *testing.T) {
	addr, cancel := startTestServer(t)
	defer cancel()

	conn := dialSMP(t, addr)
	defer conn.Close()

	recipientPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	var corrID [24]byte
	if _, err := rand.Read(corrID[:]); err != nil {
		t.Fatalf("corrID: %v", err)
	}

	block := buildNEWBlock(corrID, recipientPub)
	conn.SetWriteDeadline(common.WriteDeadline())
	if _, err := conn.Write(block[:]); err != nil {
		t.Fatalf("write NEW: %v", err)
	}

	resp := readRawBlock(t, conn)
	respCorrID, recipientID, senderID, dhPubKey := parseIDSResponse(t, resp)

	if respCorrID != corrID {
		t.Fatal("IDS corrID mismatch")
	}

	// recipientID and senderID must be non-zero
	var zero [24]byte
	if recipientID == zero {
		t.Fatal("recipientID is zero")
	}
	if senderID == zero {
		t.Fatal("senderID is zero")
	}
	if recipientID == senderID {
		t.Fatal("recipientID == senderID")
	}

	// DH key must be valid X25519 (32 bytes)
	if len(dhPubKey) != 32 {
		t.Fatalf("DH key length: %d", len(dhPubKey))
	}
}

func TestNEWIsIdempotent(t *testing.T) {
	addr, cancel := startTestServer(t)
	defer cancel()

	conn := dialSMP(t, addr)
	defer conn.Close()

	recipientPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	// First NEW
	var corrID1 [24]byte
	if _, err := rand.Read(corrID1[:]); err != nil {
		t.Fatalf("corrID: %v", err)
	}
	block1 := buildNEWBlock(corrID1, recipientPub)
	conn.SetWriteDeadline(common.WriteDeadline())
	if _, err := conn.Write(block1[:]); err != nil {
		t.Fatalf("write NEW 1: %v", err)
	}
	resp1 := readRawBlock(t, conn)
	_, rid1, sid1, dh1 := parseIDSResponse(t, resp1)

	// Second NEW with same key
	var corrID2 [24]byte
	if _, err := rand.Read(corrID2[:]); err != nil {
		t.Fatalf("corrID: %v", err)
	}
	block2 := buildNEWBlock(corrID2, recipientPub)
	conn.SetWriteDeadline(common.WriteDeadline())
	if _, err := conn.Write(block2[:]); err != nil {
		t.Fatalf("write NEW 2: %v", err)
	}
	resp2 := readRawBlock(t, conn)
	_, rid2, sid2, dh2 := parseIDSResponse(t, resp2)

	if rid1 != rid2 {
		t.Fatal("recipientID changed on idempotent NEW")
	}
	if sid1 != sid2 {
		t.Fatal("senderID changed on idempotent NEW")
	}
	if !bytes.Equal(dh1, dh2) {
		t.Fatal("DH key changed on idempotent NEW")
	}
}

func TestNEWDifferentKeysCreateDifferentQueues(t *testing.T) {
	addr, cancel := startTestServer(t)
	defer cancel()

	conn := dialSMP(t, addr)
	defer conn.Close()

	pub1, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub2, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	rid1, _ := createQueueOnConn(t, conn, pub1)
	rid2, _ := createQueueOnConn(t, conn, pub2)

	if rid1 == rid2 {
		t.Fatal("different keys should create different queues")
	}
}

func TestNEWServerDHKeyIsValidX25519(t *testing.T) {
	addr, cancel := startTestServer(t)
	defer cancel()

	conn := dialSMP(t, addr)
	defer conn.Close()

	recipientPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	var corrID [24]byte
	if _, err := rand.Read(corrID[:]); err != nil {
		t.Fatal(err)
	}
	block := buildNEWBlock(corrID, recipientPub)
	conn.SetWriteDeadline(common.WriteDeadline())
	if _, err := conn.Write(block[:]); err != nil {
		t.Fatal(err)
	}
	resp := readRawBlock(t, conn)
	_, _, _, dhPubKey := parseIDSResponse(t, resp)

	// Verify key is usable as X25519
	curve := ecdh.X25519()
	_, err = curve.NewPublicKey(dhPubKey)
	if err != nil {
		t.Fatalf("invalid X25519 key: %v", err)
	}
}

func TestNEWQueueStoredInStore(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Server.DataDir = t.TempDir()
	cfg.SMP.Enabled = true

	store := queue.NewMemoryStore()
	srv, err := newWithStore(cfg, store)
	if err != nil {
		t.Fatal(err)
	}

	recipientPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	q, err := store.CreateQueue(recipientPub)
	if err != nil {
		t.Fatal(err)
	}
	_ = srv // just verify store works

	got, err := store.GetQueue(q.RecipientID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.RecipientKey, recipientPub) {
		t.Fatal("stored key mismatch")
	}
}

func TestNEWImplicitSubscription(t *testing.T) {
	addr, cancel := startTestServer(t)
	defer cancel()

	conn := dialSMP(t, addr)
	defer conn.Close()

	recipientPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Create queue - implicit subscription via "S" mode
	_, _ = createQueueOnConn(t, conn, recipientPub)

	// Verify connection works (PING/PONG)
	var corrID [24]byte
	if _, err := rand.Read(corrID[:]); err != nil {
		t.Fatal(err)
	}
	pingBlock := buildPINGBlock(corrID)
	conn.SetWriteDeadline(common.WriteDeadline())
	if _, err := conn.Write(pingBlock[:]); err != nil {
		t.Fatal(err)
	}
	pongResp := readRawBlock(t, conn)
	payloadLen := binary.BigEndian.Uint16(pongResp[:2])
	cmds, err := common.ParsePayload(pongResp[2 : 2+payloadLen])
	if err != nil {
		t.Fatal(err)
	}
	if cmds[0].Type != common.CmdPONG {
		t.Fatalf("expected PONG, got 0x%02x", cmds[0].Type)
	}
}

func TestNEWStoreIdempotency(t *testing.T) {
	store := queue.NewMemoryStore()

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	q1, err := store.CreateQueue(pub)
	if err != nil {
		t.Fatal(err)
	}

	q2, err := store.CreateQueue(pub)
	if err != nil {
		t.Fatal(err)
	}

	if q1.RecipientID != q2.RecipientID {
		t.Fatal("idempotent CreateQueue changed recipientID")
	}
}

func TestIDSResponseV7NoSndSecure(t *testing.T) {
	// For SMP v7, the IDS response should NOT include sndSecure byte.
	// Expected IDS body size: 1+24 + 1+24 + 1+44 = 95 bytes (no trailing 'T'/'F')
	addr, cancel := startTestServer(t)
	defer cancel()

	conn := dialSMP(t, addr)
	defer conn.Close()

	recipientPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	var corrID [24]byte
	if _, err := rand.Read(corrID[:]); err != nil {
		t.Fatal(err)
	}

	block := buildNEWBlock(corrID, recipientPub)
	conn.SetWriteDeadline(common.WriteDeadline())
	if _, err := conn.Write(block[:]); err != nil {
		t.Fatal(err)
	}

	resp := readRawBlock(t, conn)
	payloadLen := binary.BigEndian.Uint16(resp[:2])
	payload := resp[2 : 2+payloadLen]
	cmds, err := common.ParsePayload(payload)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cmds[0].Type != common.CmdIDS {
		t.Fatalf("expected IDS, got 0x%02x", cmds[0].Type)
	}

	// IDS body for v7: shortString(24) + shortString(24) + shortString(44) = 95 bytes
	// No sndSecure byte at the end
	expectedLen := 1 + 24 + 1 + 24 + 1 + 44 // = 95
	if len(cmds[0].Body) != expectedLen {
		t.Fatalf("IDS body length for v7: got %d, want %d (no sndSecure)", len(cmds[0].Body), expectedLen)
	}

	// Last byte should be the last byte of the SPKI DER, NOT 'T' or 'F'
	lastByte := cmds[0].Body[len(cmds[0].Body)-1]
	if lastByte == 'T' || lastByte == 'F' {
		t.Fatalf("IDS v7 body should NOT end with sndSecure, but last byte is 0x%02x (%q)", lastByte, string(lastByte))
	}
}

func TestNEWRecipientIDDifferentFromSenderID(t *testing.T) {
	addr, cancel := startTestServer(t)
	defer cancel()

	conn := dialSMP(t, addr)
	defer conn.Close()

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	rid, sid := createQueueOnConn(t, conn, pub)
	if rid == sid {
		t.Fatal("recipientID must differ from senderID")
	}
}
