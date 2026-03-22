package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"testing"

	"github.com/saschadaemgen/GoRelay/internal/protocol/common"
	"github.com/saschadaemgen/GoRelay/internal/protocol/smp"
)

func TestOKResponseToKEYIncludesEntityId(t *testing.T) {
	addr, cancel := startTestServer(t)
	defer cancel()

	conn := dialSMP(t, addr)
	defer conn.Close()

	recipientPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	recipientID, _ := createQueueOnConn(t, conn, recipientPub)

	senderPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	var corrID [24]byte
	if _, err := rand.Read(corrID[:]); err != nil {
		t.Fatal(err)
	}

	cmd := sendAndReadResponse(t, conn, buildKEYBlock(corrID, recipientID, senderPub))
	if cmd.Type != common.CmdOK {
		t.Fatalf("KEY: expected OK, got 0x%02x (body: %q)", cmd.Type, string(cmd.Body))
	}
	if !cmd.HasEntityID {
		t.Fatal("OK response to KEY must include entityId")
	}
	if cmd.EntityID != recipientID {
		t.Fatalf("OK response entityId mismatch: got %x, want %x", cmd.EntityID, recipientID)
	}
}

func TestOKResponseToSUBIncludesEntityId(t *testing.T) {
	addr, cancel := startTestServer(t)
	defer cancel()

	conn, sessID := dialSMPWithSession(t, addr)
	defer conn.Close()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	recipientID, _ := createQueueOnConn(t, conn, pub)

	// SUB with correct key on a second connection
	conn2, sessID2 := dialSMPWithSession(t, addr)
	defer conn2.Close()
	_ = sessID

	var corrID [24]byte
	if _, err := rand.Read(corrID[:]); err != nil {
		t.Fatal(err)
	}

	block := buildSUBBlock(corrID, recipientID, priv, sessID2)
	cmd := sendAndReadResponse(t, conn2, block)
	if cmd.Type != common.CmdOK {
		t.Fatalf("SUB: expected OK, got 0x%02x (body: %q)", cmd.Type, string(cmd.Body))
	}
	if !cmd.HasEntityID {
		t.Fatal("OK response to SUB must include entityId")
	}
	if cmd.EntityID != recipientID {
		t.Fatalf("OK response entityId mismatch: got %x, want %x", cmd.EntityID, recipientID)
	}
}

func TestERRResponseIncludesEntityId(t *testing.T) {
	addr, cancel := startTestServer(t)
	defer cancel()

	conn := dialSMP(t, addr)
	defer conn.Close()

	// SKEY with a nonexistent senderID should return ERR with entityId echoed
	senderPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	var fakeSenderID [24]byte
	if _, err := rand.Read(fakeSenderID[:]); err != nil {
		t.Fatal(err)
	}

	var corrID [24]byte
	if _, err := rand.Read(corrID[:]); err != nil {
		t.Fatal(err)
	}

	// Build SKEY block with fake senderID
	keySPKI := smp.EncodeEd25519SPKI(senderPub)
	body := make([]byte, 0, 1+len(keySPKI))
	body = append(body, byte(len(keySPKI)))
	body = append(body, keySPKI...)
	transmission := common.BuildTransmission(nil, corrID, fakeSenderID[:], common.TagSKEY, body)
	block := common.WrapTransmissionBlock(transmission)

	cmd := sendAndReadResponse(t, conn, block)
	if cmd.Type != common.CmdERR {
		t.Fatalf("expected ERR, got 0x%02x", cmd.Type)
	}
	if !cmd.HasEntityID {
		t.Fatal("ERR response must include entityId echoed from request")
	}
	if cmd.EntityID != fakeSenderID {
		t.Fatalf("ERR response entityId mismatch: got %x, want %x", cmd.EntityID, fakeSenderID)
	}
}

func TestIDSResponseHasEmptyEntityId(t *testing.T) {
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
	if cmds[0].HasEntityID {
		t.Fatal("IDS response should have empty entityId")
	}
}

func TestPONGResponseHasEmptyEntityId(t *testing.T) {
	addr, cancel := startTestServer(t)
	defer cancel()

	conn := dialSMP(t, addr)
	defer conn.Close()

	var corrID [24]byte
	if _, err := rand.Read(corrID[:]); err != nil {
		t.Fatal(err)
	}

	block := buildPINGBlock(corrID)
	cmd := sendAndReadResponse(t, conn, block)
	if cmd.Type != common.CmdPONG {
		t.Fatalf("expected PONG, got 0x%02x", cmd.Type)
	}
	if cmd.HasEntityID {
		t.Fatal("PONG response should have empty entityId")
	}
}

func TestOKResponseToSENDIncludesEntityId(t *testing.T) {
	addr, cancel := startTestServer(t)
	defer cancel()

	conn, sessID := dialSMPWithSession(t, addr)
	defer conn.Close()

	recipientPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	recipientID, senderID := createQueueOnConn(t, conn, recipientPub)

	senderPub, senderPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Set sender key
	var keyCorrID [24]byte
	if _, err := rand.Read(keyCorrID[:]); err != nil {
		t.Fatal(err)
	}
	keyCmd := sendAndReadResponse(t, conn, buildKEYBlock(keyCorrID, recipientID, senderPub))
	if keyCmd.Type != common.CmdOK {
		t.Fatalf("KEY: expected OK, got 0x%02x", keyCmd.Type)
	}

	// SEND uses senderID as entityId
	var sendCorrID [24]byte
	if _, err := rand.Read(sendCorrID[:]); err != nil {
		t.Fatal(err)
	}
	sendCmd := sendAndReadResponse(t, conn, buildSignedSENDBlock(sendCorrID, senderID, senderPriv, []byte("test"), sessID))
	if sendCmd.Type != common.CmdOK {
		t.Fatalf("SEND: expected OK, got 0x%02x (body: %q)", sendCmd.Type, string(sendCmd.Body))
	}
	if !sendCmd.HasEntityID {
		t.Fatal("OK response to SEND must include entityId")
	}
	if sendCmd.EntityID != senderID {
		t.Fatalf("OK response to SEND entityId mismatch: got %x, want %x", sendCmd.EntityID, senderID)
	}
}
