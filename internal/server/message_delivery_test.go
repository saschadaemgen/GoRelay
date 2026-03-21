package server

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/saschadaemgen/GoRelay/internal/protocol/common"
)

// buildKEYBlock constructs a 16KB block containing a KEY command.
// EntityID is the senderID, body is the sender's Ed25519 public key.
func buildKEYBlock(corrID [24]byte, senderID [24]byte, senderPubKey ed25519.PublicKey) [common.BlockSize]byte {
	transmission := make([]byte, 0, 90)
	transmission = append(transmission, 0x00)              // signature length = 0
	transmission = append(transmission, 0x00)              // session_id length = 0
	transmission = append(transmission, corrID[:]...)      // correlation ID
	transmission = append(transmission, 24)                // entity_id length = 24
	transmission = append(transmission, senderID[:]...)    // entity ID = senderID
	transmission = append(transmission, common.CmdKEY)     // command
	transmission = append(transmission, senderPubKey...)   // body: sender public key

	return wrapTransmissionInBlock(transmission)
}

// buildSignedSENDBlock constructs a signed SEND command block.
func buildSignedSENDBlock(corrID [24]byte, senderID [24]byte, privKey ed25519.PrivateKey, msgBody []byte) [common.BlockSize]byte {
	// Build signed data
	signedData := make([]byte, 0, 1+24+1+24+1+len(msgBody))
	signedData = append(signedData, 0x00)              // session_id length = 0
	signedData = append(signedData, corrID[:]...)      // correlation ID
	signedData = append(signedData, 24)                // entity_id length = 24
	signedData = append(signedData, senderID[:]...)    // entity ID
	signedData = append(signedData, common.CmdSEND)    // command
	signedData = append(signedData, msgBody...)         // body

	sig := ed25519.Sign(privKey, signedData)

	transmission := make([]byte, 0, 1+len(sig)+len(signedData))
	transmission = append(transmission, byte(len(sig)))
	transmission = append(transmission, sig...)
	transmission = append(transmission, signedData...)

	return wrapTransmissionInBlock(transmission)
}

// buildACKBlock constructs an ACK command block.
// EntityID is the recipientID, body is the msgID (24 bytes).
func buildACKBlock(corrID [24]byte, recipientID [24]byte, msgID [24]byte) [common.BlockSize]byte {
	transmission := make([]byte, 0, 80)
	transmission = append(transmission, 0x00)               // signature length = 0
	transmission = append(transmission, 0x00)               // session_id length = 0
	transmission = append(transmission, corrID[:]...)       // correlation ID
	transmission = append(transmission, 24)                 // entity_id length = 24
	transmission = append(transmission, recipientID[:]...)  // entity ID = recipientID
	transmission = append(transmission, common.CmdACK)      // command
	transmission = append(transmission, msgID[:]...)         // body: msgID

	return wrapTransmissionInBlock(transmission)
}

// wrapTransmissionInBlock wraps a raw transmission into a 16KB block.
func wrapTransmissionInBlock(transmission []byte) [common.BlockSize]byte {
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

// sendAndReadResponse sends a block and reads the response.
func sendAndReadResponse(t *testing.T, conn net.Conn, block [common.BlockSize]byte) common.Command {
	t.Helper()
	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(block[:]); err != nil {
		t.Fatalf("write block: %v", err)
	}
	resp := readRawBlock(t, conn)
	return parseResponseType(t, resp)
}

// parseMSGResponse extracts MSG fields from a raw block.
func parseMSGResponse(t *testing.T, block [common.BlockSize]byte) (msgID [24]byte, timestamp uint64, flags byte, body []byte) {
	t.Helper()
	cmd := parseResponseType(t, block)
	if cmd.Type != common.CmdMSG {
		t.Fatalf("expected MSG (0x%02x), got 0x%02x", common.CmdMSG, cmd.Type)
	}
	// MSG body: msgID(24) + timestamp(8) + flags(1) + body
	if len(cmd.Body) < 33 {
		t.Fatalf("MSG body too short: %d", len(cmd.Body))
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

func TestKEYSetsSenderKeyReturnsOK(t *testing.T) {
	addr, cancel := startTestServer(t)
	defer cancel()

	conn := dialSMP(t, addr)
	defer conn.Close()

	recipientPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen recipient key: %v", err)
	}

	_, senderID := createQueueOnConn(t, conn, recipientPub)

	// Generate sender keypair
	senderPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen sender key: %v", err)
	}

	var corrID [24]byte
	if _, err := rand.Read(corrID[:]); err != nil {
		t.Fatalf("corrID: %v", err)
	}

	block := buildKEYBlock(corrID, senderID, senderPub)
	cmd := sendAndReadResponse(t, conn, block)

	if cmd.Type != common.CmdOK {
		t.Fatalf("expected OK, got 0x%02x", cmd.Type)
	}
}

func TestKEYTwiceReturnsAuthError(t *testing.T) {
	addr, cancel := startTestServer(t)
	defer cancel()

	conn := dialSMP(t, addr)
	defer conn.Close()

	recipientPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen recipient key: %v", err)
	}

	_, senderID := createQueueOnConn(t, conn, recipientPub)

	senderPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen sender key: %v", err)
	}

	// First KEY - should succeed
	var corrID1 [24]byte
	if _, err := rand.Read(corrID1[:]); err != nil {
		t.Fatalf("corrID1: %v", err)
	}
	block1 := buildKEYBlock(corrID1, senderID, senderPub)
	cmd1 := sendAndReadResponse(t, conn, block1)
	if cmd1.Type != common.CmdOK {
		t.Fatalf("first KEY: expected OK, got 0x%02x", cmd1.Type)
	}

	// Second KEY - should fail with AUTH
	var corrID2 [24]byte
	if _, err := rand.Read(corrID2[:]); err != nil {
		t.Fatalf("corrID2: %v", err)
	}
	block2 := buildKEYBlock(corrID2, senderID, senderPub)
	cmd2 := sendAndReadResponse(t, conn, block2)
	if cmd2.Type != common.CmdERR {
		t.Fatalf("second KEY: expected ERR, got 0x%02x", cmd2.Type)
	}
	if len(cmd2.Body) < 1 || cmd2.Body[0] != common.ErrAuth {
		t.Fatalf("second KEY: expected AUTH error, got body: %v", cmd2.Body)
	}
}

func TestSENDWithoutKEYReturnsNoKeyError(t *testing.T) {
	addr, cancel := startTestServer(t)
	defer cancel()

	conn := dialSMP(t, addr)
	defer conn.Close()

	recipientPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}

	_, senderID := createQueueOnConn(t, conn, recipientPub)

	// Try SEND without KEY
	_, senderPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen sender: %v", err)
	}

	var corrID [24]byte
	if _, err := rand.Read(corrID[:]); err != nil {
		t.Fatalf("corrID: %v", err)
	}

	block := buildSignedSENDBlock(corrID, senderID, senderPriv, []byte("hello"))
	cmd := sendAndReadResponse(t, conn, block)

	if cmd.Type != common.CmdERR {
		t.Fatalf("expected ERR, got 0x%02x", cmd.Type)
	}
	if len(cmd.Body) < 1 || cmd.Body[0] != common.ErrNoKey {
		t.Fatalf("expected NO_KEY error, got body: %v", cmd.Body)
	}
}

func TestSENDWithValidSignatureReturnsOK(t *testing.T) {
	addr, cancel := startTestServer(t)
	defer cancel()

	conn := dialSMP(t, addr)
	defer conn.Close()

	recipientPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen recipient key: %v", err)
	}

	_, senderID := createQueueOnConn(t, conn, recipientPub)

	// Set sender key
	senderPub, senderPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen sender key: %v", err)
	}

	var keyCorrID [24]byte
	if _, err := rand.Read(keyCorrID[:]); err != nil {
		t.Fatalf("corrID: %v", err)
	}
	keyBlock := buildKEYBlock(keyCorrID, senderID, senderPub)
	keyCmd := sendAndReadResponse(t, conn, keyBlock)
	if keyCmd.Type != common.CmdOK {
		t.Fatalf("KEY: expected OK, got 0x%02x", keyCmd.Type)
	}

	// SEND
	var sendCorrID [24]byte
	if _, err := rand.Read(sendCorrID[:]); err != nil {
		t.Fatalf("corrID: %v", err)
	}
	sendBlock := buildSignedSENDBlock(sendCorrID, senderID, senderPriv, []byte("test message"))
	sendCmd := sendAndReadResponse(t, conn, sendBlock)

	if sendCmd.Type != common.CmdOK {
		t.Fatalf("SEND: expected OK, got 0x%02x", sendCmd.Type)
	}
}

func TestSENDDeliversMSGToSubscribedRecipient(t *testing.T) {
	addr, cancel := startTestServer(t)
	defer cancel()

	// Recipient connection
	recipientConn := dialSMP(t, addr)
	defer recipientConn.Close()

	recipientPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen recipient key: %v", err)
	}

	recipientID, senderID := createQueueOnConn(t, recipientConn, recipientPub)

	// Sender connection
	senderConn := dialSMP(t, addr)
	defer senderConn.Close()

	// Set sender key
	senderPub, senderPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen sender key: %v", err)
	}

	var keyCorrID [24]byte
	if _, err := rand.Read(keyCorrID[:]); err != nil {
		t.Fatalf("corrID: %v", err)
	}
	keyBlock := buildKEYBlock(keyCorrID, senderID, senderPub)
	keyCmd := sendAndReadResponse(t, senderConn, keyBlock)
	if keyCmd.Type != common.CmdOK {
		t.Fatalf("KEY: expected OK, got 0x%02x", keyCmd.Type)
	}

	// SEND message
	msgContent := []byte("hello from sender")
	var sendCorrID [24]byte
	if _, err := rand.Read(sendCorrID[:]); err != nil {
		t.Fatalf("corrID: %v", err)
	}
	sendBlock := buildSignedSENDBlock(sendCorrID, senderID, senderPriv, msgContent)
	sendCmd := sendAndReadResponse(t, senderConn, sendBlock)
	if sendCmd.Type != common.CmdOK {
		t.Fatalf("SEND: expected OK, got 0x%02x", sendCmd.Type)
	}

	// Recipient should receive MSG
	msgResp := readRawBlock(t, recipientConn)
	msgID, _, _, body := parseMSGResponse(t, msgResp)

	if !bytes.Equal(body, msgContent) {
		t.Fatalf("MSG body: got %q, want %q", body, msgContent)
	}

	var zeroID [24]byte
	if msgID == zeroID {
		t.Fatal("MSG has zero msgID")
	}

	// Verify entity ID is the recipientID
	cmd := parseResponseType(t, msgResp)
	if !cmd.HasEntityID || cmd.EntityID != recipientID {
		t.Fatal("MSG entityID should be recipientID")
	}
}

func TestSENDWhenRecipientNotSubscribed(t *testing.T) {
	addr, cancel := startTestServer(t)
	defer cancel()

	// Create queue on one connection, then close it
	recipientConn := dialSMP(t, addr)
	recipientPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen recipient key: %v", err)
	}
	_, senderID := createQueueOnConn(t, recipientConn, recipientPub)
	recipientConn.Close()
	time.Sleep(50 * time.Millisecond) // allow server to process disconnect

	// Sender connection
	senderConn := dialSMP(t, addr)
	defer senderConn.Close()

	senderPub, senderPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen sender key: %v", err)
	}

	var keyCorrID [24]byte
	if _, err := rand.Read(keyCorrID[:]); err != nil {
		t.Fatalf("corrID: %v", err)
	}
	keyBlock := buildKEYBlock(keyCorrID, senderID, senderPub)
	keyCmd := sendAndReadResponse(t, senderConn, keyBlock)
	if keyCmd.Type != common.CmdOK {
		t.Fatalf("KEY: expected OK, got 0x%02x", keyCmd.Type)
	}

	// SEND - should still succeed (message stored for later)
	var sendCorrID [24]byte
	if _, err := rand.Read(sendCorrID[:]); err != nil {
		t.Fatalf("corrID: %v", err)
	}
	sendBlock := buildSignedSENDBlock(sendCorrID, senderID, senderPriv, []byte("queued msg"))
	sendCmd := sendAndReadResponse(t, senderConn, sendBlock)
	if sendCmd.Type != common.CmdOK {
		t.Fatalf("SEND: expected OK, got 0x%02x", sendCmd.Type)
	}
}

func TestACKDeletesMessageReturnsOK(t *testing.T) {
	addr, cancel := startTestServer(t)
	defer cancel()

	recipientConn := dialSMP(t, addr)
	defer recipientConn.Close()

	recipientPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen recipient key: %v", err)
	}

	recipientID, senderID := createQueueOnConn(t, recipientConn, recipientPub)

	senderConn := dialSMP(t, addr)
	defer senderConn.Close()

	senderPub, senderPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen sender key: %v", err)
	}

	// KEY
	var keyCorrID [24]byte
	if _, err := rand.Read(keyCorrID[:]); err != nil {
		t.Fatalf("corrID: %v", err)
	}
	sendAndReadResponse(t, senderConn, buildKEYBlock(keyCorrID, senderID, senderPub))

	// SEND
	var sendCorrID [24]byte
	if _, err := rand.Read(sendCorrID[:]); err != nil {
		t.Fatalf("corrID: %v", err)
	}
	sendAndReadResponse(t, senderConn, buildSignedSENDBlock(sendCorrID, senderID, senderPriv, []byte("msg1")))

	// Recipient reads MSG
	msgResp := readRawBlock(t, recipientConn)
	msgID, _, _, _ := parseMSGResponse(t, msgResp)

	// ACK
	var ackCorrID [24]byte
	if _, err := rand.Read(ackCorrID[:]); err != nil {
		t.Fatalf("corrID: %v", err)
	}
	ackBlock := buildACKBlock(ackCorrID, recipientID, msgID)
	ackCmd := sendAndReadResponse(t, recipientConn, ackBlock)
	if ackCmd.Type != common.CmdOK {
		t.Fatalf("ACK: expected OK, got 0x%02x", ackCmd.Type)
	}
}

func TestACKDeliversNextPendingMessage(t *testing.T) {
	addr, cancel := startTestServer(t)
	defer cancel()

	recipientConn := dialSMP(t, addr)
	defer recipientConn.Close()

	recipientPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen recipient key: %v", err)
	}

	recipientID, senderID := createQueueOnConn(t, recipientConn, recipientPub)

	senderConn := dialSMP(t, addr)
	defer senderConn.Close()

	senderPub, senderPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen sender key: %v", err)
	}

	// KEY
	var keyCorrID [24]byte
	if _, err := rand.Read(keyCorrID[:]); err != nil {
		t.Fatalf("corrID: %v", err)
	}
	sendAndReadResponse(t, senderConn, buildKEYBlock(keyCorrID, senderID, senderPub))

	// SEND two messages
	for i, content := range []string{"msg1", "msg2"} {
		var corrID [24]byte
		if _, err := rand.Read(corrID[:]); err != nil {
			t.Fatalf("corrID %d: %v", i, err)
		}
		sendAndReadResponse(t, senderConn, buildSignedSENDBlock(corrID, senderID, senderPriv, []byte(content)))
	}

	// Recipient reads first MSG
	msgResp1 := readRawBlock(t, recipientConn)
	msgID1, _, _, body1 := parseMSGResponse(t, msgResp1)
	if string(body1) != "msg1" {
		t.Fatalf("first MSG: got %q, want %q", body1, "msg1")
	}

	// ACK first message - should trigger delivery of second
	var ackCorrID [24]byte
	if _, err := rand.Read(ackCorrID[:]); err != nil {
		t.Fatalf("corrID: %v", err)
	}
	ackBlock := buildACKBlock(ackCorrID, recipientID, msgID1)
	recipientConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := recipientConn.Write(ackBlock[:]); err != nil {
		t.Fatalf("write ACK: %v", err)
	}

	// Should get OK for ACK
	okResp := readRawBlock(t, recipientConn)
	okCmd := parseResponseType(t, okResp)
	if okCmd.Type != common.CmdOK {
		t.Fatalf("ACK: expected OK, got 0x%02x", okCmd.Type)
	}

	// Should get second MSG
	msgResp2 := readRawBlock(t, recipientConn)
	_, _, _, body2 := parseMSGResponse(t, msgResp2)
	if string(body2) != "msg2" {
		t.Fatalf("second MSG: got %q, want %q", body2, "msg2")
	}
}

func TestACKIdempotent(t *testing.T) {
	addr, cancel := startTestServer(t)
	defer cancel()

	conn := dialSMP(t, addr)
	defer conn.Close()

	recipientPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}

	recipientID, _ := createQueueOnConn(t, conn, recipientPub)

	// ACK with a random msgID on a queue with no messages
	var msgID [24]byte
	if _, err := rand.Read(msgID[:]); err != nil {
		t.Fatalf("msgID: %v", err)
	}

	var corrID [24]byte
	if _, err := rand.Read(corrID[:]); err != nil {
		t.Fatalf("corrID: %v", err)
	}
	ackBlock := buildACKBlock(corrID, recipientID, msgID)
	ackCmd := sendAndReadResponse(t, conn, ackBlock)

	if ackCmd.Type != common.CmdOK {
		t.Fatalf("idempotent ACK: expected OK, got 0x%02x", ackCmd.Type)
	}
}

func TestFullCycleNEWtoKEYtoSENDtoMSGtoACK(t *testing.T) {
	addr, cancel := startTestServer(t)
	defer cancel()

	// Recipient creates queue
	recipientConn := dialSMP(t, addr)
	defer recipientConn.Close()

	recipientPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen recipient key: %v", err)
	}

	recipientID, senderID := createQueueOnConn(t, recipientConn, recipientPub)

	// Sender connects
	senderConn := dialSMP(t, addr)
	defer senderConn.Close()

	// KEY
	senderPub, senderPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen sender key: %v", err)
	}

	var keyCorrID [24]byte
	if _, err := rand.Read(keyCorrID[:]); err != nil {
		t.Fatalf("corrID: %v", err)
	}
	keyCmd := sendAndReadResponse(t, senderConn, buildKEYBlock(keyCorrID, senderID, senderPub))
	if keyCmd.Type != common.CmdOK {
		t.Fatalf("KEY: expected OK, got 0x%02x", keyCmd.Type)
	}

	// SEND
	msgContent := []byte("full cycle test message")
	var sendCorrID [24]byte
	if _, err := rand.Read(sendCorrID[:]); err != nil {
		t.Fatalf("corrID: %v", err)
	}
	sendCmd := sendAndReadResponse(t, senderConn, buildSignedSENDBlock(sendCorrID, senderID, senderPriv, msgContent))
	if sendCmd.Type != common.CmdOK {
		t.Fatalf("SEND: expected OK, got 0x%02x", sendCmd.Type)
	}

	// MSG received by recipient
	msgResp := readRawBlock(t, recipientConn)
	msgID, _, _, body := parseMSGResponse(t, msgResp)
	if !bytes.Equal(body, msgContent) {
		t.Fatalf("MSG body: got %q, want %q", body, msgContent)
	}

	// Verify MSG entityID is recipientID
	msgCmd := parseResponseType(t, msgResp)
	if msgCmd.EntityID != recipientID {
		t.Fatal("MSG entityID should be recipientID")
	}

	// ACK
	var ackCorrID [24]byte
	if _, err := rand.Read(ackCorrID[:]); err != nil {
		t.Fatalf("corrID: %v", err)
	}
	ackCmd := sendAndReadResponse(t, recipientConn, buildACKBlock(ackCorrID, recipientID, msgID))
	if ackCmd.Type != common.CmdOK {
		t.Fatalf("ACK: expected OK, got 0x%02x", ackCmd.Type)
	}
}

func TestMultipleMessagesFIFOOrder(t *testing.T) {
	addr, cancel := startTestServer(t)
	defer cancel()

	recipientConn := dialSMP(t, addr)
	defer recipientConn.Close()

	recipientPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}

	recipientID, senderID := createQueueOnConn(t, recipientConn, recipientPub)

	senderConn := dialSMP(t, addr)
	defer senderConn.Close()

	senderPub, senderPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen sender key: %v", err)
	}

	// KEY
	var keyCorrID [24]byte
	if _, err := rand.Read(keyCorrID[:]); err != nil {
		t.Fatalf("corrID: %v", err)
	}
	sendAndReadResponse(t, senderConn, buildKEYBlock(keyCorrID, senderID, senderPub))

	// Send 3 messages
	messages := []string{"first", "second", "third"}
	for _, content := range messages {
		var corrID [24]byte
		if _, err := rand.Read(corrID[:]); err != nil {
			t.Fatalf("corrID: %v", err)
		}
		sendAndReadResponse(t, senderConn, buildSignedSENDBlock(corrID, senderID, senderPriv, []byte(content)))
	}

	// Receive and ACK in order
	for i, expected := range messages {
		msgResp := readRawBlock(t, recipientConn)
		msgID, _, _, body := parseMSGResponse(t, msgResp)

		if string(body) != expected {
			t.Fatalf("message %d: got %q, want %q", i, body, expected)
		}

		var ackCorrID [24]byte
		if _, err := rand.Read(ackCorrID[:]); err != nil {
			t.Fatalf("corrID: %v", err)
		}

		ackBlock := buildACKBlock(ackCorrID, recipientID, msgID)
		recipientConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if _, err := recipientConn.Write(ackBlock[:]); err != nil {
			t.Fatalf("write ACK %d: %v", i, err)
		}

		// Read OK for ACK
		okResp := readRawBlock(t, recipientConn)
		okCmd := parseResponseType(t, okResp)
		if okCmd.Type != common.CmdOK {
			t.Fatalf("ACK %d: expected OK, got 0x%02x", i, okCmd.Type)
		}

		// If not last message, next MSG should arrive (triggered by ACK)
		// For messages after the first, MSG was already delivered via ACK handler
		// For the first message, it was delivered immediately by SEND
	}
}
