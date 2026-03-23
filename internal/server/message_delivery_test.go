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
	"github.com/saschadaemgen/GoRelay/internal/protocol/smp"
)

// buildKEYBlock constructs a 16KB block containing a KEY command.
// KEY is a recipient command - entityID = recipientID.
// Body: shortString(SPKI DER Ed25519 sender key)
func buildKEYBlock(corrID [24]byte, recipientID [24]byte, senderPubKey ed25519.PublicKey) [common.BlockSize]byte {
	keySPKI := smp.EncodeEd25519SPKI(senderPubKey)
	body := make([]byte, 0, 1+len(keySPKI))
	body = append(body, byte(len(keySPKI)))
	body = append(body, keySPKI...)

	t := common.BuildTransmission(nil, corrID, recipientID[:], common.TagKEY, body)
	return common.WrapTransmissionBlock(t)
}

// buildSignedSENDBlock constructs a signed SEND command block.
// The SEND body wire format is: smpFlags + SP(0x20) + smpEncMessage
// msgBody is the raw message content; this function prepends empty flags + SP.
// The signature covers: shortString(sessionID) + corrId + entityId + "SEND " + wireBody
func buildSignedSENDBlock(corrID [24]byte, senderID [24]byte, privKey ed25519.PrivateKey, msgBody []byte, sessionID ...[]byte) [common.BlockSize]byte {
	var sessID []byte
	if len(sessionID) > 0 {
		sessID = sessionID[0]
	}

	// Wire body: empty flags + SP + message content
	wireBody := make([]byte, 0, 1+len(msgBody))
	wireBody = append(wireBody, 0x20) // empty flags + SP
	wireBody = append(wireBody, msgBody...)

	// Build signed data with sessionID
	signedData := common.BuildSignedData(sessID, corrID, senderID[:], common.TagSEND, wireBody)
	sig := ed25519.Sign(privKey, signedData)

	// Build wire transmission (sessionID NOT in wire)
	t := common.BuildTransmission(sig, corrID, senderID[:], common.TagSEND, wireBody)
	return common.WrapTransmissionBlock(t)
}

// buildACKBlock constructs an ACK command block.
// Body: shortString(msgID)
func buildACKBlock(corrID [24]byte, recipientID [24]byte, msgID [24]byte) [common.BlockSize]byte {
	body := make([]byte, 0, 25)
	body = append(body, 24) // shortString length
	body = append(body, msgID[:]...)

	t := common.BuildTransmission(nil, corrID, recipientID[:], common.TagACK, body)
	return common.WrapTransmissionBlock(t)
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
// The MSG body is now NaCl secretbox encrypted. Use parseMSGResponseEncrypted
// with the DH shared key to decrypt and get the original body content.
func parseMSGResponse(t *testing.T, block [common.BlockSize]byte) (msgID [24]byte, timestamp uint64, flags byte, body []byte) {
	t.Helper()
	cmd := parseResponseType(t, block)
	if cmd.Type != common.CmdMSG {
		t.Fatalf("expected MSG (0x%02x), got 0x%02x", common.CmdMSG, cmd.Type)
	}
	// MSG wire format: shortString(msgId) + encryptedRcvMsgBody
	mBody := cmd.Body
	if len(mBody) < 1 {
		t.Fatalf("MSG body too short: %d", len(mBody))
	}
	mIDLen := int(mBody[0])
	if 1+mIDLen > len(mBody) || mIDLen < 24 {
		t.Fatalf("MSG body too short for msgId: len=%d, mIDLen=%d", len(mBody), mIDLen)
	}
	copy(msgID[:], mBody[1:1+24])
	// Remaining bytes are encrypted body (no timestamp/flags in cleartext)
	body = mBody[1+mIDLen:]
	return
}

// parseMSGResponseEncrypted extracts and decrypts MSG fields from a raw block.
// dhSharedKey is the raw X25519 DH shared secret from ECDH().
func parseMSGResponseEncrypted(t *testing.T, block [common.BlockSize]byte, dhSharedKey [32]byte) (msgID [24]byte, timestamp uint64, flags byte, body []byte) {
	t.Helper()
	cmd := parseResponseType(t, block)
	if cmd.Type != common.CmdMSG {
		t.Fatalf("expected MSG (0x%02x), got 0x%02x", common.CmdMSG, cmd.Type)
	}
	// MSG wire format: shortString(msgId) + timestamp(12) + flagsByte(1) + encryptedRcvMsgBody
	mBody := cmd.Body
	if len(mBody) < 1 {
		t.Fatalf("MSG body too short: %d", len(mBody))
	}
	mIDLen := int(mBody[0])
	if 1+mIDLen+13 > len(mBody) || mIDLen < 24 {
		t.Fatalf("MSG body too short for msgId+ts+flags: len=%d, mIDLen=%d", len(mBody), mIDLen)
	}
	copy(msgID[:], mBody[1:1+24])
	off := 1 + mIDLen
	// Skip cleartext timestamp (12 bytes) and flags (1 byte)
	off += 13
	encrypted := mBody[off:]

	// Decrypt with SimpleX custom XSalsa20 variant
	decrypted, ok := smp.SimplexCryptoBoxOpen(dhSharedKey, msgID, encrypted)
	if !ok {
		t.Fatalf("SimplexCryptoBoxOpen failed on MSG body (encrypted len=%d)", len(encrypted))
	}

	// Decrypted is padded: uint16BE(rcvMsgBodyLen) + rcvMsgBody + zero padding
	if len(decrypted) < 2 {
		t.Fatalf("decrypted MSG too short: %d", len(decrypted))
	}
	rcvLen := int(binary.BigEndian.Uint16(decrypted[0:2]))
	if 2+rcvLen > len(decrypted) {
		t.Fatalf("decrypted MSG rcvLen=%d exceeds buffer %d", rcvLen, len(decrypted))
	}
	rcvBody := decrypted[2 : 2+rcvLen]

	// rcvMsgBody = timestamp(12) + flagsByte(1) + uint16BE(2) + smpEncMessage
	if len(rcvBody) < 15 {
		t.Fatalf("rcvMsgBody too short: %d", len(rcvBody))
	}
	timestamp = binary.BigEndian.Uint64(rcvBody[0:8])
	// skip nanoseconds at rcvBody[8:12]
	flags = rcvBody[12]
	// skip uint16BE length prefix at rcvBody[13:15]
	body = rcvBody[15:]
	return
}

func TestKEYSetsSenderKeyReturnsOK(t *testing.T) {
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
		t.Fatalf("KEY: expected OK, got 0x%02x", cmd.Type)
	}
}

func TestKEYTwiceReturnsAuthError(t *testing.T) {
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

	var corrID1 [24]byte
	if _, err := rand.Read(corrID1[:]); err != nil {
		t.Fatal(err)
	}
	cmd1 := sendAndReadResponse(t, conn, buildKEYBlock(corrID1, recipientID, senderPub))
	if cmd1.Type != common.CmdOK {
		t.Fatalf("KEY 1: expected OK, got 0x%02x", cmd1.Type)
	}

	var corrID2 [24]byte
	if _, err := rand.Read(corrID2[:]); err != nil {
		t.Fatal(err)
	}
	cmd2 := sendAndReadResponse(t, conn, buildKEYBlock(corrID2, recipientID, senderPub))
	if cmd2.Type != common.CmdERR {
		t.Fatalf("KEY 2: expected ERR, got 0x%02x", cmd2.Type)
	}
	if string(cmd2.Body) != "AUTH" {
		t.Fatalf("KEY 2: expected AUTH error, got body: %q", string(cmd2.Body))
	}
}

func TestSENDWithoutKEYAllowsConfirmation(t *testing.T) {
	addr, cancel := startTestServer(t)
	defer cancel()

	conn, _ := dialSMPWithSession(t, addr)
	defer conn.Close()

	recipientPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	_, senderID := createQueueOnConn(t, conn, recipientPub)

	// Send unsigned SEND (no KEY set yet) - should succeed as confirmation message
	var corrID [24]byte
	if _, err := rand.Read(corrID[:]); err != nil {
		t.Fatal(err)
	}

	sendBody := []byte("confirmation")
	transmission := common.BuildTransmission(nil, corrID, senderID[:], common.TagSEND, sendBody)
	block := common.WrapTransmissionBlock(transmission)
	cmd := sendAndReadResponse(t, conn, block)
	if cmd.Type != common.CmdOK {
		t.Fatalf("SEND without KEY: expected OK, got 0x%02x (body: %q)", cmd.Type, string(cmd.Body))
	}
}

func TestSENDWithValidSignatureReturnsOK(t *testing.T) {
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

	// Set sender key (KEY uses recipientID as entityID)
	var keyCorrID [24]byte
	if _, err := rand.Read(keyCorrID[:]); err != nil {
		t.Fatal(err)
	}
	keyCmd := sendAndReadResponse(t, conn, buildKEYBlock(keyCorrID, recipientID, senderPub))
	if keyCmd.Type != common.CmdOK {
		t.Fatalf("KEY: expected OK, got 0x%02x", keyCmd.Type)
	}

	// Send message
	var sendCorrID [24]byte
	if _, err := rand.Read(sendCorrID[:]); err != nil {
		t.Fatal(err)
	}
	sendCmd := sendAndReadResponse(t, conn, buildSignedSENDBlock(sendCorrID, senderID, senderPriv, []byte("hello"), sessID))
	if sendCmd.Type != common.CmdOK {
		t.Fatalf("SEND: expected OK, got 0x%02x (body=%v)", sendCmd.Type, sendCmd.Body)
	}
}

func TestSENDDeliversMSGToSubscribedRecipient(t *testing.T) {
	addr, cancel := startTestServer(t)
	defer cancel()

	// Connection A: recipient
	connA := dialSMP(t, addr)
	defer connA.Close()

	recipientPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	recipientID, senderID, dhKey := createQueueOnConnWithDH(t, connA, recipientPub)

	// Connection B: sender
	connB, sessBID := dialSMPWithSession(t, addr)
	defer connB.Close()

	senderPub, senderPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// KEY
	var keyCorrID [24]byte
	if _, err := rand.Read(keyCorrID[:]); err != nil {
		t.Fatal(err)
	}
	keyCmd := sendAndReadResponse(t, connB, buildKEYBlock(keyCorrID, recipientID, senderPub))
	if keyCmd.Type != common.CmdOK {
		t.Fatalf("KEY: expected OK, got 0x%02x", keyCmd.Type)
	}

	// SEND
	msgContent := []byte("hello world")
	var sendCorrID [24]byte
	if _, err := rand.Read(sendCorrID[:]); err != nil {
		t.Fatal(err)
	}
	sendCmd := sendAndReadResponse(t, connB, buildSignedSENDBlock(sendCorrID, senderID, senderPriv, msgContent, sessBID))
	if sendCmd.Type != common.CmdOK {
		t.Fatalf("SEND: expected OK, got 0x%02x", sendCmd.Type)
	}

	// A receives MSG
	msgResp := readRawBlock(t, connA)
	_, _, _, body := parseMSGResponseEncrypted(t, msgResp, dhKey)
	if !bytes.Equal(body, msgContent) {
		t.Fatalf("MSG body: got %q, want %q", body, msgContent)
	}

}

func TestSENDWhenRecipientNotSubscribed(t *testing.T) {
	addr, cancel := startTestServer(t)
	defer cancel()

	// Create queue on conn A
	connA := dialSMP(t, addr)
	recipientPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	recipientID, senderID := createQueueOnConn(t, connA, recipientPub)
	connA.Close() // disconnect recipient

	time.Sleep(50 * time.Millisecond) // let server process disconnect

	// Sender on conn B
	connB, sessBID := dialSMPWithSession(t, addr)
	defer connB.Close()

	senderPub, senderPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	var keyCorrID [24]byte
	if _, err := rand.Read(keyCorrID[:]); err != nil {
		t.Fatal(err)
	}
	keyCmd := sendAndReadResponse(t, connB, buildKEYBlock(keyCorrID, recipientID, senderPub))
	if keyCmd.Type != common.CmdOK {
		t.Fatalf("KEY: expected OK, got 0x%02x", keyCmd.Type)
	}

	var sendCorrID [24]byte
	if _, err := rand.Read(sendCorrID[:]); err != nil {
		t.Fatal(err)
	}
	sendCmd := sendAndReadResponse(t, connB, buildSignedSENDBlock(sendCorrID, senderID, senderPriv, []byte("queued"), sessBID))
	if sendCmd.Type != common.CmdOK {
		t.Fatalf("SEND: expected OK (message queued), got 0x%02x", sendCmd.Type)
	}
}

func TestACKDeletesMessageReturnsOK(t *testing.T) {
	addr, cancel := startTestServer(t)
	defer cancel()

	connA := dialSMP(t, addr)
	defer connA.Close()

	recipientPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	recipientID, senderID := createQueueOnConn(t, connA, recipientPub)

	connB, sessBID := dialSMPWithSession(t, addr)
	defer connB.Close()

	senderPub, senderPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	var keyCorrID [24]byte
	if _, err := rand.Read(keyCorrID[:]); err != nil {
		t.Fatal(err)
	}
	sendAndReadResponse(t, connB, buildKEYBlock(keyCorrID, recipientID, senderPub))

	var sendCorrID [24]byte
	if _, err := rand.Read(sendCorrID[:]); err != nil {
		t.Fatal(err)
	}
	sendAndReadResponse(t, connB, buildSignedSENDBlock(sendCorrID, senderID, senderPriv, []byte("to-ack"), sessBID))

	// A receives MSG
	msgResp := readRawBlock(t, connA)
	msgID, _, _, _ := parseMSGResponse(t, msgResp)

	// A sends ACK
	var ackCorrID [24]byte
	if _, err := rand.Read(ackCorrID[:]); err != nil {
		t.Fatal(err)
	}
	ackCmd := sendAndReadResponse(t, connA, buildACKBlock(ackCorrID, recipientID, msgID))
	if ackCmd.Type != common.CmdOK {
		t.Fatalf("ACK: expected OK, got 0x%02x", ackCmd.Type)
	}
}

func TestACKDeliversNextPendingMessage(t *testing.T) {
	addr, cancel := startTestServer(t)
	defer cancel()

	connA := dialSMP(t, addr)
	defer connA.Close()

	recipientPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	recipientID, senderID, dhKey := createQueueOnConnWithDH(t, connA, recipientPub)

	connB, sessBID := dialSMPWithSession(t, addr)
	defer connB.Close()

	senderPub, senderPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	var keyCorrID [24]byte
	if _, err := rand.Read(keyCorrID[:]); err != nil {
		t.Fatal(err)
	}
	sendAndReadResponse(t, connB, buildKEYBlock(keyCorrID, recipientID, senderPub))

	// Send two messages
	for i := 0; i < 2; i++ {
		var corrID [24]byte
		if _, err := rand.Read(corrID[:]); err != nil {
			t.Fatal(err)
		}
		msg := []byte("msg-" + string(rune('A'+i)))
		cmd := sendAndReadResponse(t, connB, buildSignedSENDBlock(corrID, senderID, senderPriv, msg, sessBID))
		if cmd.Type != common.CmdOK {
			t.Fatalf("SEND %d: expected OK, got 0x%02x", i, cmd.Type)
		}
	}

	// A receives first MSG
	msgResp1 := readRawBlock(t, connA)
	msgID1, _, _, body1 := parseMSGResponseEncrypted(t, msgResp1, dhKey)
	if !bytes.Equal(body1, []byte("msg-A")) {
		t.Fatalf("first MSG body: got %q", body1)
	}

	// A sends ACK for first message
	var ackCorrID [24]byte
	if _, err := rand.Read(ackCorrID[:]); err != nil {
		t.Fatal(err)
	}
	ackCmd := sendAndReadResponse(t, connA, buildACKBlock(ackCorrID, recipientID, msgID1))
	if ackCmd.Type != common.CmdOK {
		t.Fatalf("ACK: expected OK, got 0x%02x", ackCmd.Type)
	}

	// A should receive second MSG
	msgResp2 := readRawBlock(t, connA)
	_, _, _, body2 := parseMSGResponseEncrypted(t, msgResp2, dhKey)
	if !bytes.Equal(body2, []byte("msg-B")) {
		t.Fatalf("second MSG body: got %q", body2)
	}
}

func TestACKIdempotent(t *testing.T) {
	addr, cancel := startTestServer(t)
	defer cancel()

	connA := dialSMP(t, addr)
	defer connA.Close()

	recipientPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	recipientID, senderID := createQueueOnConn(t, connA, recipientPub)

	connB, sessBID := dialSMPWithSession(t, addr)
	defer connB.Close()

	senderPub, senderPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	var keyCorrID [24]byte
	if _, err := rand.Read(keyCorrID[:]); err != nil {
		t.Fatal(err)
	}
	sendAndReadResponse(t, connB, buildKEYBlock(keyCorrID, recipientID, senderPub))

	var sendCorrID [24]byte
	if _, err := rand.Read(sendCorrID[:]); err != nil {
		t.Fatal(err)
	}
	sendAndReadResponse(t, connB, buildSignedSENDBlock(sendCorrID, senderID, senderPriv, []byte("ack-me"), sessBID))

	msgResp := readRawBlock(t, connA)
	msgID, _, _, _ := parseMSGResponse(t, msgResp)

	// First ACK
	var ack1 [24]byte
	if _, err := rand.Read(ack1[:]); err != nil {
		t.Fatal(err)
	}
	cmd1 := sendAndReadResponse(t, connA, buildACKBlock(ack1, recipientID, msgID))
	if cmd1.Type != common.CmdOK {
		t.Fatalf("ACK 1: expected OK, got 0x%02x", cmd1.Type)
	}

	// Second ACK (idempotent)
	var ack2 [24]byte
	if _, err := rand.Read(ack2[:]); err != nil {
		t.Fatal(err)
	}
	cmd2 := sendAndReadResponse(t, connA, buildACKBlock(ack2, recipientID, msgID))
	if cmd2.Type != common.CmdOK {
		t.Fatalf("ACK 2: expected OK (idempotent), got 0x%02x", cmd2.Type)
	}
}

func TestFullCycleNEWtoKEYtoSENDtoMSGtoACK(t *testing.T) {
	addr, cancel := startTestServer(t)
	defer cancel()

	connA := dialSMP(t, addr)
	defer connA.Close()

	recipientPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	recipientID, senderID, dhKey := createQueueOnConnWithDH(t, connA, recipientPub)

	connB, sessBID := dialSMPWithSession(t, addr)
	defer connB.Close()

	senderPub, senderPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// KEY
	var keyCorrID [24]byte
	if _, err := rand.Read(keyCorrID[:]); err != nil {
		t.Fatal(err)
	}
	keyCmd := sendAndReadResponse(t, connB, buildKEYBlock(keyCorrID, recipientID, senderPub))
	if keyCmd.Type != common.CmdOK {
		t.Fatalf("KEY: expected OK, got 0x%02x", keyCmd.Type)
	}

	// SEND
	msgContent := []byte("full cycle test")
	var sendCorrID [24]byte
	if _, err := rand.Read(sendCorrID[:]); err != nil {
		t.Fatal(err)
	}
	sendCmd := sendAndReadResponse(t, connB, buildSignedSENDBlock(sendCorrID, senderID, senderPriv, msgContent, sessBID))
	if sendCmd.Type != common.CmdOK {
		t.Fatalf("SEND: expected OK, got 0x%02x", sendCmd.Type)
	}

	// A receives MSG
	msgResp := readRawBlock(t, connA)
	msgID, _, _, body := parseMSGResponseEncrypted(t, msgResp, dhKey)
	if !bytes.Equal(body, msgContent) {
		t.Fatalf("MSG body: got %q, want %q", body, msgContent)
	}

	// A ACKs
	var ackCorrID [24]byte
	if _, err := rand.Read(ackCorrID[:]); err != nil {
		t.Fatal(err)
	}
	ackCmd := sendAndReadResponse(t, connA, buildACKBlock(ackCorrID, recipientID, msgID))
	if ackCmd.Type != common.CmdOK {
		t.Fatalf("ACK: expected OK, got 0x%02x", ackCmd.Type)
	}

	// PING should work, no more MSG
	var pingCorrID [24]byte
	if _, err := rand.Read(pingCorrID[:]); err != nil {
		t.Fatal(err)
	}
	pingCmd := sendAndReadResponse(t, connA, buildPINGBlock(pingCorrID))
	if pingCmd.Type != common.CmdPONG {
		t.Fatalf("PING: expected PONG, got 0x%02x", pingCmd.Type)
	}
}

func TestMultipleMessagesFIFOOrder(t *testing.T) {
	addr, cancel := startTestServer(t)
	defer cancel()

	connA := dialSMP(t, addr)
	defer connA.Close()

	recipientPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	recipientID, senderID, dhKey := createQueueOnConnWithDH(t, connA, recipientPub)

	connB, sessBID := dialSMPWithSession(t, addr)
	defer connB.Close()

	senderPub, senderPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	var keyCorrID [24]byte
	if _, err := rand.Read(keyCorrID[:]); err != nil {
		t.Fatal(err)
	}
	sendAndReadResponse(t, connB, buildKEYBlock(keyCorrID, recipientID, senderPub))

	msgs := []string{"first", "second", "third"}
	for _, m := range msgs {
		var corrID [24]byte
		if _, err := rand.Read(corrID[:]); err != nil {
			t.Fatal(err)
		}
		cmd := sendAndReadResponse(t, connB, buildSignedSENDBlock(corrID, senderID, senderPriv, []byte(m), sessBID))
		if cmd.Type != common.CmdOK {
			t.Fatalf("SEND %q: expected OK, got 0x%02x", m, cmd.Type)
		}
	}

	// Receive and ACK all messages in FIFO order
	for i, expected := range msgs {
		resp := readRawBlock(t, connA)
		msgID, _, _, body := parseMSGResponseEncrypted(t, resp, dhKey)
		if !bytes.Equal(body, []byte(expected)) {
			t.Fatalf("msg %d: got %q, want %q", i, body, expected)
		}

		var ackCorrID [24]byte
		if _, err := rand.Read(ackCorrID[:]); err != nil {
			t.Fatal(err)
		}
		ackCmd := sendAndReadResponse(t, connA, buildACKBlock(ackCorrID, recipientID, msgID))
		if ackCmd.Type != common.CmdOK {
			t.Fatalf("ACK %d: expected OK, got 0x%02x", i, ackCmd.Type)
		}
	}
}
