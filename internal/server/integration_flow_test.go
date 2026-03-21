package server

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/saschadaemgen/GoRelay/internal/protocol/common"
	"github.com/saschadaemgen/GoRelay/internal/queue"
)

// --- Test Case 1: Complete flow NEW -> KEY -> SEND -> MSG -> ACK ---

func TestIntegrationCompleteFlow(t *testing.T) {
	t.Parallel()

	addr, cancel := startTestServer(t)
	defer cancel()

	// Connection A: recipient creates queue
	connA := dialSMP(t, addr)
	defer connA.Close()

	recipientPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen recipient key: %v", err)
	}

	recipientID, senderID := createQueueOnConn(t, connA, recipientPub)

	// Connection B: sender
	connB := dialSMP(t, addr)
	defer connB.Close()

	senderPub, senderPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen sender key: %v", err)
	}

	// B sets sender key (KEY)
	var keyCorrID [24]byte
	if _, err := rand.Read(keyCorrID[:]); err != nil {
		t.Fatalf("corrID: %v", err)
	}
	keyCmd := sendAndReadResponse(t, connB, buildKEYBlock(keyCorrID, senderID, senderPub))
	if keyCmd.Type != common.CmdOK {
		t.Fatalf("KEY: expected OK, got 0x%02x", keyCmd.Type)
	}

	// B sends message (SEND)
	msgContent := []byte("integration test message")
	var sendCorrID [24]byte
	if _, err := rand.Read(sendCorrID[:]); err != nil {
		t.Fatalf("corrID: %v", err)
	}
	sendCmd := sendAndReadResponse(t, connB, buildSignedSENDBlock(sendCorrID, senderID, senderPriv, msgContent))
	if sendCmd.Type != common.CmdOK {
		t.Fatalf("SEND: expected OK, got 0x%02x", sendCmd.Type)
	}

	// A receives MSG with correct body
	msgResp := readRawBlock(t, connA)
	msgID, _, _, body := parseMSGResponse(t, msgResp)
	if !bytes.Equal(body, msgContent) {
		t.Fatalf("MSG body: got %q, want %q", body, msgContent)
	}

	// A sends ACK
	var ackCorrID [24]byte
	if _, err := rand.Read(ackCorrID[:]); err != nil {
		t.Fatalf("corrID: %v", err)
	}
	ackCmd := sendAndReadResponse(t, connA, buildACKBlock(ackCorrID, recipientID, msgID))
	if ackCmd.Type != common.CmdOK {
		t.Fatalf("ACK: expected OK, got 0x%02x", ackCmd.Type)
	}

	// Verify message is deleted: PING should work, no more MSG
	var pingCorrID [24]byte
	if _, err := rand.Read(pingCorrID[:]); err != nil {
		t.Fatalf("corrID: %v", err)
	}
	pingCmd := sendAndReadResponse(t, connA, buildPINGBlock(pingCorrID))
	if pingCmd.Type != common.CmdPONG {
		t.Fatalf("PING after ACK: expected PONG, got 0x%02x", pingCmd.Type)
	}
}

// --- Test Case 2: Subscription takeover ---

func TestIntegrationSubscriptionTakeover(t *testing.T) {
	t.Parallel()

	addr, cancel := startTestServer(t)
	defer cancel()

	// Connection A: creates queue (implicit subscribe)
	connA := dialSMP(t, addr)
	defer connA.Close()

	recipientPub, recipientPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen recipient key: %v", err)
	}

	recipientID, senderID := createQueueOnConn(t, connA, recipientPub)

	// Connection B: sender sets key
	connB := dialSMP(t, addr)
	defer connB.Close()

	senderPub, senderPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen sender key: %v", err)
	}

	var keyCorrID [24]byte
	if _, err := rand.Read(keyCorrID[:]); err != nil {
		t.Fatalf("corrID: %v", err)
	}
	sendAndReadResponse(t, connB, buildKEYBlock(keyCorrID, senderID, senderPub))

	// Connection C: subscribes to same queue (SUB with valid signature)
	connC := dialSMP(t, addr)
	defer connC.Close()

	var subCorrID [24]byte
	if _, err := rand.Read(subCorrID[:]); err != nil {
		t.Fatalf("corrID: %v", err)
	}
	subBlock := buildSUBBlock(subCorrID, recipientID, recipientPriv)
	connC.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := connC.Write(subBlock[:]); err != nil {
		t.Fatalf("write SUB: %v", err)
	}

	// C should get OK
	subResp := readRawBlock(t, connC)
	subCmd := parseResponseType(t, subResp)
	if subCmd.Type != common.CmdOK {
		t.Fatalf("SUB: expected OK, got 0x%02x", subCmd.Type)
	}

	// A must receive END
	endResp := readRawBlock(t, connA)
	endCmd := parseResponseType(t, endResp)
	if endCmd.Type != common.CmdEND {
		t.Fatalf("connA: expected END (0x%02x), got 0x%02x", common.CmdEND, endCmd.Type)
	}

	// B sends message
	var sendCorrID [24]byte
	if _, err := rand.Read(sendCorrID[:]); err != nil {
		t.Fatalf("corrID: %v", err)
	}
	sendCmd := sendAndReadResponse(t, connB, buildSignedSENDBlock(sendCorrID, senderID, senderPriv, []byte("after takeover")))
	if sendCmd.Type != common.CmdOK {
		t.Fatalf("SEND: expected OK, got 0x%02x", sendCmd.Type)
	}

	// C (not A) receives the MSG
	msgResp := readRawBlock(t, connC)
	_, _, _, body := parseMSGResponse(t, msgResp)
	if string(body) != "after takeover" {
		t.Fatalf("MSG body: got %q, want %q", body, "after takeover")
	}
}

// --- Test Case 3: Multiple messages FIFO order ---

func TestIntegrationFIFOThreeMessages(t *testing.T) {
	t.Parallel()

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

	var keyCorrID [24]byte
	if _, err := rand.Read(keyCorrID[:]); err != nil {
		t.Fatalf("corrID: %v", err)
	}
	sendAndReadResponse(t, senderConn, buildKEYBlock(keyCorrID, senderID, senderPub))

	// Send 3 messages
	messages := []string{"alpha", "bravo", "charlie"}
	for _, content := range messages {
		var corrID [24]byte
		if _, err := rand.Read(corrID[:]); err != nil {
			t.Fatalf("corrID: %v", err)
		}
		sendAndReadResponse(t, senderConn, buildSignedSENDBlock(corrID, senderID, senderPriv, []byte(content)))
	}

	// Receive and ACK each one, verifying FIFO order
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
	}
}

// --- Test Case 4: Idempotency ---

func TestIntegrationNEWIdempotent(t *testing.T) {
	t.Parallel()

	addr, cancel := startTestServer(t)
	defer cancel()

	conn := dialSMP(t, addr)
	defer conn.Close()

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}

	// First NEW
	var corrID1 [24]byte
	if _, err := rand.Read(corrID1[:]); err != nil {
		t.Fatalf("corrID1: %v", err)
	}
	block1 := buildNEWBlock(corrID1, pub)
	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(block1[:]); err != nil {
		t.Fatalf("write NEW 1: %v", err)
	}
	resp1 := readRawBlock(t, conn)
	_, rid1, sid1, dhKey1 := parseIDSResponse(t, resp1)

	// Second NEW with same key
	var corrID2 [24]byte
	if _, err := rand.Read(corrID2[:]); err != nil {
		t.Fatalf("corrID2: %v", err)
	}
	block2 := buildNEWBlock(corrID2, pub)
	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(block2[:]); err != nil {
		t.Fatalf("write NEW 2: %v", err)
	}
	resp2 := readRawBlock(t, conn)
	_, rid2, sid2, dhKey2 := parseIDSResponse(t, resp2)

	if rid1 != rid2 {
		t.Fatal("idempotent NEW returned different recipientID")
	}
	if sid1 != sid2 {
		t.Fatal("idempotent NEW returned different senderID")
	}
	if !bytes.Equal(dhKey1, dhKey2) {
		t.Fatal("idempotent NEW returned different DH key")
	}
}

func TestIntegrationACKIdempotent(t *testing.T) {
	t.Parallel()

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

	var keyCorrID [24]byte
	if _, err := rand.Read(keyCorrID[:]); err != nil {
		t.Fatalf("corrID: %v", err)
	}
	sendAndReadResponse(t, senderConn, buildKEYBlock(keyCorrID, senderID, senderPub))

	// Send a message
	var sendCorrID [24]byte
	if _, err := rand.Read(sendCorrID[:]); err != nil {
		t.Fatalf("corrID: %v", err)
	}
	sendAndReadResponse(t, senderConn, buildSignedSENDBlock(sendCorrID, senderID, senderPriv, []byte("ack-test")))

	// Receive MSG
	msgResp := readRawBlock(t, recipientConn)
	msgID, _, _, _ := parseMSGResponse(t, msgResp)

	// ACK first time
	var ackCorrID1 [24]byte
	if _, err := rand.Read(ackCorrID1[:]); err != nil {
		t.Fatalf("corrID: %v", err)
	}
	ack1 := sendAndReadResponse(t, recipientConn, buildACKBlock(ackCorrID1, recipientID, msgID))
	if ack1.Type != common.CmdOK {
		t.Fatalf("first ACK: expected OK, got 0x%02x", ack1.Type)
	}

	// ACK same message again (already deleted) - should still return OK
	var ackCorrID2 [24]byte
	if _, err := rand.Read(ackCorrID2[:]); err != nil {
		t.Fatalf("corrID: %v", err)
	}
	ack2 := sendAndReadResponse(t, recipientConn, buildACKBlock(ackCorrID2, recipientID, msgID))
	if ack2.Type != common.CmdOK {
		t.Fatalf("second ACK (idempotent): expected OK, got 0x%02x", ack2.Type)
	}
}

// --- Test Case 5: Error cases ---

func TestIntegrationSENDBeforeKEY(t *testing.T) {
	t.Parallel()

	addr, cancel := startTestServer(t)
	defer cancel()

	conn := dialSMP(t, addr)
	defer conn.Close()

	recipientPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}

	_, senderID := createQueueOnConn(t, conn, recipientPub)

	_, senderPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen sender key: %v", err)
	}

	var corrID [24]byte
	if _, err := rand.Read(corrID[:]); err != nil {
		t.Fatalf("corrID: %v", err)
	}

	cmd := sendAndReadResponse(t, conn, buildSignedSENDBlock(corrID, senderID, senderPriv, []byte("too early")))
	if cmd.Type != common.CmdERR {
		t.Fatalf("SEND before KEY: expected ERR, got 0x%02x", cmd.Type)
	}
	if len(cmd.Body) < 1 || cmd.Body[0] != common.ErrNoKey {
		t.Fatalf("expected NO_KEY error, got body: %v", cmd.Body)
	}
}

func TestIntegrationSUBNonexistentQueue(t *testing.T) {
	t.Parallel()

	addr, cancel := startTestServer(t)
	defer cancel()

	conn := dialSMP(t, addr)
	defer conn.Close()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}

	var fakeRecipientID [24]byte
	if _, err := rand.Read(fakeRecipientID[:]); err != nil {
		t.Fatalf("fakeID: %v", err)
	}

	var corrID [24]byte
	if _, err := rand.Read(corrID[:]); err != nil {
		t.Fatalf("corrID: %v", err)
	}

	cmd := sendAndReadResponse(t, conn, buildSUBBlock(corrID, fakeRecipientID, priv))
	if cmd.Type != common.CmdERR {
		t.Fatalf("SUB nonexistent: expected ERR, got 0x%02x", cmd.Type)
	}
	if len(cmd.Body) < 1 || cmd.Body[0] != common.ErrNoQueue {
		t.Fatalf("expected NO_QUEUE error, got body: %v", cmd.Body)
	}
}

func TestIntegrationKEYTwice(t *testing.T) {
	t.Parallel()

	addr, cancel := startTestServer(t)
	defer cancel()

	conn := dialSMP(t, addr)
	defer conn.Close()

	recipientPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}

	_, senderID := createQueueOnConn(t, conn, recipientPub)

	senderPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen sender key: %v", err)
	}

	// First KEY
	var corrID1 [24]byte
	if _, err := rand.Read(corrID1[:]); err != nil {
		t.Fatalf("corrID: %v", err)
	}
	cmd1 := sendAndReadResponse(t, conn, buildKEYBlock(corrID1, senderID, senderPub))
	if cmd1.Type != common.CmdOK {
		t.Fatalf("first KEY: expected OK, got 0x%02x", cmd1.Type)
	}

	// Second KEY
	senderPub2, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen sender key 2: %v", err)
	}
	var corrID2 [24]byte
	if _, err := rand.Read(corrID2[:]); err != nil {
		t.Fatalf("corrID: %v", err)
	}
	cmd2 := sendAndReadResponse(t, conn, buildKEYBlock(corrID2, senderID, senderPub2))
	if cmd2.Type != common.CmdERR {
		t.Fatalf("second KEY: expected ERR, got 0x%02x", cmd2.Type)
	}
	if len(cmd2.Body) < 1 || cmd2.Body[0] != common.ErrAuth {
		t.Fatalf("expected AUTH error, got body: %v", cmd2.Body)
	}
}

func TestIntegrationSUBInvalidSignature(t *testing.T) {
	t.Parallel()

	addr, cancel := startTestServer(t)
	defer cancel()

	conn := dialSMP(t, addr)
	defer conn.Close()

	recipientPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}

	recipientID, _ := createQueueOnConn(t, conn, recipientPub)

	// Use wrong key to sign SUB
	_, wrongPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen wrong key: %v", err)
	}

	// SUB from a new connection with wrong signature
	conn2 := dialSMP(t, addr)
	defer conn2.Close()

	var corrID [24]byte
	if _, err := rand.Read(corrID[:]); err != nil {
		t.Fatalf("corrID: %v", err)
	}

	cmd := sendAndReadResponse(t, conn2, buildSUBBlock(corrID, recipientID, wrongPriv))
	if cmd.Type != common.CmdERR {
		t.Fatalf("SUB invalid sig: expected ERR, got 0x%02x", cmd.Type)
	}
	if len(cmd.Body) < 1 || cmd.Body[0] != common.ErrAuth {
		t.Fatalf("expected AUTH error, got body: %v", cmd.Body)
	}
}

// --- Test Case 6: Message delivery on SUB (re-subscribe) ---

func TestIntegrationSUBDeliversPendingMessage(t *testing.T) {
	t.Parallel()

	addr, cancel := startTestServer(t)
	defer cancel()

	// Create queue on connA, then close it so no subscriber
	connA := dialSMP(t, addr)

	recipientPub, recipientPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen recipient key: %v", err)
	}

	recipientID, senderID := createQueueOnConn(t, connA, recipientPub)
	connA.Close()
	time.Sleep(50 * time.Millisecond) // allow server to process disconnect

	// Sender connects and sends a message (no subscriber)
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
	sendAndReadResponse(t, senderConn, buildKEYBlock(keyCorrID, senderID, senderPub))

	var sendCorrID [24]byte
	if _, err := rand.Read(sendCorrID[:]); err != nil {
		t.Fatalf("corrID: %v", err)
	}
	sendCmd := sendAndReadResponse(t, senderConn, buildSignedSENDBlock(sendCorrID, senderID, senderPriv, []byte("pending msg")))
	if sendCmd.Type != common.CmdOK {
		t.Fatalf("SEND: expected OK, got 0x%02x", sendCmd.Type)
	}

	// New connection SUBs to queue - should receive pending MSG immediately
	connNew := dialSMP(t, addr)
	defer connNew.Close()

	var subCorrID [24]byte
	if _, err := rand.Read(subCorrID[:]); err != nil {
		t.Fatalf("corrID: %v", err)
	}
	subBlock := buildSUBBlock(subCorrID, recipientID, recipientPriv)
	connNew.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := connNew.Write(subBlock[:]); err != nil {
		t.Fatalf("write SUB: %v", err)
	}

	// SUB should return MSG (pending message) instead of OK
	resp := readRawBlock(t, connNew)
	cmd := parseResponseType(t, resp)
	if cmd.Type != common.CmdMSG {
		t.Fatalf("SUB with pending msg: expected MSG (0x%02x), got 0x%02x", common.CmdMSG, cmd.Type)
	}

	_, _, _, body := parseMSGResponse(t, resp)
	if string(body) != "pending msg" {
		t.Fatalf("pending MSG body: got %q, want %q", body, "pending msg")
	}
}

// --- Test Case 7: Delivery counter tracking ---

func TestDeliveryAttemptsAutoDiscard(t *testing.T) {
	t.Parallel()

	store := queue.NewMemoryStore()

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}

	q, err := store.CreateQueue(pub)
	if err != nil {
		t.Fatalf("create queue: %v", err)
	}

	// Set sender key so we can push
	senderPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen sender key: %v", err)
	}
	if err := store.SetSenderKey(q.SenderID, senderPub); err != nil {
		t.Fatalf("set sender key: %v", err)
	}

	// Push a message
	msg, err := store.PushMessage(q.SenderID, 0, []byte("bomb"))
	if err != nil {
		t.Fatalf("push message: %v", err)
	}

	originalID := msg.ID

	// Pop the message MaxDeliveryAttempts-1 times (should still be available)
	for i := 0; i < queue.MaxDeliveryAttempts-1; i++ {
		peeked, peekErr := store.PopMessage(q.RecipientID)
		if peekErr != nil {
			t.Fatalf("pop %d: unexpected error: %v", i, peekErr)
		}
		if peeked.ID != originalID {
			t.Fatalf("pop %d: wrong message ID", i)
		}
		if peeked.DeliveryAttempts != i+1 {
			t.Fatalf("pop %d: delivery attempts = %d, want %d", i, peeked.DeliveryAttempts, i+1)
		}
	}

	// Next pop should auto-discard (attempts == MaxDeliveryAttempts)
	_, err = store.PopMessage(q.RecipientID)
	if err != queue.ErrNoMessage {
		t.Fatalf("after max deliveries: expected ErrNoMessage, got %v", err)
	}
}

func TestDeliveryAttemptsAutoDiscardRevealsNext(t *testing.T) {
	t.Parallel()

	store := queue.NewMemoryStore()

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}

	q, err := store.CreateQueue(pub)
	if err != nil {
		t.Fatalf("create queue: %v", err)
	}

	senderPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen sender key: %v", err)
	}
	if err := store.SetSenderKey(q.SenderID, senderPub); err != nil {
		t.Fatalf("set sender key: %v", err)
	}

	// Push two messages
	msg1, err := store.PushMessage(q.SenderID, 0, []byte("bad"))
	if err != nil {
		t.Fatalf("push msg1: %v", err)
	}

	msg2, err := store.PushMessage(q.SenderID, 0, []byte("good"))
	if err != nil {
		t.Fatalf("push msg2: %v", err)
	}

	_ = msg1

	// Exhaust delivery attempts on msg1
	for i := 0; i < queue.MaxDeliveryAttempts-1; i++ {
		_, popErr := store.PopMessage(q.RecipientID)
		if popErr != nil {
			t.Fatalf("pop %d: %v", i, popErr)
		}
	}

	// Next pop should discard msg1 and return msg2
	result, err := store.PopMessage(q.RecipientID)
	if err != nil {
		t.Fatalf("expected msg2, got error: %v", err)
	}
	if result.ID != msg2.ID {
		t.Fatal("expected msg2 after msg1 auto-discarded")
	}
	if string(result.Body) != "good" {
		t.Fatalf("msg2 body: got %q, want %q", result.Body, "good")
	}
}

func TestIntegrationDeliveryCounterViaNetwork(t *testing.T) {
	t.Parallel()

	addr, cancel := startTestServer(t)
	defer cancel()

	recipientPub, recipientPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen recipient key: %v", err)
	}

	// Create queue on connA, close it
	connA := dialSMP(t, addr)
	_, senderID := createQueueOnConn(t, connA, recipientPub)
	recipientID := func() [24]byte {
		// Re-read from IDS - we need recipientID from createQueueOnConn
		// Actually createQueueOnConn returns it
		return [24]byte{} // placeholder
	}()
	// Actually let me redo this properly
	connA.Close()

	// Start fresh
	addr2, cancel2 := startTestServer(t)
	defer cancel2()

	connCreate := dialSMP(t, addr2)
	recipientID, senderID = createQueueOnConn(t, connCreate, recipientPub)
	connCreate.Close()
	time.Sleep(50 * time.Millisecond)

	// Sender sends a message
	senderConn := dialSMP(t, addr2)
	defer senderConn.Close()

	senderPub, senderPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen sender key: %v", err)
	}

	var keyCorrID [24]byte
	if _, err := rand.Read(keyCorrID[:]); err != nil {
		t.Fatalf("corrID: %v", err)
	}
	sendAndReadResponse(t, senderConn, buildKEYBlock(keyCorrID, senderID, senderPub))

	var sendCorrID [24]byte
	if _, err := rand.Read(sendCorrID[:]); err != nil {
		t.Fatalf("corrID: %v", err)
	}
	sendAndReadResponse(t, senderConn, buildSignedSENDBlock(sendCorrID, senderID, senderPriv, []byte("redelivery test")))

	// SUB, receive MSG, disconnect (no ACK) - repeat until message is discarded
	for attempt := 0; attempt < queue.MaxDeliveryAttempts; attempt++ {
		subConn := dialSMP(t, addr2)

		var subCorrID [24]byte
		if _, err := rand.Read(subCorrID[:]); err != nil {
			t.Fatalf("corrID: %v", err)
		}
		subBlock := buildSUBBlock(subCorrID, recipientID, recipientPriv)
		subConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if _, err := subConn.Write(subBlock[:]); err != nil {
			t.Fatalf("attempt %d: write SUB: %v", attempt, err)
		}

		resp := readRawBlock(t, subConn)
		cmd := parseResponseType(t, resp)

		if attempt < queue.MaxDeliveryAttempts-1 {
			// Should still get MSG
			if cmd.Type != common.CmdMSG {
				t.Fatalf("attempt %d: expected MSG, got 0x%02x", attempt, cmd.Type)
			}
		} else {
			// Last attempt: message should have been discarded, get OK
			if cmd.Type != common.CmdOK {
				t.Fatalf("attempt %d (final): expected OK (msg discarded), got 0x%02x", attempt, cmd.Type)
			}
		}

		subConn.Close()
		time.Sleep(50 * time.Millisecond)
	}
}
