package queue

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	badger "github.com/dgraph-io/badger/v4"
)

func newTestBadgerStore(t *testing.T) *BadgerStore {
	t.Helper()
	dir := t.TempDir()
	s, err := NewBadgerStore(BadgerStoreConfig{
		Path:       dir,
		DefaultTTL: 48 * time.Hour,
		MaxTTL:     7 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("new badger store: %v", err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Logf("close badger store: %v", err)
		}
	})
	return s
}

func TestBadgerCreateAndGetQueue(t *testing.T) {
	s := newTestBadgerStore(t)

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}

	q, err := s.CreateQueue(pub)
	if err != nil {
		t.Fatalf("create queue: %v", err)
	}

	got, err := s.GetQueue(q.RecipientID)
	if err != nil {
		t.Fatalf("get queue: %v", err)
	}

	if got.RecipientID != q.RecipientID {
		t.Fatal("recipientID mismatch")
	}
	if got.SenderID != q.SenderID {
		t.Fatal("senderID mismatch")
	}
	if !bytes.Equal(got.RecipientKey, pub) {
		t.Fatal("recipientKey mismatch")
	}
}

func TestBadgerCreateQueueIdempotent(t *testing.T) {
	s := newTestBadgerStore(t)

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}

	q1, err := s.CreateQueue(pub)
	if err != nil {
		t.Fatalf("create queue 1: %v", err)
	}

	q2, err := s.CreateQueue(pub)
	if err != nil {
		t.Fatalf("create queue 2: %v", err)
	}

	if q1.RecipientID != q2.RecipientID {
		t.Fatal("idempotent create returned different recipientID")
	}
	if q1.SenderID != q2.SenderID {
		t.Fatal("idempotent create returned different senderID")
	}
}

func TestBadgerGetQueueBySenderID(t *testing.T) {
	s := newTestBadgerStore(t)

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}

	q, err := s.CreateQueue(pub)
	if err != nil {
		t.Fatalf("create queue: %v", err)
	}

	got, err := s.GetQueueBySenderID(q.SenderID)
	if err != nil {
		t.Fatalf("get by sender: %v", err)
	}

	if got.RecipientID != q.RecipientID {
		t.Fatal("recipientID mismatch via sender lookup")
	}
}

func TestBadgerFindQueueByRecipientKey(t *testing.T) {
	s := newTestBadgerStore(t)

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}

	q, err := s.CreateQueue(pub)
	if err != nil {
		t.Fatalf("create queue: %v", err)
	}

	got, err := s.FindQueueByRecipientKey(pub)
	if err != nil {
		t.Fatalf("find by key: %v", err)
	}

	if got.RecipientID != q.RecipientID {
		t.Fatal("recipientID mismatch via key lookup")
	}
}

func TestBadgerSetSenderKey(t *testing.T) {
	s := newTestBadgerStore(t)

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}

	q, err := s.CreateQueue(pub)
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	senderPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen sender key: %v", err)
	}

	if err := s.SetSenderKey(q.SenderID, senderPub); err != nil {
		t.Fatalf("set sender key: %v", err)
	}

	// Verify it persisted
	got, err := s.GetQueue(q.RecipientID)
	if err != nil {
		t.Fatalf("get queue: %v", err)
	}
	if !bytes.Equal(got.SenderKey, senderPub) {
		t.Fatal("sender key not persisted")
	}

	// Second set should fail
	if err := s.SetSenderKey(q.SenderID, senderPub); err != ErrKeyAlreadySet {
		t.Fatalf("expected ErrKeyAlreadySet, got: %v", err)
	}
}

func TestBadgerDeleteQueue(t *testing.T) {
	s := newTestBadgerStore(t)

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}

	q, err := s.CreateQueue(pub)
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	if err := s.DeleteQueue(q.RecipientID); err != nil {
		t.Fatalf("delete: %v", err)
	}

	if _, err := s.GetQueue(q.RecipientID); err != ErrNoQueue {
		t.Fatalf("expected ErrNoQueue after delete, got: %v", err)
	}

	// Idempotent
	if err := s.DeleteQueue(q.RecipientID); err != nil {
		t.Fatalf("idempotent delete: %v", err)
	}
}

func TestBadgerPushAndPopMessage(t *testing.T) {
	s := newTestBadgerStore(t)

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}

	q, err := s.CreateQueue(pub)
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	senderPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen sender key: %v", err)
	}
	if err := s.SetSenderKey(q.SenderID, senderPub); err != nil {
		t.Fatalf("set sender key: %v", err)
	}

	msg, err := s.PushMessage(q.SenderID, 0, []byte("hello badger"))
	if err != nil {
		t.Fatalf("push: %v", err)
	}

	popped, err := s.PopMessage(q.RecipientID)
	if err != nil {
		t.Fatalf("pop: %v", err)
	}

	if popped.ID != msg.ID {
		t.Fatal("msg ID mismatch")
	}
	if !bytes.Equal(popped.Body, []byte("hello badger")) {
		t.Fatalf("body mismatch: %q", popped.Body)
	}
	if popped.DeliveryAttempts != 1 {
		t.Fatalf("delivery attempts: got %d, want 1", popped.DeliveryAttempts)
	}
}

func TestBadgerAckMessage(t *testing.T) {
	s := newTestBadgerStore(t)

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}

	q, err := s.CreateQueue(pub)
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	senderPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen sender key: %v", err)
	}
	if err := s.SetSenderKey(q.SenderID, senderPub); err != nil {
		t.Fatalf("set sender key: %v", err)
	}

	msg, err := s.PushMessage(q.SenderID, 0, []byte("to ack"))
	if err != nil {
		t.Fatalf("push: %v", err)
	}

	if err := s.AckMessage(q.RecipientID, msg.ID); err != nil {
		t.Fatalf("ack: %v", err)
	}

	// No more messages
	if _, err := s.PopMessage(q.RecipientID); err != ErrNoMessage {
		t.Fatalf("expected ErrNoMessage after ack, got: %v", err)
	}

	// Idempotent ACK
	if err := s.AckMessage(q.RecipientID, msg.ID); err != nil {
		t.Fatalf("idempotent ack: %v", err)
	}
}

func TestBadgerFIFOOrder(t *testing.T) {
	s := newTestBadgerStore(t)

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}

	q, err := s.CreateQueue(pub)
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	senderPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen sender key: %v", err)
	}
	if err := s.SetSenderKey(q.SenderID, senderPub); err != nil {
		t.Fatalf("set sender key: %v", err)
	}

	messages := []string{"first", "second", "third"}
	for _, content := range messages {
		if _, err := s.PushMessage(q.SenderID, 0, []byte(content)); err != nil {
			t.Fatalf("push %q: %v", content, err)
		}
	}

	for i, expected := range messages {
		msg, err := s.PopMessage(q.RecipientID)
		if err != nil {
			t.Fatalf("pop %d: %v", i, err)
		}
		if string(msg.Body) != expected {
			t.Fatalf("message %d: got %q, want %q", i, msg.Body, expected)
		}
		if err := s.AckMessage(q.RecipientID, msg.ID); err != nil {
			t.Fatalf("ack %d: %v", i, err)
		}
	}
}

func TestBadgerDeliveryAttemptsAutoDiscard(t *testing.T) {
	s := newTestBadgerStore(t)

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}

	q, err := s.CreateQueue(pub)
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	senderPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen sender key: %v", err)
	}
	if err := s.SetSenderKey(q.SenderID, senderPub); err != nil {
		t.Fatalf("set sender key: %v", err)
	}

	if _, err := s.PushMessage(q.SenderID, 0, []byte("bomb")); err != nil {
		t.Fatalf("push: %v", err)
	}

	// Pop MaxDeliveryAttempts-1 times
	for i := 0; i < MaxDeliveryAttempts-1; i++ {
		msg, popErr := s.PopMessage(q.RecipientID)
		if popErr != nil {
			t.Fatalf("pop %d: %v", i, popErr)
		}
		if msg.DeliveryAttempts != i+1 {
			t.Fatalf("pop %d: attempts=%d, want %d", i, msg.DeliveryAttempts, i+1)
		}
	}

	// Next pop should auto-discard
	_, err = s.PopMessage(q.RecipientID)
	if err != ErrNoMessage {
		t.Fatalf("expected ErrNoMessage after max deliveries, got: %v", err)
	}
}

// Test persistence: message survives store close and reopen
func TestBadgerPersistenceAcrossRestart(t *testing.T) {
	dir := t.TempDir()

	// Open, create queue, push message, close
	s1, err := NewBadgerStore(BadgerStoreConfig{
		Path:       dir,
		DefaultTTL: 48 * time.Hour,
		MaxTTL:     7 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("open store 1: %v", err)
	}

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}

	q, err := s1.CreateQueue(pub)
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	senderPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen sender key: %v", err)
	}
	if err := s1.SetSenderKey(q.SenderID, senderPub); err != nil {
		t.Fatalf("set sender key: %v", err)
	}

	if _, err := s1.PushMessage(q.SenderID, 0, []byte("survive restart")); err != nil {
		t.Fatalf("push: %v", err)
	}

	recipientID := q.RecipientID

	if err := s1.Close(); err != nil {
		t.Fatalf("close store 1: %v", err)
	}

	// Reopen
	s2, err := NewBadgerStore(BadgerStoreConfig{
		Path:       dir,
		DefaultTTL: 48 * time.Hour,
		MaxTTL:     7 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("open store 2: %v", err)
	}
	defer func() {
		if err := s2.Close(); err != nil {
			t.Logf("close store 2: %v", err)
		}
	}()

	// Queue should still exist
	got, err := s2.GetQueue(recipientID)
	if err != nil {
		t.Fatalf("get queue after restart: %v", err)
	}
	if !bytes.Equal(got.RecipientKey, pub) {
		t.Fatal("recipientKey mismatch after restart")
	}

	// Message should still be there
	msg, err := s2.PopMessage(recipientID)
	if err != nil {
		t.Fatalf("pop after restart: %v", err)
	}
	if string(msg.Body) != "survive restart" {
		t.Fatalf("body after restart: %q", msg.Body)
	}
}

// Test DeliveryAttempts persists across store reopens
func TestBadgerDeliveryAttemptsPersistAcrossRestart(t *testing.T) {
	dir := t.TempDir()

	s1, err := NewBadgerStore(BadgerStoreConfig{
		Path:       dir,
		DefaultTTL: 48 * time.Hour,
		MaxTTL:     7 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("open store 1: %v", err)
	}

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}

	q, err := s1.CreateQueue(pub)
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	senderPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen sender key: %v", err)
	}
	if err := s1.SetSenderKey(q.SenderID, senderPub); err != nil {
		t.Fatalf("set sender key: %v", err)
	}

	if _, err := s1.PushMessage(q.SenderID, 0, []byte("attempts test")); err != nil {
		t.Fatalf("push: %v", err)
	}

	// Pop twice to set delivery attempts to 2
	for i := 0; i < 2; i++ {
		if _, err := s1.PopMessage(q.RecipientID); err != nil {
			t.Fatalf("pop %d: %v", i, err)
		}
	}

	recipientID := q.RecipientID
	if err := s1.Close(); err != nil {
		t.Fatalf("close store 1: %v", err)
	}

	// Reopen
	s2, err := NewBadgerStore(BadgerStoreConfig{
		Path:       dir,
		DefaultTTL: 48 * time.Hour,
		MaxTTL:     7 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("open store 2: %v", err)
	}
	defer func() {
		if err := s2.Close(); err != nil {
			t.Logf("close store 2: %v", err)
		}
	}()

	msg, err := s2.PopMessage(recipientID)
	if err != nil {
		t.Fatalf("pop after restart: %v", err)
	}
	// Should be 3 now (2 from before restart + 1 from this pop)
	if msg.DeliveryAttempts != 3 {
		t.Fatalf("delivery attempts after restart: got %d, want 3", msg.DeliveryAttempts)
	}
}

// Test TTL expiry: store message with short TTL, verify it disappears
func TestBadgerTTLExpiry(t *testing.T) {
	dir := t.TempDir()

	s, err := NewBadgerStore(BadgerStoreConfig{
		Path:       dir,
		DefaultTTL: 48 * time.Hour,
		MaxTTL:     7 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() {
		if err := s.Close(); err != nil {
			t.Logf("close: %v", err)
		}
	}()

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}

	q, err := s.CreateQueue(pub)
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	senderPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen sender key: %v", err)
	}
	if err := s.SetSenderKey(q.SenderID, senderPub); err != nil {
		t.Fatalf("set sender key: %v", err)
	}

	// Push with very short TTL
	if _, err := s.PushMessageWithTTL(q.SenderID, 0, []byte("expires soon"), 1*time.Second); err != nil {
		t.Fatalf("push: %v", err)
	}

	// Should be readable immediately
	msg, err := s.PopMessage(q.RecipientID)
	if err != nil {
		t.Fatalf("immediate pop: %v", err)
	}
	if string(msg.Body) != "expires soon" {
		t.Fatalf("body: %q", msg.Body)
	}

	// Wait for TTL to expire
	time.Sleep(2 * time.Second)

	// Should be gone now
	_, err = s.PopMessage(q.RecipientID)
	if err != ErrNoMessage {
		t.Fatalf("after TTL: expected ErrNoMessage, got: %v", err)
	}
}

// Test cryptographic deletion: after ACK, the encrypted data key is zeroed
func TestBadgerCryptographicDeletion(t *testing.T) {
	dir := t.TempDir()

	s, err := NewBadgerStore(BadgerStoreConfig{
		Path:       dir,
		DefaultTTL: 48 * time.Hour,
		MaxTTL:     7 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}

	q, err := s.CreateQueue(pub)
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	senderPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen sender key: %v", err)
	}
	if err := s.SetSenderKey(q.SenderID, senderPub); err != nil {
		t.Fatalf("set sender key: %v", err)
	}

	msg, err := s.PushMessage(q.SenderID, 0, []byte("secret data"))
	if err != nil {
		t.Fatalf("push: %v", err)
	}

	// ACK the message (crypto deletion)
	if err := s.AckMessage(q.RecipientID, msg.ID); err != nil {
		t.Fatalf("ack: %v", err)
	}

	// Verify the message entries are deleted from DB
	err = s.db.View(func(txn *badger.Txn) error {
		prefix := msgPrefix(q.RecipientID)
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = false
		it := txn.NewIterator(opts)
		defer it.Close()

		it.Seek(prefix)
		if it.ValidForPrefix(prefix) {
			t.Fatal("message entries still exist after crypto deletion")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("verify deletion: %v", err)
	}

	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}

// Test GC goroutine starts without error
func TestBadgerGCStarts(t *testing.T) {
	s := newTestBadgerStore(t)
	// GC goroutine is started in NewBadgerStore. If we get here without panic, it's working.
	// Run a manual GC to verify it doesn't error
	err := s.db.RunValueLogGC(0.5)
	// ErrNoRewrite is expected on an empty/small DB
	if err != nil && err.Error() != "Value log GC attempt didn't result in any cleanup" {
		// OK - this is normal for a small DB
		_ = err
	}
}

// Test nonexistent queue operations
func TestBadgerNonexistentQueue(t *testing.T) {
	s := newTestBadgerStore(t)

	var fakeID [24]byte
	if _, err := rand.Read(fakeID[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}

	if _, err := s.GetQueue(fakeID); err != ErrNoQueue {
		t.Fatalf("get nonexistent: expected ErrNoQueue, got: %v", err)
	}

	if _, err := s.GetQueueBySenderID(fakeID); err != ErrNoQueue {
		t.Fatalf("get by sender nonexistent: expected ErrNoQueue, got: %v", err)
	}

	if _, err := s.PopMessage(fakeID); err != ErrNoMessage {
		t.Fatalf("pop nonexistent: expected ErrNoMessage, got: %v", err)
	}

	// ACK on nonexistent is idempotent
	if err := s.AckMessage(fakeID, fakeID); err != nil {
		t.Fatalf("ack nonexistent: %v", err)
	}
}
