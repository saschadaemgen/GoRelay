package queue

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	badger "github.com/dgraph-io/badger/v4"
)

// Key prefixes for BadgerDB
var (
	prefixQueue     = []byte("q:")  // q:<recipientID> -> JSON queue
	prefixSender    = []byte("s:")  // s:<senderID> -> recipientID
	prefixRecipKey  = []byte("rk:") // rk:<sha256(recipientKey)> -> recipientID
	prefixMsg       = []byte("m:")  // m:<recipientID>:<seq16>:d -> encrypted data
	prefixMsgKey    = []byte("m:")  // m:<recipientID>:<seq16>:k -> per-message key
	prefixMsgMeta   = []byte("m:")  // m:<recipientID>:<seq16>:t -> meta (msgID + timestamp + flags + deliveryAttempts)
	prefixSeq       = []byte("n:")  // n:<recipientID> -> uint64 sequence counter
)

// BadgerStore implements the Store interface using BadgerDB v4.
type BadgerStore struct {
	db         *badger.DB
	defaultTTL time.Duration
	maxTTL     time.Duration
	cancel     context.CancelFunc
	wg         sync.WaitGroup
}

// slogAdapter adapts log/slog to badger.Logger interface.
type slogAdapter struct{}

func (s slogAdapter) Errorf(f string, a ...interface{})   { slog.Error(fmt.Sprintf(f, a...)) }
func (s slogAdapter) Warningf(f string, a ...interface{}) { slog.Warn(fmt.Sprintf(f, a...)) }
func (s slogAdapter) Infof(f string, a ...interface{})    { slog.Info(fmt.Sprintf(f, a...)) }
func (s slogAdapter) Debugf(f string, a ...interface{})   { slog.Debug(fmt.Sprintf(f, a...)) }

// BadgerStoreConfig holds configuration for the BadgerDB store.
type BadgerStoreConfig struct {
	Path       string
	DefaultTTL time.Duration
	MaxTTL     time.Duration
}

// NewBadgerStore creates a new BadgerDB-backed queue store.
func NewBadgerStore(cfg BadgerStoreConfig) (*BadgerStore, error) {
	if cfg.DefaultTTL == 0 {
		cfg.DefaultTTL = 48 * time.Hour
	}
	if cfg.MaxTTL == 0 {
		cfg.MaxTTL = 7 * 24 * time.Hour
	}
	if cfg.DefaultTTL > cfg.MaxTTL {
		cfg.DefaultTTL = cfg.MaxTTL
	}

	if err := os.MkdirAll(cfg.Path, 0700); err != nil {
		return nil, fmt.Errorf("create badger dir: %w", err)
	}

	opts := badger.DefaultOptions(cfg.Path).
		WithLogger(slogAdapter{}).
		WithNumVersionsToKeep(1)

	db, err := badger.Open(opts)
	if err != nil {
		return nil, fmt.Errorf("open badger: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	s := &BadgerStore{
		db:         db,
		defaultTTL: cfg.DefaultTTL,
		maxTTL:     cfg.MaxTTL,
		cancel:     cancel,
	}

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.gcLoop(ctx)
	}()

	return s, nil
}

// gcLoop runs BadgerDB value log GC periodically.
func (s *BadgerStore) gcLoop(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for {
				err := s.db.RunValueLogGC(0.5)
				if err != nil {
					break
				}
			}
		}
	}
}

// Close shuts down the GC goroutine and closes BadgerDB.
func (s *BadgerStore) Close() error {
	s.cancel()
	s.wg.Wait()
	return s.db.Close()
}

// --- Key builders ---

func queueKey(recipientID [24]byte) []byte {
	k := make([]byte, 2+24)
	copy(k, prefixQueue)
	copy(k[2:], recipientID[:])
	return k
}

func senderKey(senderID [24]byte) []byte {
	k := make([]byte, 2+24)
	copy(k, prefixSender)
	copy(k[2:], senderID[:])
	return k
}

func recipKeyIndex(recipientKey ed25519.PublicKey) []byte {
	h := sha256.Sum256(recipientKey)
	k := make([]byte, 3+32)
	copy(k, prefixRecipKey)
	copy(k[3:], h[:])
	return k
}

func seqKey(recipientID [24]byte) []byte {
	k := make([]byte, 2+24)
	copy(k, prefixSeq)
	copy(k[2:], recipientID[:])
	return k
}

// msgPrefix returns the message key prefix for a recipient: m:<recipientID>:
func msgPrefix(recipientID [24]byte) []byte {
	k := make([]byte, 2+24+1)
	copy(k, prefixMsg)
	copy(k[2:], recipientID[:])
	k[26] = ':'
	return k
}

// msgDataKey: m:<recipientID>:<seq16>:d
func msgDataKey(recipientID [24]byte, seq uint64) []byte {
	prefix := msgPrefix(recipientID)
	k := make([]byte, len(prefix)+16+2)
	copy(k, prefix)
	writeSeq16(k[len(prefix):], seq)
	k[len(prefix)+16] = ':'
	k[len(prefix)+17] = 'd'
	return k
}

// msgKeyKey: m:<recipientID>:<seq16>:k
func msgKeyKey(recipientID [24]byte, seq uint64) []byte {
	prefix := msgPrefix(recipientID)
	k := make([]byte, len(prefix)+16+2)
	copy(k, prefix)
	writeSeq16(k[len(prefix):], seq)
	k[len(prefix)+16] = ':'
	k[len(prefix)+17] = 'k'
	return k
}

// msgMetaKey: m:<recipientID>:<seq16>:t
func msgMetaKey(recipientID [24]byte, seq uint64) []byte {
	prefix := msgPrefix(recipientID)
	k := make([]byte, len(prefix)+16+2)
	copy(k, prefix)
	writeSeq16(k[len(prefix):], seq)
	k[len(prefix)+16] = ':'
	k[len(prefix)+17] = 't'
	return k
}

// writeSeq16 writes a zero-padded 16-char hex sequence into dst.
func writeSeq16(dst []byte, seq uint64) {
	const hexChars = "0123456789abcdef"
	for i := 15; i >= 0; i-- {
		dst[i] = hexChars[seq&0xf]
		seq >>= 4
	}
}

// parseSeq16 reads a 16-char hex sequence from src.
func parseSeq16(src []byte) (uint64, error) {
	if len(src) < 16 {
		return 0, errors.New("seq too short")
	}
	var val uint64
	for i := 0; i < 16; i++ {
		val <<= 4
		c := src[i]
		switch {
		case c >= '0' && c <= '9':
			val |= uint64(c - '0')
		case c >= 'a' && c <= 'f':
			val |= uint64(c-'a') + 10
		default:
			return 0, fmt.Errorf("invalid hex char: %c", c)
		}
	}
	return val, nil
}

// --- Queue JSON encoding ---

type queueJSON struct {
	RecipientID    [24]byte `json:"rid"`
	SenderID       [24]byte `json:"sid"`
	RecipientKey   []byte   `json:"rkey"`
	SenderKey      []byte   `json:"skey,omitempty"`
	ServerDHPubKey []byte   `json:"dhpub,omitempty"`
	ServerDHSecret []byte   `json:"dhsec,omitempty"`
	Status         byte     `json:"status"`
	CreatedAt      int64    `json:"created"`
}

func encodeQueue(q *Queue) ([]byte, error) {
	jq := queueJSON{
		RecipientID:    q.RecipientID,
		SenderID:       q.SenderID,
		RecipientKey:   q.RecipientKey,
		SenderKey:      q.SenderKey,
		ServerDHPubKey: q.ServerDHPubKey,
		ServerDHSecret: q.ServerDHSecret,
		Status:         q.Status,
		CreatedAt:      q.CreatedAt.UnixNano(),
	}
	return json.Marshal(jq)
}

func decodeQueue(data []byte) (*Queue, error) {
	var jq queueJSON
	if err := json.Unmarshal(data, &jq); err != nil {
		return nil, err
	}
	q := &Queue{
		RecipientID:    jq.RecipientID,
		SenderID:       jq.SenderID,
		ServerDHPubKey: jq.ServerDHPubKey,
		ServerDHSecret: jq.ServerDHSecret,
		Status:         jq.Status,
		CreatedAt:      time.Unix(0, jq.CreatedAt),
	}
	if len(jq.RecipientKey) > 0 {
		q.RecipientKey = make(ed25519.PublicKey, len(jq.RecipientKey))
		copy(q.RecipientKey, jq.RecipientKey)
	}
	if len(jq.SenderKey) > 0 {
		q.SenderKey = make(ed25519.PublicKey, len(jq.SenderKey))
		copy(q.SenderKey, jq.SenderKey)
	}
	return q, nil
}

// --- Message meta encoding ---
// Meta: msgID(24) + timestamp(8) + flags(1) + deliveryAttempts(4) = 37 bytes

func encodeMsgMeta(msg *Message) []byte {
	buf := make([]byte, 24+8+1+4)
	copy(buf[0:24], msg.ID[:])
	binary.BigEndian.PutUint64(buf[24:32], msg.Timestamp)
	buf[32] = msg.Flags
	binary.BigEndian.PutUint32(buf[33:37], uint32(msg.DeliveryAttempts))
	return buf
}

func decodeMsgMeta(data []byte) (msgID [24]byte, timestamp uint64, flags byte, deliveryAttempts int, err error) {
	if len(data) < 33 {
		err = errors.New("meta too short")
		return
	}
	copy(msgID[:], data[0:24])
	timestamp = binary.BigEndian.Uint64(data[24:32])
	flags = data[32]
	if len(data) >= 37 {
		deliveryAttempts = int(binary.BigEndian.Uint32(data[33:37]))
	}
	return
}

// --- AES-256-GCM encryption ---

func encryptMessage(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func decryptMessage(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}
	return gcm.Open(nil, ciphertext[:nonceSize], ciphertext[nonceSize:], nil)
}

// --- Store interface implementation ---

func (s *BadgerStore) CreateQueue(recipientKey ed25519.PublicKey) (*Queue, error) {
	// Idempotency: check if queue with this recipientKey already exists
	existing, err := s.FindQueueByRecipientKey(recipientKey)
	if err == nil {
		return existing, nil
	}

	// Generate unique IDs
	var recipientID [24]byte
	if _, err := rand.Read(recipientID[:]); err != nil {
		return nil, fmt.Errorf("generate recipient ID: %w", err)
	}
	var senderID [24]byte
	for {
		if _, err := rand.Read(senderID[:]); err != nil {
			return nil, fmt.Errorf("generate sender ID: %w", err)
		}
		if senderID != recipientID {
			break
		}
	}

	q := &Queue{
		RecipientID:  recipientID,
		SenderID:     senderID,
		RecipientKey: make(ed25519.PublicKey, len(recipientKey)),
		Status:       StatusActive,
		CreatedAt:    time.Now(),
	}
	copy(q.RecipientKey, recipientKey)

	encoded, err := encodeQueue(q)
	if err != nil {
		return nil, fmt.Errorf("encode queue: %w", err)
	}

	err = s.db.Update(func(txn *badger.Txn) error {
		// Check for ID collision
		if _, err := txn.Get(queueKey(recipientID)); err == nil {
			return errors.New("recipient ID collision")
		}
		if _, err := txn.Get(senderKey(senderID)); err == nil {
			return errors.New("sender ID collision")
		}

		if err := txn.Set(queueKey(recipientID), encoded); err != nil {
			return err
		}
		if err := txn.Set(senderKey(senderID), recipientID[:]); err != nil {
			return err
		}
		if err := txn.Set(recipKeyIndex(recipientKey), recipientID[:]); err != nil {
			return err
		}
		// Initialize sequence counter
		seqBuf := make([]byte, 8)
		if err := txn.Set(seqKey(recipientID), seqBuf); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("create queue txn: %w", err)
	}

	return q, nil
}

func (s *BadgerStore) GetQueue(recipientID [24]byte) (*Queue, error) {
	var q *Queue
	err := s.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(queueKey(recipientID))
		if err != nil {
			return ErrNoQueue
		}
		return item.Value(func(val []byte) error {
			var decErr error
			q, decErr = decodeQueue(val)
			return decErr
		})
	})
	if err != nil {
		return nil, err
	}
	return q, nil
}

func (s *BadgerStore) GetQueueBySenderID(senderID [24]byte) (*Queue, error) {
	var recipientID [24]byte
	err := s.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(senderKey(senderID))
		if err != nil {
			return ErrNoQueue
		}
		return item.Value(func(val []byte) error {
			copy(recipientID[:], val)
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	return s.GetQueue(recipientID)
}

func (s *BadgerStore) FindQueueByRecipientKey(recipientKey ed25519.PublicKey) (*Queue, error) {
	var recipientID [24]byte
	err := s.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(recipKeyIndex(recipientKey))
		if err != nil {
			return ErrNoQueue
		}
		return item.Value(func(val []byte) error {
			copy(recipientID[:], val)
			return nil
		})
	})
	if err != nil {
		return nil, err
	}

	q, err := s.GetQueue(recipientID)
	if err != nil {
		return nil, err
	}

	// Verify the key actually matches (defense in depth against hash collisions)
	if subtle.ConstantTimeCompare(q.RecipientKey, recipientKey) != 1 {
		return nil, ErrNoQueue
	}
	return q, nil
}

func (s *BadgerStore) SetSenderKey(senderID [24]byte, senderPubKey ed25519.PublicKey) error {
	return s.db.Update(func(txn *badger.Txn) error {
		// Look up recipientID
		sItem, err := txn.Get(senderKey(senderID))
		if err != nil {
			return ErrNoQueue
		}
		var recipientID [24]byte
		if err := sItem.Value(func(val []byte) error {
			copy(recipientID[:], val)
			return nil
		}); err != nil {
			return err
		}

		// Get queue
		qItem, err := txn.Get(queueKey(recipientID))
		if err != nil {
			return ErrNoQueue
		}

		var q *Queue
		if err := qItem.Value(func(val []byte) error {
			var decErr error
			q, decErr = decodeQueue(val)
			return decErr
		}); err != nil {
			return err
		}

		if q.SenderKey != nil {
			return ErrKeyAlreadySet
		}

		q.SenderKey = make(ed25519.PublicKey, len(senderPubKey))
		copy(q.SenderKey, senderPubKey)

		encoded, err := encodeQueue(q)
		if err != nil {
			return err
		}
		return txn.Set(queueKey(recipientID), encoded)
	})
}

func (s *BadgerStore) DeleteQueue(recipientID [24]byte) error {
	return s.db.Update(func(txn *badger.Txn) error {
		// Get queue to find senderID and recipientKey
		qItem, err := txn.Get(queueKey(recipientID))
		if err != nil {
			return nil // idempotent
		}

		var q *Queue
		if err := qItem.Value(func(val []byte) error {
			var decErr error
			q, decErr = decodeQueue(val)
			return decErr
		}); err != nil {
			return nil // idempotent on decode failure
		}

		// Delete queue record
		if err := txn.Delete(queueKey(recipientID)); err != nil {
			return err
		}
		// Delete sender mapping
		if err := txn.Delete(senderKey(q.SenderID)); err != nil {
			return err
		}
		// Delete recipient key index
		if q.RecipientKey != nil {
			if err := txn.Delete(recipKeyIndex(q.RecipientKey)); err != nil {
				return err
			}
		}
		// Delete sequence counter
		if err := txn.Delete(seqKey(recipientID)); err != nil {
			return err
		}

		// Delete all messages (prefix scan)
		prefix := msgPrefix(recipientID)
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = false
		it := txn.NewIterator(opts)
		defer it.Close()

		var keysToDelete [][]byte
		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			keyCopy := make([]byte, len(it.Item().Key()))
			copy(keyCopy, it.Item().Key())
			keysToDelete = append(keysToDelete, keyCopy)
		}
		for _, k := range keysToDelete {
			if err := txn.Delete(k); err != nil {
				return err
			}
		}

		return nil
	})
}

func (s *BadgerStore) PushMessage(senderID [24]byte, flags byte, body []byte) (*Message, error) {
	// Look up recipientID
	var recipientID [24]byte
	err := s.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(senderKey(senderID))
		if err != nil {
			return ErrNoQueue
		}
		return item.Value(func(val []byte) error {
			copy(recipientID[:], val)
			return nil
		})
	})
	if err != nil {
		return nil, err
	}

	// Generate per-message symmetric key
	msgEncKey := make([]byte, 32)
	if _, err := rand.Read(msgEncKey); err != nil {
		return nil, fmt.Errorf("generate message key: %w", err)
	}

	// Encrypt body
	encrypted, err := encryptMessage(msgEncKey, body)
	if err != nil {
		return nil, fmt.Errorf("encrypt message: %w", err)
	}

	now := uint64(time.Now().UnixNano())

	var msg *Message
	err = s.db.Update(func(txn *badger.Txn) error {
		// Increment sequence counter
		seq, seqErr := s.incrementSeq(txn, recipientID)
		if seqErr != nil {
			return seqErr
		}

		// Generate message ID: timestamp(8) + sequence(8) + random(8)
		var msgID [24]byte
		binary.BigEndian.PutUint64(msgID[0:8], now)
		binary.BigEndian.PutUint64(msgID[8:16], seq)
		if _, err := rand.Read(msgID[16:]); err != nil {
			return fmt.Errorf("generate message ID: %w", err)
		}

		msg = &Message{
			ID:        msgID,
			QueueID:   recipientID,
			Timestamp: now / 1e9, // seconds
			Flags:     flags,
			Body:      make([]byte, len(body)),
		}
		copy(msg.Body, body)

		ttl := s.defaultTTL
		if ttl > s.maxTTL {
			ttl = s.maxTTL
		}

		// Store encrypted data
		if err := txn.SetEntry(badger.NewEntry(msgDataKey(recipientID, seq), encrypted).WithTTL(ttl)); err != nil {
			return err
		}
		// Store per-message key
		if err := txn.SetEntry(badger.NewEntry(msgKeyKey(recipientID, seq), msgEncKey).WithTTL(ttl)); err != nil {
			return err
		}
		// Store meta
		meta := encodeMsgMeta(msg)
		if err := txn.SetEntry(badger.NewEntry(msgMetaKey(recipientID, seq), meta).WithTTL(ttl)); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return msg, nil
}

func (s *BadgerStore) PopMessage(recipientID [24]byte) (*Message, error) {
	for {
		msg, seq, err := s.peekFirstMessage(recipientID)
		if err != nil {
			return nil, err
		}

		msg.DeliveryAttempts++
		if msg.DeliveryAttempts >= MaxDeliveryAttempts {
			// Auto-discard
			if delErr := s.deleteMessageBySeq(recipientID, seq); delErr != nil {
				return nil, fmt.Errorf("auto-discard: %w", delErr)
			}
			continue
		}

		// Persist updated delivery attempts
		if err := s.updateDeliveryAttempts(recipientID, seq, msg); err != nil {
			return nil, err
		}

		return msg, nil
	}
}

func (s *BadgerStore) AckMessage(recipientID [24]byte, msgID [24]byte) error {
	// Find the message by scanning for its msgID in meta entries
	return s.db.Update(func(txn *badger.Txn) error {
		prefix := msgPrefix(recipientID)
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = false
		it := txn.NewIterator(opts)
		defer it.Close()

		// Find the first :t (meta) key - we ACK the head of the queue
		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			key := it.Item().Key()
			if len(key) > 2 && key[len(key)-1] == 't' && key[len(key)-2] == ':' {
				// Found first meta key, extract seq from key
				seqStart := len(prefix)
				seqEnd := seqStart + 16
				if seqEnd > len(key)-2 {
					continue
				}
				seq, parseErr := parseSeq16(key[seqStart:seqEnd])
				if parseErr != nil {
					continue
				}

				// Cryptographic deletion: zero the per-message key first
				mkk := msgKeyKey(recipientID, seq)
				keyItem, kerr := txn.Get(mkk)
				if kerr == nil {
					if vErr := keyItem.Value(func(val []byte) error {
						for i := range val {
							val[i] = 0
						}
						return nil
					}); vErr != nil {
						// Continue with deletion anyway
						slog.Debug("zero message key failed")
					}
				}

				// Delete all three entries for this message
				if err := txn.Delete(msgDataKey(recipientID, seq)); err != nil && !errors.Is(err, badger.ErrKeyNotFound) {
					return err
				}
				if err := txn.Delete(mkk); err != nil && !errors.Is(err, badger.ErrKeyNotFound) {
					return err
				}
				if err := txn.Delete(msgMetaKey(recipientID, seq)); err != nil && !errors.Is(err, badger.ErrKeyNotFound) {
					return err
				}
				return nil
			}
		}

		// No message found - idempotent
		return nil
	})
}

// --- Internal helpers ---

func (s *BadgerStore) incrementSeq(txn *badger.Txn, recipientID [24]byte) (uint64, error) {
	sk := seqKey(recipientID)
	item, err := txn.Get(sk)
	if err != nil {
		return 0, fmt.Errorf("get seq: %w", err)
	}

	var seq uint64
	if err := item.Value(func(val []byte) error {
		if len(val) == 8 {
			seq = binary.BigEndian.Uint64(val)
		}
		return nil
	}); err != nil {
		return 0, err
	}

	seq++
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, seq)
	if err := txn.Set(sk, buf); err != nil {
		return 0, err
	}
	return seq, nil
}

func (s *BadgerStore) peekFirstMessage(recipientID [24]byte) (*Message, uint64, error) {
	var msg *Message
	var seq uint64

	err := s.db.View(func(txn *badger.Txn) error {
		prefix := msgPrefix(recipientID)
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = true
		opts.PrefetchSize = 3
		it := txn.NewIterator(opts)
		defer it.Close()

		// Find first meta key (:t suffix)
		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			key := it.Item().Key()
			if len(key) < 2 || key[len(key)-1] != 't' || key[len(key)-2] != ':' {
				continue
			}

			seqStart := len(prefix)
			seqEnd := seqStart + 16
			if seqEnd > len(key)-2 {
				continue
			}
			var parseErr error
			seq, parseErr = parseSeq16(key[seqStart:seqEnd])
			if parseErr != nil {
				continue
			}

			// Read meta
			var msgID [24]byte
			var timestamp uint64
			var flags byte
			var deliveryAttempts int
			if err := it.Item().Value(func(val []byte) error {
				var decErr error
				msgID, timestamp, flags, deliveryAttempts, decErr = decodeMsgMeta(val)
				return decErr
			}); err != nil {
				return err
			}

			// Read message key
			mkk := msgKeyKey(recipientID, seq)
			keyItem, kerr := txn.Get(mkk)
			if kerr != nil {
				return fmt.Errorf("read message key: %w", kerr)
			}
			var msgEncKey []byte
			if err := keyItem.Value(func(val []byte) error {
				msgEncKey = make([]byte, len(val))
				copy(msgEncKey, val)
				return nil
			}); err != nil {
				return err
			}

			// Read encrypted data
			mdk := msgDataKey(recipientID, seq)
			dataItem, derr := txn.Get(mdk)
			if derr != nil {
				return fmt.Errorf("read message data: %w", derr)
			}
			var body []byte
			if err := dataItem.Value(func(val []byte) error {
				decrypted, decErr := decryptMessage(msgEncKey, val)
				if decErr != nil {
					return decErr
				}
				body = decrypted
				return nil
			}); err != nil {
				return err
			}

			msg = &Message{
				ID:               msgID,
				QueueID:          recipientID,
				Timestamp:        timestamp,
				Flags:            flags,
				Body:             body,
				DeliveryAttempts: deliveryAttempts,
			}
			return nil
		}
		return ErrNoMessage
	})

	if err != nil {
		return nil, 0, err
	}
	return msg, seq, nil
}

func (s *BadgerStore) deleteMessageBySeq(recipientID [24]byte, seq uint64) error {
	return s.db.Update(func(txn *badger.Txn) error {
		// Zero the per-message key first (crypto deletion)
		mkk := msgKeyKey(recipientID, seq)
		keyItem, kerr := txn.Get(mkk)
		if kerr == nil {
			if vErr := keyItem.Value(func(val []byte) error {
				for i := range val {
					val[i] = 0
				}
				return nil
			}); vErr != nil {
				slog.Debug("zero message key failed during auto-discard")
			}
		}

		if err := txn.Delete(msgDataKey(recipientID, seq)); err != nil && !errors.Is(err, badger.ErrKeyNotFound) {
			return err
		}
		if err := txn.Delete(mkk); err != nil && !errors.Is(err, badger.ErrKeyNotFound) {
			return err
		}
		if err := txn.Delete(msgMetaKey(recipientID, seq)); err != nil && !errors.Is(err, badger.ErrKeyNotFound) {
			return err
		}
		return nil
	})
}

func (s *BadgerStore) updateDeliveryAttempts(recipientID [24]byte, seq uint64, msg *Message) error {
	return s.db.Update(func(txn *badger.Txn) error {
		// Read existing TTL from the meta entry to preserve it
		mk := msgMetaKey(recipientID, seq)
		item, err := txn.Get(mk)
		if err != nil {
			return err
		}

		expiresAt := item.ExpiresAt()
		meta := encodeMsgMeta(msg)

		entry := badger.NewEntry(mk, meta)
		if expiresAt > 0 {
			remaining := time.Until(time.Unix(int64(expiresAt), 0))
			if remaining > 0 {
				entry = entry.WithTTL(remaining)
			}
		}
		return txn.SetEntry(entry)
	})
}

// PushMessageWithTTL stores a message with a custom TTL (for testing).
func (s *BadgerStore) PushMessageWithTTL(senderID [24]byte, flags byte, body []byte, ttl time.Duration) (*Message, error) {
	// Look up recipientID
	var recipientID [24]byte
	err := s.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(senderKey(senderID))
		if err != nil {
			return ErrNoQueue
		}
		return item.Value(func(val []byte) error {
			copy(recipientID[:], val)
			return nil
		})
	})
	if err != nil {
		return nil, err
	}

	if ttl > s.maxTTL {
		ttl = s.maxTTL
	}

	msgEncKey := make([]byte, 32)
	if _, err := rand.Read(msgEncKey); err != nil {
		return nil, fmt.Errorf("generate message key: %w", err)
	}

	encrypted, err := encryptMessage(msgEncKey, body)
	if err != nil {
		return nil, fmt.Errorf("encrypt message: %w", err)
	}

	now := uint64(time.Now().UnixNano())

	var msg *Message
	err = s.db.Update(func(txn *badger.Txn) error {
		seq, seqErr := s.incrementSeq(txn, recipientID)
		if seqErr != nil {
			return seqErr
		}

		var msgID [24]byte
		binary.BigEndian.PutUint64(msgID[0:8], now)
		binary.BigEndian.PutUint64(msgID[8:16], seq)
		if _, err := rand.Read(msgID[16:]); err != nil {
			return fmt.Errorf("generate message ID: %w", err)
		}

		msg = &Message{
			ID:        msgID,
			QueueID:   recipientID,
			Timestamp: now / 1e9,
			Flags:     flags,
			Body:      make([]byte, len(body)),
		}
		copy(msg.Body, body)

		if err := txn.SetEntry(badger.NewEntry(msgDataKey(recipientID, seq), encrypted).WithTTL(ttl)); err != nil {
			return err
		}
		if err := txn.SetEntry(badger.NewEntry(msgKeyKey(recipientID, seq), msgEncKey).WithTTL(ttl)); err != nil {
			return err
		}
		meta := encodeMsgMeta(msg)
		if err := txn.SetEntry(badger.NewEntry(msgMetaKey(recipientID, seq), meta).WithTTL(ttl)); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return msg, nil
}
