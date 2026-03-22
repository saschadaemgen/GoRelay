package queue

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"sync"
	"time"
)

var (
	ErrNoQueue      = errors.New("queue not found")
	ErrNoMessage    = errors.New("no message available")
	ErrKeyAlreadySet = errors.New("sender key already set")
)

// Store defines the interface for persistent queue storage
type Store interface {
	CreateQueue(recipientKey ed25519.PublicKey) (*Queue, error)
	GetQueue(recipientID [24]byte) (*Queue, error)
	GetQueueBySenderID(senderID [24]byte) (*Queue, error)
	FindQueueByRecipientKey(recipientKey ed25519.PublicKey) (*Queue, error)
	SetSenderKey(senderID [24]byte, senderKey ed25519.PublicKey) error
	UpdateQueueDH(recipientID [24]byte, dhPubKey []byte, dhSharedSecret []byte) error
	DeleteQueue(recipientID [24]byte) error
	PushMessage(senderID [24]byte, flags byte, body []byte) (*Message, error)
	PopMessage(recipientID [24]byte) (*Message, error)
	AckMessage(recipientID [24]byte, msgID [24]byte) error
	Close() error
}

// Queue represents a message queue
type Queue struct {
	RecipientID    [24]byte
	SenderID       [24]byte
	RecipientKey   ed25519.PublicKey
	SenderKey      ed25519.PublicKey // set via KEY command, nil until then
	ServerDHPubKey []byte           // X25519 public key (32 bytes)
	ServerDHSecret []byte           // NaCl precomputed shared key (32 bytes) from box.Precompute
	Status         byte
	CreatedAt      time.Time
}

// StatusActive indicates the queue is accepting messages
const StatusActive byte = 0x01

// MaxDeliveryAttempts is the maximum number of times a message will be
// delivered before being automatically discarded. This prevents the
// redelivery loop attack (compression bomb + no ACK = device bricked).
const MaxDeliveryAttempts = 5

// Message represents a stored message
type Message struct {
	ID               [24]byte
	QueueID          [24]byte
	Timestamp        uint64
	Flags            byte
	Body             []byte
	DeliveryAttempts int
}

// MemoryStore is an in-memory queue store for development and testing
type MemoryStore struct {
	mu       sync.RWMutex
	queues   map[[24]byte]*Queue       // recipientID -> Queue
	senders  map[[24]byte][24]byte     // senderID -> recipientID
	messages map[[24]byte][]*Message
}

// NewMemoryStore creates a new in-memory queue store
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		queues:   make(map[[24]byte]*Queue),
		senders:  make(map[[24]byte][24]byte),
		messages: make(map[[24]byte][]*Message),
	}
}

func (s *MemoryStore) CreateQueue(recipientKey ed25519.PublicKey) (*Queue, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Idempotency: check if a queue with this recipientKey already exists
	for _, q := range s.queues {
		if subtle.ConstantTimeCompare(q.RecipientKey, recipientKey) == 1 {
			return q, nil
		}
	}

	recipientID, err := generateUniqueID(s.queues)
	if err != nil {
		return nil, fmt.Errorf("generate recipient ID: %w", err)
	}

	senderID, err := generateUniqueSenderID(s.senders, recipientID)
	if err != nil {
		return nil, fmt.Errorf("generate sender ID: %w", err)
	}

	q := &Queue{
		RecipientID:  recipientID,
		SenderID:     senderID,
		RecipientKey: recipientKey,
		Status:       StatusActive,
		CreatedAt:    time.Now(),
	}

	s.queues[recipientID] = q
	s.senders[senderID] = recipientID
	return q, nil
}

func (s *MemoryStore) GetQueue(recipientID [24]byte) (*Queue, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	q, ok := s.queues[recipientID]
	if !ok {
		return nil, ErrNoQueue
	}
	return q, nil
}

func (s *MemoryStore) GetQueueBySenderID(senderID [24]byte) (*Queue, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	recipientID, ok := s.senders[senderID]
	if !ok {
		return nil, ErrNoQueue
	}
	q, ok := s.queues[recipientID]
	if !ok {
		return nil, ErrNoQueue
	}
	return q, nil
}

func (s *MemoryStore) SetSenderKey(senderID [24]byte, senderKey ed25519.PublicKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	recipientID, ok := s.senders[senderID]
	if !ok {
		return ErrNoQueue
	}
	q, ok := s.queues[recipientID]
	if !ok {
		return ErrNoQueue
	}
	if q.SenderKey != nil {
		return ErrKeyAlreadySet
	}
	q.SenderKey = make(ed25519.PublicKey, len(senderKey))
	copy(q.SenderKey, senderKey)
	return nil
}

func (s *MemoryStore) UpdateQueueDH(recipientID [24]byte, dhPubKey []byte, dhSharedSecret []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	q, ok := s.queues[recipientID]
	if !ok {
		return ErrNoQueue
	}
	q.ServerDHPubKey = make([]byte, len(dhPubKey))
	copy(q.ServerDHPubKey, dhPubKey)
	q.ServerDHSecret = make([]byte, len(dhSharedSecret))
	copy(q.ServerDHSecret, dhSharedSecret)
	return nil
}

func (s *MemoryStore) FindQueueByRecipientKey(recipientKey ed25519.PublicKey) (*Queue, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, q := range s.queues {
		if subtle.ConstantTimeCompare(q.RecipientKey, recipientKey) == 1 {
			return q, nil
		}
	}
	return nil, ErrNoQueue
}

func (s *MemoryStore) DeleteQueue(recipientID [24]byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	q, ok := s.queues[recipientID]
	if !ok {
		return nil // idempotent
	}
	delete(s.senders, q.SenderID)
	delete(s.queues, recipientID)
	delete(s.messages, recipientID)
	return nil
}

func (s *MemoryStore) PushMessage(senderID [24]byte, flags byte, body []byte) (*Message, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	recipientID, ok := s.senders[senderID]
	if !ok {
		return nil, ErrNoQueue
	}

	// Generate message ID: timestamp(8) + sequence(8) + random(8)
	var msgID [24]byte
	now := uint64(time.Now().UnixNano())
	msgID[0] = byte(now >> 56)
	msgID[1] = byte(now >> 48)
	msgID[2] = byte(now >> 40)
	msgID[3] = byte(now >> 32)
	msgID[4] = byte(now >> 24)
	msgID[5] = byte(now >> 16)
	msgID[6] = byte(now >> 8)
	msgID[7] = byte(now)
	// sequence
	seq := uint64(len(s.messages[recipientID]))
	msgID[8] = byte(seq >> 56)
	msgID[9] = byte(seq >> 48)
	msgID[10] = byte(seq >> 40)
	msgID[11] = byte(seq >> 32)
	msgID[12] = byte(seq >> 24)
	msgID[13] = byte(seq >> 16)
	msgID[14] = byte(seq >> 8)
	msgID[15] = byte(seq)
	// random
	if _, err := rand.Read(msgID[16:]); err != nil {
		return nil, fmt.Errorf("generate message ID: %w", err)
	}

	msg := &Message{
		ID:        msgID,
		QueueID:   recipientID,
		Timestamp: now / 1e9, // seconds
		Flags:     flags,
		Body:      make([]byte, len(body)),
	}
	copy(msg.Body, body)

	s.messages[recipientID] = append(s.messages[recipientID], msg)
	return msg, nil
}

func (s *MemoryStore) PopMessage(recipientID [24]byte) (*Message, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for {
		msgs, ok := s.messages[recipientID]
		if !ok || len(msgs) == 0 {
			return nil, ErrNoMessage
		}

		msg := msgs[0]
		msg.DeliveryAttempts++

		if msg.DeliveryAttempts >= MaxDeliveryAttempts {
			// Auto-discard: message exceeded max delivery attempts
			s.messages[recipientID] = msgs[1:]
			continue
		}

		return msg, nil
	}
}

func (s *MemoryStore) AckMessage(recipientID [24]byte, msgID [24]byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	msgs, ok := s.messages[recipientID]
	if !ok || len(msgs) == 0 {
		return nil // idempotent
	}
	s.messages[recipientID] = msgs[1:]
	return nil
}

func (s *MemoryStore) Close() error {
	return nil
}

// generateUniqueID generates a random 24-byte ID that doesn't collide with existing queue keys.
func generateUniqueID(existing map[[24]byte]*Queue) ([24]byte, error) {
	for attempts := 0; attempts < 10; attempts++ {
		var id [24]byte
		if _, err := rand.Read(id[:]); err != nil {
			return id, fmt.Errorf("crypto/rand: %w", err)
		}
		if _, exists := existing[id]; !exists {
			return id, nil
		}
	}
	return [24]byte{}, errors.New("failed to generate unique ID after 10 attempts")
}

// generateUniqueSenderID generates a random 24-byte ID that doesn't collide with
// existing sender IDs and is different from the given recipientID.
func generateUniqueSenderID(existing map[[24]byte][24]byte, recipientID [24]byte) ([24]byte, error) {
	for attempts := 0; attempts < 10; attempts++ {
		var id [24]byte
		if _, err := rand.Read(id[:]); err != nil {
			return id, fmt.Errorf("crypto/rand: %w", err)
		}
		if id == recipientID {
			continue
		}
		if _, exists := existing[id]; !exists {
			return id, nil
		}
	}
	return [24]byte{}, errors.New("failed to generate unique sender ID after 10 attempts")
}
