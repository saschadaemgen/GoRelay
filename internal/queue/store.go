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
	ErrNoQueue   = errors.New("queue not found")
	ErrNoMessage = errors.New("no message available")
)

// Store defines the interface for persistent queue storage
type Store interface {
	CreateQueue(recipientKey ed25519.PublicKey) (*Queue, error)
	GetQueue(recipientID [24]byte) (*Queue, error)
	FindQueueByRecipientKey(recipientKey ed25519.PublicKey) (*Queue, error)
	DeleteQueue(recipientID [24]byte) error
	PushMessage(senderID [24]byte, flags byte, body []byte) error
	PopMessage(recipientID [24]byte) (*Message, error)
	AckMessage(recipientID [24]byte, msgID [24]byte) error
	Close() error
}

// Queue represents a message queue
type Queue struct {
	RecipientID    [24]byte
	SenderID       [24]byte
	RecipientKey   ed25519.PublicKey
	ServerDHPubKey []byte // X25519 public key (32 bytes)
	ServerDHSecret []byte // X25519 private key (32 bytes) - zeroed after use
	Status         byte
	CreatedAt      time.Time
}

// StatusActive indicates the queue is accepting messages
const StatusActive byte = 0x01

// Message represents a stored message
type Message struct {
	ID        [24]byte
	QueueID   [24]byte
	Timestamp uint64
	Flags     byte
	Body      []byte
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

func (s *MemoryStore) PushMessage(senderID [24]byte, flags byte, body []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	recipientID, ok := s.senders[senderID]
	if !ok {
		return ErrNoQueue
	}

	msg := &Message{
		QueueID: recipientID,
		Flags:   flags,
		Body:    make([]byte, len(body)),
	}
	copy(msg.Body, body)

	s.messages[recipientID] = append(s.messages[recipientID], msg)
	return nil
}

func (s *MemoryStore) PopMessage(recipientID [24]byte) (*Message, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	msgs, ok := s.messages[recipientID]
	if !ok || len(msgs) == 0 {
		return nil, ErrNoMessage
	}
	return msgs[0], nil
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
