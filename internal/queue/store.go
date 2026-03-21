package queue

import (
	"crypto/ed25519"
	"errors"
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
	DeleteQueue(recipientID [24]byte) error
	PushMessage(senderID [24]byte, flags byte, body []byte) error
	PopMessage(recipientID [24]byte) (*Message, error)
	AckMessage(recipientID [24]byte, msgID [24]byte) error
	Close() error
}

// Queue represents a message queue
type Queue struct {
	RecipientID  [24]byte
	SenderID     [24]byte
	RecipientKey ed25519.PublicKey
	Status       byte
	CreatedAt    time.Time
}

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
	queues   map[[24]byte]*Queue
	messages map[[24]byte][]*Message
}

// NewMemoryStore creates a new in-memory queue store
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		queues:   make(map[[24]byte]*Queue),
		messages: make(map[[24]byte][]*Message),
	}
}

func (s *MemoryStore) CreateQueue(recipientKey ed25519.PublicKey) (*Queue, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	q := &Queue{
		RecipientKey: recipientKey,
		CreatedAt:    time.Now(),
	}
	// Generate random IDs
	// TODO: use crypto/rand for real IDs
	s.queues[q.RecipientID] = q
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

func (s *MemoryStore) DeleteQueue(recipientID [24]byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.queues, recipientID)
	delete(s.messages, recipientID)
	return nil
}

func (s *MemoryStore) PushMessage(senderID [24]byte, flags byte, body []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// TODO: look up recipientID from senderID
	msg := &Message{
		Flags: flags,
		Body:  body,
	}
	s.messages[senderID] = append(s.messages[senderID], msg)
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
		return nil
	}
	s.messages[recipientID] = msgs[1:]
	return nil
}

func (s *MemoryStore) Close() error {
	return nil
}
