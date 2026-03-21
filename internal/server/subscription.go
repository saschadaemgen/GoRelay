package server

import "sync"

// SubscriptionHub maps queue IDs to active subscriber clients
type SubscriptionHub struct {
	subscribers sync.Map // [24]byte -> *Client
}

// NewSubscriptionHub creates a new subscription hub
func NewSubscriptionHub() *SubscriptionHub {
	return &SubscriptionHub{}
}

// Subscribe registers a client as the subscriber for a queue.
// Returns the old client if one was displaced (caller should send END).
func (h *SubscriptionHub) Subscribe(queueID [24]byte, client *Client) *Client {
	old, loaded := h.subscribers.Swap(queueID, client)
	if loaded && old != nil {
		return old.(*Client)
	}
	return nil
}

// Unsubscribe removes a subscription only if the current subscriber matches.
func (h *SubscriptionHub) Unsubscribe(queueID [24]byte, client *Client) {
	h.subscribers.CompareAndDelete(queueID, client)
}

// GetSubscriber returns the active subscriber for a queue, or nil.
func (h *SubscriptionHub) GetSubscriber(queueID [24]byte) *Client {
	sub, ok := h.subscribers.Load(queueID)
	if !ok {
		return nil
	}
	return sub.(*Client)
}
