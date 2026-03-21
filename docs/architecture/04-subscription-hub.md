---
title: "Subscription Hub"
sidebar_position: 4
---

# Subscription and Routing Hub

*How GoRelay routes messages from senders to recipients in real-time using a lock-free subscription registry with cross-protocol support.*

**Status:** In development
**Date:** 2026-03-09 (Session 001)

---

## Purpose

The Subscription Hub is the real-time message routing layer. When a message arrives via SEND, the hub determines if a recipient is currently connected and subscribed. If yes, the message is delivered immediately via the subscriber's send channel. If no, the message waits in the queue store until the recipient subscribes.

---

## Data Structure

```go
type Hub struct {
    // recipientID -> *Client (active subscriber)
    subscribers sync.Map

    // Metrics
    activeSubscriptions atomic.Int64
    deliveriesImmediate atomic.Int64
    deliveriesQueued    atomic.Int64
}
```

`sync.Map` is chosen over `map` + `sync.RWMutex` because the subscription pattern is read-heavy: every SEND command checks for a subscriber (read), while SUB/END events (writes) are infrequent by comparison. `sync.Map` is optimized for exactly this access pattern - reads are lock-free and nearly zero-cost.

---

## Operations

### Subscribe

```go
func (h *Hub) Subscribe(recipientID [24]byte, client *Client) (oldClient *Client) {
    old, loaded := h.subscribers.Swap(recipientID, client)

    if loaded && old != nil {
        oldClient = old.(*Client)
        // Send END to the displaced client
        oldClient.sndQ <- Response{
            Command:  CMD_END,
            EntityID: recipientID,
        }
        return oldClient
    }

    h.activeSubscriptions.Add(1)
    return nil
}
```

**Atomic swap:** `sync.Map.Swap` atomically replaces the old subscriber with the new one. There is no window where two subscribers exist simultaneously. The old subscriber receives END and the new subscriber is immediately active.

**Cross-protocol:** The Client struct could be SMP or GRP. The hub does not care - it pushes Response structs to `sndQ`, and the client's sender goroutine serializes them in the appropriate protocol format.

### Unsubscribe

```go
func (h *Hub) Unsubscribe(recipientID [24]byte, client *Client) {
    // Only unsubscribe if the current subscriber is this client
    // (prevents race where a new subscriber already took over)
    h.subscribers.CompareAndDelete(recipientID, client)
    h.activeSubscriptions.Add(-1)
}
```

`CompareAndDelete` ensures that we only remove the subscription if it still belongs to this client. If another client already took over via SUB (triggering Swap), we do not accidentally remove the new subscriber.

### Deliver

```go
func (h *Hub) TryDeliver(recipientID [24]byte, msg *Message) bool {
    sub, ok := h.subscribers.Load(recipientID)
    if !ok {
        h.deliveriesQueued.Add(1)
        return false  // no subscriber, message stays in queue
    }

    client := sub.(*Client)
    response := Response{
        Command:   CMD_MSG,
        EntityID:  recipientID,
        MessageID: msg.ID,
        Timestamp: msg.Timestamp,
        Flags:     msg.Flags,
        Body:      msg.Body,
    }

    select {
    case client.sndQ <- response:
        h.deliveriesImmediate.Add(1)
        return true  // delivered to subscriber's send queue
    default:
        h.deliveriesQueued.Add(1)
        return false  // subscriber's send queue is full (backpressure)
    }
}
```

The `select` with `default` prevents blocking when the subscriber's send queue is full. If the channel is full (client is slow or disconnected), the message stays in the queue store and will be delivered when the client catches up.

---

## Message Delivery Flow

### Immediate Delivery (subscriber connected)

```
Sender --SEND--> [Processor]
                     |
                     v
              queueStore.PushMessage()
                     |
                     v
              subHub.TryDeliver()
                     |
                     +---> subscriber.sndQ ---> [Sender Goroutine] ---> Wire
```

Time from SEND to wire: typically under 1 millisecond (in-memory operations only).

### Deferred Delivery (subscriber offline)

```
Sender --SEND--> [Processor]
                     |
                     v
              queueStore.PushMessage()
                     |
                     v
              subHub.TryDeliver() -> false (no subscriber)
                     |
                     v
              Message waits in BadgerDB
                     ...
              (later, recipient connects)
                     ...
Recipient --SUB--> [Processor]
                     |
                     v
              subHub.Subscribe(recipientID, client)
                     |
                     v
              queueStore.PopMessage(recipientID)
                     |
                     v
              client.sndQ ---> [Sender Goroutine] ---> Wire
```

### One Message at a Time

GRP delivers messages strictly sequentially per queue. After delivering a MSG, the server waits for ACK before delivering the next message. This means only one message is ever "in flight" per queue.

```go
func (s *Server) handleSUB(client *Client, recipientID [24]byte) {
    // Register subscription
    old := s.subHub.Subscribe(recipientID, client)
    client.subscriptions[recipientID] = true

    // Try to deliver first pending message
    msg, err := s.queueStore.PopMessage(recipientID)
    if err == ErrNoMessage {
        client.sndQ <- Response{Command: CMD_OK}
        return
    }

    client.sndQ <- Response{
        Command:   CMD_MSG,
        EntityID:  recipientID,
        MessageID: msg.ID,
        Timestamp: msg.Timestamp,
        Flags:     msg.Flags,
        Body:      msg.Body,
    }
    // Next message delivered only after ACK
}
```

---

## Cover Traffic Integration

The cover traffic generator injects dummy messages directly into the subscriber's send queue:

```go
func (s *Server) coverTrafficLoop(ctx context.Context, client *Client) {
    for {
        // ... Poisson delay ...
        dummy := s.generateCoverMessage()
        select {
        case client.sndQ <- dummy:
            // cover message queued for delivery
        default:
            // send queue full, skip this dummy
        }
    }
}
```

Cover messages and real messages share the same `sndQ` channel. The sender goroutine serializes them identically - it does not know (or care) whether a response is a real MSG or a cover traffic dummy. This architectural decision ensures that cover traffic is indistinguishable from real traffic at every layer of the system, not just on the wire.

---

## Connection Cleanup

When a client disconnects, all its subscriptions must be released:

```go
func (s *Server) clientDisconnected(client *Client) {
    for recipientID := range client.subscriptions {
        s.subHub.Unsubscribe(recipientID, client)
    }
    client.conn.Close()
    s.connectionCount.Add(-1)
}
```

Messages for the disconnected client remain in the queue store. When the client reconnects and sends SUB again, delivery resumes from the last unACKed message.

---

## Scaling Characteristics

| Metric | Performance |
|---|---|
| Subscribe | O(1) - sync.Map.Swap |
| Unsubscribe | O(1) - sync.Map.CompareAndDelete |
| Lookup (TryDeliver) | O(1) - sync.Map.Load |
| Memory per subscription | ~100 bytes (key + pointer) |
| 10,000 subscriptions | ~1 MB |
| 100,000 subscriptions | ~10 MB |
| Concurrent reads | Lock-free (unlimited) |
| Concurrent writes | Lock-free for different keys, serialized for same key |

The subscription hub is not a bottleneck at any realistic messaging scale. The bottlenecks, if any, are network I/O and disk I/O for message persistence.

---

*GoRelay - IT and More Systems, Recklinghausen*
