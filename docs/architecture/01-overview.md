---
title: "Overview"
sidebar_position: 1
---

# Server Architecture Overview

*How GoRelay is structured internally - from the dual-port listener to the shared queue store, with every component designed for simplicity, testability, and zero-knowledge operation.*

**Status:** In development
**Date:** 2026-03-09 (Session 001)

---

## Design Goals

GoRelay's architecture serves three priorities in strict order:

1. **Security:** Zero-knowledge by construction. The server cannot learn message content, user identities, or communication patterns even if every line of code is inspected.
2. **Simplicity:** A single developer should be able to understand the entire system. No microservices, no message queues, no external dependencies beyond the binary itself.
3. **Performance:** Handle thousands of concurrent connections on commodity hardware. Not because messaging requires it, but because headroom means fewer servers and less operational complexity.

---

## Package Structure

```
cmd/
  gorelay/
    main.go              Entry point, CLI, signal handling

internal/
  config/
    config.go            Configuration loading (koanf)
    defaults.go          Default values
    validate.go          Configuration validation

  server/
    server.go            Core server struct, lifecycle management
    smp_listener.go      SMP listener (port 5223, TLS 1.3)
    grp_listener.go      GRP listener (port 7443, Noise + PQC)
    client.go            Client connection struct
    metrics.go           Prometheus metrics

  protocol/
    smp/
      parser.go          SMP binary frame parser
      serializer.go      SMP response serializer
      commands.go        SMP command handlers
      handshake.go       SMP version handshake
    grp/
      parser.go          GRP frame parser
      serializer.go      GRP response serializer
      commands.go        GRP command handlers (superset of SMP)
      noise.go           Noise handshake + hybrid PQC
      relay.go           PFWD/RFWD relay routing
    common/
      block.go           16 KB block read/write (shared)
      transmission.go    Transmission encoding/decoding (shared)

  queue/
    store.go             QueueStore interface
    badger.go            BadgerDB implementation
    memory.go            In-memory implementation (testing)
    message.go           Message types and operations
    ttl.go               TTL enforcement and garbage collection

  subscription/
    hub.go               SubscriptionHub (queue -> client mapping)
    cover.go             Cover traffic generator

  relay/
    pool.go              Relay-to-relay connection pool
    forward.go           Message forwarding logic
    auth.go              Peer relay authentication

configs/
  gorelay.yaml           Example configuration file
```

The `internal/` package ensures that nothing is importable by external code. GoRelay is a server binary, not a library.

### Dependency Rules

```
cmd/gorelay -> internal/server -> internal/protocol/smp
                                -> internal/protocol/grp
                                -> internal/protocol/common
                                -> internal/queue
                                -> internal/subscription
                                -> internal/relay
                                -> internal/config
```

**Critical rule:** `smp/` and `grp/` never import each other. Both import `common/` for shared block framing and transmission encoding. Both interact with the same `QueueStore` interface and `SubscriptionHub`.

---

## Core Components

### Server

The `Server` struct is the top-level coordinator. It owns the listeners, the queue store, the subscription hub, and the relay pool:

```go
type Server struct {
    config        *config.Config
    queueStore    queue.Store
    subHub        *subscription.Hub
    relayPool     *relay.Pool
    smpListener   net.Listener
    grpListener   net.Listener
    metrics       *Metrics
}
```

The server starts both listeners concurrently using `errgroup.WithContext`. If either listener fails fatally, the context cancellation propagates to all components for graceful shutdown.

### Client

Each connection (SMP or GRP) creates a `Client` struct that holds the connection state:

```go
type Client struct {
    conn          net.Conn          // TLS or Noise connection
    protocol      Protocol          // SMP or GRP
    rcvQ          chan Command       // receiver -> processor (buffered, 128)
    sndQ          chan Response      // processor/cover -> sender (buffered, 128)
    subscriptions map[[24]byte]bool  // active queue subscriptions
    limiter       *rate.Limiter     // per-connection rate limit
    createdAt     time.Time
    lastActivity  time.Time
}
```

Three goroutines per client: receiver, processor, sender. All three share the context - if any exits, all three shut down cleanly.

### QueueStore Interface

```go
type Store interface {
    CreateQueue(recipientKey ed25519.PublicKey, dhKey *ecdh.PublicKey) (*Queue, error)
    GetQueue(recipientID [24]byte) (*Queue, error)
    GetQueueBySender(senderID [24]byte) (*Queue, error)
    SetSenderKey(recipientID [24]byte, senderKey ed25519.PublicKey) error
    DisableQueue(recipientID [24]byte) error
    DeleteQueue(recipientID [24]byte) error
    PushMessage(senderID [24]byte, flags byte, body []byte) (*MessageID, error)
    PopMessage(recipientID [24]byte) (*Message, error)
    AckMessage(recipientID [24]byte, msgID [24]byte) error
}
```

The interface is deliberately minimal. Both `badger.go` (production) and `memory.go` (testing) implement it. No leaky abstractions, no ORM, no query builder.

### SubscriptionHub

```go
type Hub struct {
    subscribers sync.Map  // [24]byte (recipientID) -> *Client
}
```

Maps queue IDs to active client connections. When a message arrives via SEND, the hub checks if a subscriber exists and routes the MSG delivery directly to the client's `sndQ` channel. If no subscriber, the message waits in the store.

---

## Data Flow

### Message Send (Single-Hop)

```
1. Sender connects via SMP or GRP
2. Sender sends SEND command with encrypted message
3. Receiver goroutine parses block, extracts SEND
4. Processor goroutine:
   a. Validates sender signature
   b. Calls queueStore.PushMessage()
   c. Checks subHub for active subscriber
   d. If subscriber exists: pushes MSG to subscriber's sndQ
   e. Responds OK to sender's sndQ
5. Subscriber's sender goroutine writes MSG as 16 KB block
6. Subscriber's client receives and decrypts message
```

### Message Send (Two-Hop)

```
1. Sender connects to Relay A via GRP
2. Sender sends PFWD with s2d-encrypted payload
3. Relay A's processor:
   a. Wraps payload in f2d encryption
   b. Forwards via RFWD to Relay B (connection pool)
4. Relay B's processor:
   a. Decrypts f2d layer
   b. Decrypts s2d layer (reads destination queue)
   c. Calls queueStore.PushMessage()
   d. Routes to subscriber if present
   e. Returns result via RRES to Relay A
5. Relay A returns PRES to sender
```

---

## Concurrency Model

GoRelay uses Go's standard concurrency patterns:

**Goroutine-per-connection:** Each client gets 3 goroutines (receiver, processor, sender) plus 1 optional goroutine for cover traffic. With 1,000 clients, that is 3,000-4,000 goroutines - well within Go's capabilities.

**Channel-based communication:** The `rcvQ` and `sndQ` channels decouple the receiver from the processor from the sender. Backpressure propagates naturally through channel blocking.

**Context-based cancellation:** A single `context.Context` per connection coordinates shutdown. Cancel the context and all goroutines exit cleanly.

**sync.Map for subscriptions:** Lock-free concurrent access for the read-heavy subscription lookup pattern.

**No mutexes in hot paths:** The queue store (BadgerDB) handles its own concurrency. The subscription hub uses sync.Map. Channel operations are inherently synchronized. The only mutex is in the relay connection pool for idle connection management.

---

## Memory Model

### Per-Connection Memory

| Component | Size | Notes |
|---|---|---|
| TLS/Noise state | ~8 KB | Session keys, buffers |
| Read buffer | 16 KB | Fixed array, reused |
| Write buffer | 16 KB | Fixed array, reused |
| rcvQ channel | ~16 KB | 128 slots * pointer |
| sndQ channel | ~16 KB | 128 slots * pointer |
| Goroutine stacks (3x) | ~24 KB | 8 KB each, grows as needed |
| Client struct | ~1 KB | Metadata, subscription map |

**Total per connection:** approximately 100 KB

**1,000 connections:** approximately 100 MB
**10,000 connections:** approximately 1 GB

### Queue Store Memory

BadgerDB keeps keys and metadata in memory (LSM tree) while values (encrypted message blobs) stay on disk (value log). For a server with 10,000 active queues and 50,000 pending messages:

| Component | Size |
|---|---|
| Queue metadata (10K queues) | ~5 MB |
| Message index (50K messages) | ~10 MB |
| BadgerDB LSM overhead | ~20 MB |
| **Total** | **~35 MB** |

Message content (the actual encrypted blobs) is stored on disk via BadgerDB's value log. Only metadata and indexes live in memory.

---

## Error Handling

GoRelay follows Go's explicit error handling philosophy:

**Connection errors:** Close the connection, release all subscriptions, log at INFO level. Connection drops are expected in mobile messaging.

**Queue store errors:** Return ERR INTERNAL to the client, log at ERROR level. Do not crash the server.

**Configuration errors:** Fail fast at startup. Do not start with invalid configuration.

**Cryptographic errors:** Return ERR AUTH to the client, log at WARN level. Rate limit the connection. Do not reveal which specific check failed (prevents oracle attacks).

**Panic recovery:** Each client goroutine has a deferred recover() that logs the panic and closes the connection. A panic in one connection must never crash the server or affect other connections.

---

*GoRelay - IT and More Systems, Recklinghausen*
