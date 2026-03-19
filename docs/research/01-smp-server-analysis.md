---
title: "SMP Server Analysis"
sidebar_position: 1
---

# SMP Server Analysis

*Deep analysis of the SimpleX Messaging Protocol server architecture, based on the simplexmq Haskell reference implementation.*

**Research date:** 2026-03-09 (Session 001)

---

## What is SMP?

SMP (SimpleX Messaging Protocol) is a transport protocol for asynchronous message delivery through relay servers. It was designed by Evgeny Poberezkin as part of the SimpleX ecosystem and is the only messaging protocol that operates without any form of user identity - no phone numbers, no usernames, no public keys as identifiers.

The protocol operates on unidirectional simplex queues: each queue has exactly one sender and one recipient, identified by random 24-byte IDs. A full duplex conversation between two users requires two queues, potentially hosted on different servers. The server maintains zero user identities - only ephemeral queue records with cryptographic keys.

The reference implementation is written in Haskell and published under AGPL-3.0 at github.com/simplex-chat/simplexmq.

---

## Server Architecture

### Three Threads Per Connection

The simplexmq server spawns three concurrent Haskell threads for every client connection:

**Reader thread:** Reads 16 KB blocks from the TLS connection, parses the binary frames into SMP transmissions, verifies cryptographic signatures, and places parsed commands into an internal receive queue (STM TQueue).

**Processor thread:** Reads commands from the receive queue, dispatches them against the queue store (creating queues, storing messages, managing subscriptions), and places responses into a send queue.

**Writer thread:** Reads responses from the send queue, serializes them into 16 KB padded blocks, and writes them to the TLS connection.

This separation ensures the read path never blocks on write backpressure and vice versa. The three threads communicate exclusively through STM (Software Transactional Memory) channels, which provides race-condition-free concurrent access without explicit locking.

### Connection Lifecycle

1. Client connects via TCP to port 5223
2. TLS 1.3 handshake with ALPN "smp/1"
3. SMP handshake: server sends version range + server public key, client sends client version + client public key + auth
4. Version negotiation settles on agreed version
5. Client sends commands (NEW, SUB, SEND, ACK, PING, etc.)
6. Server responds with results or delivers messages
7. Connection remains open for subscription delivery and keep-alive

---

## Transport Layer

### Fixed 16 KB Block Framing

Every SMP frame on the wire is exactly 16,384 bytes. No exceptions, no dynamic sizing, no chunking. This is a deliberate security decision - fixed-size blocks prevent traffic analysis based on message length. An observer cannot distinguish a short text message from a long one or from a keep-alive ping.

The block format:

```
paddedBlock = originalLength (2 bytes, uint16 big-endian) + content + padding
```

The first 2 bytes encode the actual content length as a big-endian unsigned 16-bit integer. The content follows immediately. The remaining bytes up to 16,384 are filled with '#' characters as padding.

### Transmission Format

Within a block, the content contains one or more transmissions (batching was added in protocol v4):

```
content = transmissionCount (1 byte) + transmissions
transmission = transmissionLength (2 bytes, uint16 BE) + signedTransmission
signedTransmission = signature + sessionId + corrId (24 bytes) + entityId + command
```

The `signature` and `sessionId` use a shortString format with a 1-byte length prefix. The `corrId` (correlation ID) is always 24 bytes and links responses to requests. The `entityId` identifies the queue being operated on.

### TLS Configuration

The server uses TLS 1.3 exclusively with ALPN negotiation set to "smp/1". The trust model uses a two-certificate chain: an offline CA cert (whose fingerprint appears in the server address `smp://<fingerprint>@<host>`) signs an online TLS cert. This allows certificate rotation without changing the server's identity.

---

## Queue Model

### Unidirectional Simplex Queues

Each queue is strictly unidirectional - one sender, one recipient. A queue record contains:

- **recipientId:** 24-byte random identifier used by the recipient to manage the queue
- **senderId:** 24-byte random identifier used by the sender to push messages
- **Recipient public key:** Ed25519/X25519 key for verifying recipient commands
- **Sender public key:** Optional, set via KEY command after queue creation
- **Server DH public key:** Used for server-side re-encryption
- **Status flag:** Active, disabled, or deleted

The recipient and sender IDs are completely unrelated - there is no way to correlate them without access to the server's internal state. This is a core privacy property of SMP.

### Server-Side Re-Encryption

When delivering a message, the server re-encrypts it using a DH-derived shared secret (from queue creation) with the msgId as nonce via NaCl crypto_box. This means the ciphertext arriving at the server from the sender is different from the ciphertext leaving the server to the recipient. Even if TLS is compromised on both sides, an observer cannot correlate incoming and outgoing messages by comparing ciphertext.

---

## Commands

### Recipient Commands

| Command | Purpose |
|---------|---------|
| NEW | Create a new message queue. Returns recipientId, senderId, and server DH key. The queue is immediately subscribed after creation. |
| SUB | Subscribe to a queue to receive messages. If a message is pending, it is delivered immediately. |
| KEY | Set the sender's public key on the queue (one-time operation). |
| ACK | Acknowledge receipt of a message. The server deletes the message and delivers the next one if available. |
| OFF | Disable a queue (stop accepting new messages). |
| DEL | Permanently delete a queue. |
| GET | Poll for a message without maintaining a subscription. |

### Sender Commands

| Command | Purpose |
|---------|---------|
| SEND | Push an encrypted message to a queue via the senderId. |
| PING | Keep-alive. Server responds with PONG. |

### Server Responses

| Response | Purpose |
|----------|---------|
| IDS | Response to NEW - contains recipientId, senderId, server DH key. |
| MSG | Deliver a message to a subscribed recipient. |
| END | Notify that a subscription was terminated (another socket subscribed). |
| OK | Generic success response. |
| ERR | Error response with error code. |
| PONG | Response to PING. |

---

## Subscription Semantics

### One Subscription Per Queue

This is one of the most critical protocol rules: only ONE connection can subscribe to a queue at any time. If a client subscribes to a queue from socket B while socket A already has an active subscription, socket A receives an END notification and the subscription transfers to socket B.

This design handles mobile reconnection gracefully - when a phone loses connectivity and reconnects on a new socket, the old socket's subscription is automatically replaced. The server does not need to detect dead connections through timeouts before allowing re-subscription.

### NEW Creates an Implicit Subscription

When a recipient creates a queue with NEW, that queue is immediately subscribed on the creating connection. A subsequent SUB command on the same connection is a no-op (but will re-deliver the last unACKed message if one exists).

### Message Delivery Flow

1. Sender pushes message via SEND to senderId
2. Server stores message in queue, re-encrypts it
3. If recipient is subscribed, server delivers via MSG immediately
4. If recipient is not subscribed, message waits in queue
5. When recipient ACKs, server deletes message and delivers next (if any)
6. Messages remain in queue until ACKed or expired

### Keep-Alive

PING/PONG keep-alive is essential. Without regular PING messages, the server will eventually drop the subscription after a timeout. The client must send PINGs at regular intervals (typically every 30-60 seconds) to maintain its subscriptions.

---

## Idempotency

All state-changing commands MUST be idempotent. This is critical for handling lost responses - if a client sends NEW but never receives the IDS response (network interruption), it must be safe to retry the operation. The server handles this by checking if the operation has already been completed and returning the same result.

This property was explicitly stated by Evgeny Poberezkin as a core protocol requirement derived from the realities of unreliable network communication.

---

## Storage Architecture

### In-Memory Queue Store

The Haskell server primarily uses STM-backed in-memory data structures for queue and message storage. Messages have short lifetimes (deleted after ACK) which keeps the working set small.

The server also supports persistent storage via an append-only log for crash recovery. On startup, the log is replayed to reconstruct the in-memory state.

### Message Retention

Messages are stored until the recipient acknowledges them via ACK. The server can be configured with a maximum retention period after which undelivered messages are automatically deleted. There is no built-in minimum retention requirement - the protocol design favors aggressive deletion.

---

## What GoRelay Learns From This

The simplexmq architecture validates several design decisions for GoRelay:

**Three concurrent handlers per connection** maps directly to Go's goroutine model. Go channels replace STM TQueues for inter-goroutine communication.

**Fixed 16 KB block framing** is trivial to implement in Go using `io.ReadFull` for exact reads and fixed-size byte arrays for writes.

**The subscription model** (one subscriber per queue, END on takeover) can be implemented with a `sync.Map` mapping queue IDs to active client connections.

**Server-side re-encryption** adds meaningful security but increases per-message CPU cost. GoRelay will implement this in Phase 2.

**In-memory store with persistent backup** maps to GoRelay's architecture of in-memory queues over BadgerDB. BadgerDB's native TTL replaces the need for custom expiry logic.

The key difference: GoRelay will build this in Go (single binary, cross-compilation, audited crypto) instead of Haskell (GHC runtime, complex deployment, unaudited crypto libraries), and add GRP protocol support for enhanced security properties that SMP does not provide.

---

*GoRelay - IT and More Systems, Recklinghausen*
