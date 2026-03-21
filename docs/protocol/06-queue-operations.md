---
title: "Queue Operations"
sidebar_position: 6
---

# GRP Protocol Specification: Queue Operations

*Complete specification of queue lifecycle management, command semantics, state transitions, and idempotency guarantees.*

**Version:** GRP/1 (Draft)
**Status:** In development
**Date:** 2026-03-09

---

## Queue Lifecycle

A GRP queue passes through a well-defined lifecycle from creation to deletion:

```
          NEW
           |
           v
      +---------+
      |  ACTIVE  |<----+
      +---------+      |
       |       |        |
      OFF     DEL    SUB (re-enable)
       |       |
       v       v
  +---------+  +----------+
  | DISABLED|  |  DELETED  |
  +---------+  +----------+
       |
      DEL
       |
       v
  +----------+
  |  DELETED  |
  +----------+
```

**ACTIVE:** The queue accepts SEND commands from the sender and delivers messages to a subscribed recipient. This is the normal operating state.

**DISABLED:** The queue stops accepting new SEND commands but continues to deliver already-stored messages to the recipient. Used for graceful queue migration during rotation.

**DELETED:** The queue and all associated data are permanently removed. This state is terminal and irreversible.

---

## Commands

### NEW - Create Queue

**Direction:** Client to Server
**Entity ID:** Empty (server assigns IDs)
**Requires signature:** Yes (recipient key)

**Request parameters:**
```
recipient_public_key:  Ed25519 public key (32 bytes)
dh_public_key:         X25519 public key (32 bytes) for server re-encryption
```

**Response:** IDS

**Behavior:**
1. Server generates a random 24-byte `recipient_id`
2. Server generates a random 24-byte `sender_id`
3. Server generates an X25519 keypair for server-side re-encryption
4. Server creates the queue record in the store
5. Server implicitly subscribes the creating connection to this queue
6. Server responds with IDS containing both IDs and the server's DH public key

**Idempotency:** If the client retries NEW with the same recipient_public_key and the queue already exists, the server returns the existing IDS response. This handles lost responses on unreliable connections.

**Rate limit:** Maximum 10 NEW commands per connection per minute.

### IDS - Queue Created Response

**Direction:** Server to Client
**Entity ID:** The new recipient_id

**Response parameters:**
```
recipient_id:          24 bytes (random, used by recipient for queue management)
sender_id:             24 bytes (random, given to sender for message delivery)
server_dh_public_key:  X25519 public key (32 bytes) for re-encryption
```

The recipient shares the `sender_id` and `server_dh_public_key` with the sender through a separate channel (the end-to-end encrypted application layer). The `recipient_id` is never shared with anyone.

---

### SUB - Subscribe to Queue

**Direction:** Client to Server
**Entity ID:** recipient_id
**Requires signature:** Yes

**Request parameters:** None

**Response:** OK (subscription confirmed) or MSG (if a message is pending)

**Behavior:**
1. Server verifies the signature against the queue's recipient_public_key
2. If another connection has an active subscription to this queue, that connection receives an END notification and its subscription is removed
3. The new connection becomes the active subscriber
4. If an undelivered message exists, the server immediately delivers it via MSG
5. If no message exists, the server responds with OK and delivers messages as they arrive

**Critical rule:** Only ONE connection can subscribe to a queue at any time. This is fundamental to the protocol's correctness and handles mobile reconnection gracefully.

**After NEW:** A queue created with NEW is immediately subscribed on the creating connection. Calling SUB on the same connection is a no-op but will re-deliver the last unACKed message if one exists.

---

### KEY - Set Sender Key

**Direction:** Client to Server
**Entity ID:** recipient_id
**Requires signature:** Yes (recipient key)

**Request parameters:**
```
sender_public_key:  Ed25519 public key (32 bytes)
```

**Response:** OK

**Behavior:**
1. Server verifies the signature against the queue's recipient_public_key
2. Server stores the sender_public_key in the queue record
3. Subsequent SEND commands to this queue's sender_id must be signed with this key

**One-time operation:** KEY can only be called once per queue. Calling it again returns ERR DUPLICATE. To change the sender key, create a new queue (queue rotation).

---

### SEND - Send Message

**Direction:** Client to Server
**Entity ID:** sender_id
**Requires signature:** Yes (sender key, after KEY is set)

**Request parameters:**
```
flags:         1 byte (cover_traffic, notification, priority)
message_body:  variable length (encrypted by client, opaque to server)
```

**Response:** OK

**Behavior:**
1. Server verifies the signature against the queue's sender_public_key
2. Server generates a 24-byte message_id (timestamp + sequence + random)
3. Server re-encrypts the message body using the queue's DH shared secret with message_id as nonce
4. Server stores the re-encrypted message with its message_id and timestamp
5. If a recipient is subscribed and has ACKed the previous message, server delivers via MSG immediately
6. If no recipient is subscribed or the previous message is unACKed, the message waits in the queue

**Maximum message body size:** 16,101 bytes (16,382 max payload - overhead for headers, signature, and framing).

**Queue disabled:** If the queue is in DISABLED state, SEND returns ERR DISABLED.

---

### MSG - Message Delivery

**Direction:** Server to Client
**Entity ID:** recipient_id

**Delivery parameters:**
```
message_id:    24 bytes
timestamp:     8 bytes (uint64 BE, Unix seconds)
flags:         1 byte
message_body:  variable length (re-encrypted by server)
```

**Behavior:**
1. Server delivers the oldest unACKed message in the queue
2. The message remains in the queue until the recipient sends ACK
3. Only one message is in-flight (unACKed) at a time per queue
4. If the connection drops before ACK, the message is re-delivered on the next SUB

**One message at a time:** GRP delivers messages strictly sequentially. The server does not send the next message until the current one is ACKed. This simplifies the client implementation and ensures reliable, ordered delivery.

---

### ACK - Acknowledge Message

**Direction:** Client to Server
**Entity ID:** recipient_id
**Requires signature:** Yes

**Request parameters:**
```
message_id:  24 bytes (the ID of the message being acknowledged)
```

**Response:** OK, optionally followed by MSG if another message is queued

**Behavior:**
1. Server verifies the signature and message_id
2. Server permanently deletes the acknowledged message (both encrypted blob and encryption key)
3. Server securely zeros the message content in memory
4. If another message is waiting in the queue, server immediately delivers it via MSG
5. If no more messages, server responds with OK

**Cryptographic deletion:** On ACK, the server deletes both the encrypted message and its per-message symmetric key. Even if the encrypted blob temporarily persists on disk before garbage collection, it is unreadable without the key.

---

### GET - Poll Without Subscription

**Direction:** Client to Server
**Entity ID:** recipient_id
**Requires signature:** Yes

**Request parameters:** None

**Response:** MSG (if message available) or ERR NO_MSG

**Behavior:**
1. Server checks if an undelivered message exists for this queue
2. If yes, delivers via MSG (the message still requires ACK)
3. If no, returns ERR NO_MSG
4. Does NOT create a persistent subscription - no ongoing delivery

**Use case:** Lightweight polling for clients that cannot maintain persistent connections (e.g., constrained IoT devices that wake periodically).

---

### OFF - Disable Queue

**Direction:** Client to Server
**Entity ID:** recipient_id
**Requires signature:** Yes

**Request parameters:** None

**Response:** OK

**Behavior:**
1. Queue transitions to DISABLED state
2. New SEND commands are rejected with ERR DISABLED
3. Already-stored messages continue to be deliverable
4. Subscriptions remain active

**Use case:** First step of queue rotation - disable the old queue to stop new messages while draining existing ones.

---

### DEL - Delete Queue

**Direction:** Client to Server
**Entity ID:** recipient_id
**Requires signature:** Yes

**Request parameters:** None

**Response:** OK

**Behavior:**
1. All messages in the queue are permanently deleted (both blobs and keys)
2. The queue record is permanently deleted
3. Active subscriptions receive END and are removed
4. The recipient_id and sender_id are freed (but will never be reused)
5. The queue transitions to DELETED state

**Irreversible:** There is no recovery after DEL. The client should ensure all messages are delivered and ACKed before deleting.

---

### PING / PONG - Keep-Alive

**Direction:** PING client to server, PONG server to client
**Entity ID:** Empty
**Requires signature:** No

**Request parameters:** None

**Response:** PONG

**Behavior:** Simple keep-alive to maintain the connection and subscription state. The server drops subscriptions after 5 minutes of inactivity. Clients MUST send PING at least every 60 seconds.

---

### END - Subscription Terminated

**Direction:** Server to Client
**Entity ID:** recipient_id

**Behavior:** Informs the client that its subscription to the specified queue has been taken over by another connection (a new SUB command from a different socket). The client should stop expecting message deliveries on this queue from this connection.

---

## Queue Rotation

### QROT - Initiate Rotation

**Direction:** Client to Server
**Entity ID:** recipient_id (old queue)
**Requires signature:** Yes

**Request parameters:**
```
new_recipient_id:    24 bytes (pre-created on same or different server)
new_sender_id:       24 bytes
migration_window:    uint32 (seconds to keep old queue active, max 3600)
```

**Response:** OK

**Behavior:**
1. Server marks the old queue for rotation with the specified migration window
2. During the migration window, both old and new queues are active
3. After the migration window, the old queue is automatically disabled (OFF)
4. The old queue is automatically deleted after an additional grace period (24 hours)

### QACK - Rotation Acknowledged

**Direction:** Server to Client
**Entity ID:** recipient_id (old queue)

**Behavior:** Confirms that the rotation has been registered and the migration window is active.

### Automatic Rotation Triggers

GRP clients SHOULD implement automatic queue rotation based on:

- **Time:** Every 24-72 hours (with random jitter of plus or minus 6 hours)
- **Message count:** Every 100-500 messages
- **Server diversity:** When rotating, prefer a different GoRelay server

The jitter is critical - without it, an adversary can correlate old and new queues by observing that one queue disappears and another appears at predictable intervals.

---

## State Machine

### Queue State Transitions

```
State: EMPTY (queue just created, no sender key)
  KEY -> READY
  DEL -> DELETED

State: READY (sender key set, no messages)
  SEND -> HAS_MESSAGES
  OFF  -> DISABLED
  DEL  -> DELETED

State: HAS_MESSAGES (messages waiting for delivery)
  SUB  -> DELIVERING
  GET  -> DELIVERING
  OFF  -> DISABLED_DRAINING
  DEL  -> DELETED

State: DELIVERING (actively delivering to subscriber)
  ACK  -> READY (if no more messages) or HAS_MESSAGES (if more)
  END  -> HAS_MESSAGES (subscription taken over)
  SEND -> DELIVERING (new message queued behind current)
  OFF  -> DISABLED_DRAINING
  DEL  -> DELETED

State: DISABLED (no new sends, no pending messages)
  DEL  -> DELETED

State: DISABLED_DRAINING (no new sends, delivering remaining messages)
  ACK  -> DISABLED (if no more messages)
  DEL  -> DELETED
```

### Connection State Transitions

```
State: CONNECTED (TLS/Noise handshake complete)
  Any command -> ACTIVE
  Timeout (30s no command) -> DISCONNECTED

State: ACTIVE (at least one command sent)
  PING -> ACTIVE (reset inactivity timer)
  Any command -> ACTIVE
  Timeout (5min no activity) -> DISCONNECTED

State: DISCONNECTED
  All subscriptions for this connection receive END
  All resources freed
```

---

## Idempotency Requirements

All state-changing commands MUST be idempotent. This is essential for reliable operation over unreliable networks:

| Command | Retry behavior |
|---|---|
| NEW | Returns existing IDS if queue already created with same key |
| SUB | Re-subscribes (safe to call multiple times) |
| KEY | Returns ERR DUPLICATE if already set (client knows key was set) |
| SEND | Server deduplicates by correlation_id within a 5-minute window |
| ACK | No-op if message already deleted (returns OK) |
| OFF | No-op if already disabled (returns OK) |
| DEL | No-op if already deleted (returns OK) |
| PING | Always safe to retry |

The correlation_id in each transmission enables the server to detect duplicate commands. If the server receives a command with a correlation_id it has already processed within the deduplication window, it returns the cached response without re-executing the command.

---

## Message TTL and Expiry

Messages that are not delivered within the configured TTL are automatically deleted:

- **Default TTL:** 48 hours
- **Hard maximum:** 7 days (server-enforced, cannot be overridden)
- **Minimum TTL:** 1 hour (prevents accidental instant expiry)

TTL is enforced via BadgerDB's native key expiry. A background goroutine runs garbage collection every 5 minutes to reclaim disk space from expired entries.

Messages approaching expiry (within 1 hour of TTL) are NOT delivered to prevent the recipient from receiving a message that expires before it can be processed.

---

*GoRelay Protocol Specification - IT and More Systems, Recklinghausen*
