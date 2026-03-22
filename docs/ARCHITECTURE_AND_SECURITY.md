---
title: "GoRelay Architecture & Security"
sidebar_position: 1
---

# GoRelay Architecture & Security

**Document version:** Season 002 | March 2026
**Runtime:** Linux (any architecture), single binary
**Copyright:** (c) 2025-2026 Sascha Daemgen, IT and More Systems, Recklinghausen
**License:** AGPL-3.0

---

## Overview

| Property | Details |
|----------|---------|
| Protocol | SMP v7 (SimpleX Messaging Protocol) + GRP/1 (GoRelay Protocol, planned) |
| Language | Go 1.24+, single binary compilation, zero runtime dependencies |
| Concurrency | Three goroutines per connection (receiver, processor, sender) |
| Persistence | BadgerDB v4 with per-message AES-256-GCM encryption |
| Transport | TLS 1.2, ChaCha20-Poly1305, Ed25519, X25519 |
| Block size | Fixed 16,384 bytes, '#' padded |
| Test status | SimpleX Chat Desktop server test PASSED (March 22, 2026) |
| Binary size | ~15 MB |
| Memory | 608 KB heap, 12.5 MB system at idle |

GoRelay is not a proxy or middleware. It is a complete SMP relay server that stores and forwards encrypted messages. The server is zero-knowledge by construction - the code to read message content does not exist.

---

## 1. Goroutine Architecture

Three goroutines run per SMP connection, communicating via Go channels. This mirrors the Haskell reference server's three-thread model (reader, writer, processor) but uses Go's lightweight goroutine scheduler instead of GHC's green threads.

| Goroutine | Responsibility |
|-----------|---------------|
| `receiver` | Reads 16 KB blocks via `io.ReadFull` from TLS connection. Parses transmissions (authorization, corrId, entityId, command). Sends parsed commands to processor via channel. Panic recovery with `debug.Stack()` logging. |
| `processor` | Dispatches commands to handlers (handleNEW, handleSUB, handleSEND, etc.). Manages queue state via QueueStore interface. Echoes entityId in OK/ERR responses. Sends responses to sender via channel. |
| `sender` | Serializes responses into 16 KB blocks with '#' padding. Writes blocks to TLS connection. Handles delivery ordering (MSG after OK). Panic recovery with logging. |

### Inter-Goroutine Communication

| Mechanism | Direction | Description |
|-----------|-----------|-------------|
| `cmdChan` | Receiver -> Processor | Parsed Command structs with corrId, entityId, signature, body |
| `respChan` | Processor -> Sender | Response structs with type, corrId, entityId, body, optional deliveries |
| `doneChan` | Any -> All | Connection shutdown signal, closes all goroutines |

### Connection Lifecycle

| Phase | What happens |
|-------|-------------|
| 1. TLS Accept | TCP accept, TLS 1.2 handshake, ChaCha20-Poly1305, ALPN `smp/1` |
| 2. TLS Unique | Extract `ConnectionState().TLSUnique` for session binding (RFC 5929) |
| 3. SMP Handshake | Server sends ServerHello (version range + sessionId + cert + signed DH key). Client sends ClientHello (version + keyHash). Verify keyHash matches CA fingerprint. |
| 4. Spawn Goroutines | Three goroutines started with shared channels and connection state |
| 5. Command Loop | Receiver reads blocks, processor dispatches, sender writes responses |
| 6. Disconnect | Channel close propagates to all goroutines. SubscriptionHub cleanup. Metrics update. |

---

## 2. Memory Architecture

Go manages memory via its garbage collector. GoRelay's memory footprint is minimal because the server is stateless except for the QueueStore and SubscriptionHub.

| Component | Typical Size | Contents |
|-----------|-------------|----------|
| Per-connection | ~50 KB | TLS state (~30 KB), three goroutine stacks (~6 KB each), channels, buffers |
| QueueStore (memory) | Variable | Queue metadata + messages (tests only) |
| QueueStore (BadgerDB) | Variable | On-disk LSM tree, ~2 GB for 100K+ messages |
| SubscriptionHub | ~100 bytes/queue | sync.Map entry per active subscription |
| Admin metrics | ~1 KB | Atomic counters, security event ring buffer (50 entries) |
| Embedded dashboard | ~50 KB | Single HTML file via go:embed |

### Memory Safety

- Go is memory-safe by default (no buffer overflows, no use-after-free)
- All key material explicitly zeroed after use with zeroing loops
- `crypto/subtle.ConstantTimeCompare` for all secret comparisons
- No unsafe package usage anywhere in the codebase

---

## 3. Encryption and Security

### Server-Side Encryption (what GoRelay does)

GoRelay performs two types of encryption:

| Type | Algorithm | Purpose |
|------|-----------|---------|
| Storage encryption | AES-256-GCM with random 32-byte per-message key | Protects messages at rest in BadgerDB. Compromising the database file reveals only ciphertext. |
| MSG delivery encryption | NaCl crypto_box (X25519 + XSalsa20 + Poly1305) | Re-encrypts message before delivery to prevent traffic correlation. NOT YET IMPLEMENTED. |

### What GoRelay does NOT do (client responsibility)

GoRelay never touches, parses, or has access to:

- End-to-end encryption (Double Ratchet, X3DH, X448)
- Post-quantum key exchange (sntrup761 or ML-KEM-768)
- Per-queue sender-to-destination encryption
- Message content, contact information, user identities

The server sees only opaque encrypted blobs. It stores them, delivers them, deletes them. Nothing more.

### SMP Handshake Crypto

| Component | Algorithm | Library |
|-----------|-----------|---------|
| TLS transport | TLS 1.2, ChaCha20-Poly1305 | crypto/tls (stdlib) |
| CA certificate | Ed25519 | crypto/ed25519 (stdlib) |
| Online certificate | Ed25519, signed by CA | crypto/x509 (stdlib) |
| Session binding | tls-unique (RFC 5929) | crypto/tls ConnectionState |
| Handshake DH | X25519 ephemeral per connection | crypto/ecdh (stdlib) |
| CA fingerprint | SHA256(cert.Raw), base64url no-pad | crypto/sha256 (stdlib) |
| Signed server key | Ed25519 signature over X25519 SPKI | crypto/ed25519 (stdlib) |

### Storage Crypto (BadgerDB)

| Component | Algorithm | Library |
|-----------|-----------|---------|
| Per-message encryption | AES-256-GCM, random 32-byte key | crypto/aes + crypto/cipher (stdlib) |
| Key generation | crypto/rand | crypto/rand (stdlib) |
| Cryptographic deletion | Key zeroed, then entry deleted | Explicit zeroing loop |

### Command Authentication

| Command | Auth Method | Key Source |
|---------|-------------|------------|
| NEW | Ed25519 signature | recipientAuthPublicKey from command body (self-certifying) |
| SUB | Ed25519 signature | Stored recipientKey from queue record |
| KEY | Ed25519 signature | Stored recipientKey from queue record |
| SKEY | Ed25519 signature | senderKey from command body |
| SEND | Ed25519 signature | Stored senderKey from queue record |
| ACK | Ed25519 signature | Stored recipientKey from queue record |
| DEL | Ed25519 signature | Stored recipientKey from queue record |
| PING | None | Unsigned, no queue context |

All signature verification includes sessionId (tls-unique) in the signed data, even though sessionId is not transmitted on the wire (SMP v7 optimization). This binds every command to the specific TLS session.

---

## 4. Wire Format

### Block Structure

Every SMP transmission is a 16,384-byte block:

```
[contentLength: 2 bytes, Word16 big-endian]
[content: variable length]
[padding: '#' (0x23) bytes to fill 16,384]
```

### Transmission Structure (inside content)

```
[transmissionCount: 1 byte, number of transmissions]
[transmissionLength: 2 bytes, Word16 big-endian]
[transmission: variable]
  [authorization: shortString (1 byte len + signature bytes, or 0x00 for unsigned)]
  [corrId: 0x18 + 24 random bytes for commands, 0x00 for server notifications]
  [entityId: shortString (1 byte len + queue ID bytes, or 0x00 for empty)]
  [command: text-based tag + body]
```

### Encoding Rules

| Type | Format |
|------|--------|
| shortString | 1 byte length prefix + data bytes |
| originalLength | 2 byte Word16 big-endian length prefix + data bytes |
| Ed25519 signature | shortString with length 0x40 (64 bytes) |
| corrId | 0x18 (24) + 24 random bytes, echoed in response |
| entityId | shortString, empty (0x00) for NEW/IDS/PING/PONG |
| SPKI encoding | ASN.1 DER X.509 SubjectPublicKeyInfo (44 bytes for Ed25519/X25519) |

### Version-Dependent Fields

| Field | Version | Notes |
|-------|---------|-------|
| sessionId in wire | v7+ | Empty on wire, but included in signature computation |
| sndSecure in NEW/IDS | v9+ | Not sent for v7 |
| basicAuth in NEW | v9+ | Not sent for v7 |

---

## 5. SMP Handshake

### ServerHello (server to client, 16 KB block)

```
[smpVersionRange: 4 bytes (min=6 Word16 BE, max=7 Word16 BE)]
[sessionIdentifier: shortString (tls-unique channel binding)]
[serverCert: originalLength + online certificate DER]
[signedServerKey: originalLength + X25519 SPKI DER + Ed25519 signature]
[padding: '#' to 16,384 bytes]
```

### ClientHello (client to server, 16 KB block)

```
[smpVersion: 2 bytes Word16 BE (chosen version)]
[keyHash: shortString (32 bytes raw SHA256 of CA cert.Raw)]
[clientKey: optional shortString (X25519 SPKI, for proxy connections)]
[ignoredPart: remaining bytes, forward compatibility]
[padding: '#' to 16,384 bytes]
```

### Verification Steps

1. Server extracts tls-unique from TLS connection state
2. Server sends ServerHello with session ID, online cert, and signed X25519 key
3. Client verifies signed key against online cert
4. Client verifies online cert is signed by CA
5. Client verifies SHA256(CA cert.Raw) matches fingerprint from SMP URI
6. Client sends keyHash (raw 32-byte SHA256)
7. Server verifies keyHash matches own CA fingerprint using subtle.ConstantTimeCompare
8. Both sides agree on highest mutual version

---

## 6. Queue Operations

### Queue Record Structure

| Field | Type | Purpose |
|-------|------|---------|
| RecipientID | 24 bytes | Recipient's queue identifier |
| SenderID | 24 bytes | Sender's queue identifier |
| RecipientKey | Ed25519 public key | Verifies recipient commands (SUB, ACK, KEY, DEL) |
| SenderKey | Ed25519 public key | Verifies sender commands (SEND), set via KEY/SKEY |
| ServerDHPubKey | X25519 public key | Server's DH key for MSG re-encryption |
| ServerDHSecret | X25519 private key | Server's DH secret (stored for MSG delivery) |

### Command Flow

```
Recipient                    GoRelay                      Sender
    |                           |                            |
    |--- NEW (authKey+dhKey) -->|                            |
    |<-- IDS (rID+sID+dhPub) --|                            |
    |                           |                            |
    |  (share sID+dhPub via     |                            |
    |   out-of-band channel)    |                            |
    |                           |                            |
    |                           |<-- KEY (senderKey) --------|
    |                           |--- OK ------------------->|
    |                           |                            |
    |--- SUB (signed) -------->|                            |
    |<-- OK -------------------|                            |
    |                           |                            |
    |                           |<-- SEND (msg, signed) ----|
    |                           |--- OK ------------------->|
    |<-- MSG (encrypted msg) --|                            |
    |--- ACK (msgId) --------->|                            |
    |                           |  (message deleted +        |
    |                           |   key cryptographically    |
    |                           |   destroyed)               |
```

### Subscription Rules

- Only ONE connection per queue at any time
- NEW creates implicit subscription (subscribeMode='S')
- New SUB sends END to old subscriber (atomic takeover)
- Messages delivered one at a time, ACK required before next
- DEL removes queue, all messages, and subscription

### Idempotency

| Command | Idempotent Behavior |
|---------|---------------------|
| NEW | Same recipientKey returns existing IDS |
| ACK | Already-deleted message returns OK |
| DEL | Already-deleted queue returns OK |

### Redelivery Loop Protection

Messages track `DeliveryAttempts`. After 5 failed deliveries (MSG sent but no ACK), the message is auto-discarded. This prevents a crafted malicious message from bricking the recipient device for the entire TTL period.

---

## 7. File-by-File Analysis

### cmd/gorelay/ (Entry Point)

| File | Function | Status |
|------|----------|--------|
| `main.go` | CLI flag parsing (--smp-port, --grp-port, --host, --data-dir, --admin-port), environment variable support, signal handling (SIGINT/SIGTERM), graceful shutdown | Clean. No shutdown timeout (known issue). |

### cmd/gorelay-test/ (Test Client)

| File | Function | Status |
|------|----------|--------|
| `main.go` | CLI routing for 5 subcommands (ping, create-queue, subscribe, send-message, full-test), ANSI color output, timing reports | Clean. |
| `smpclient.go` | Reusable SMPClient type: TLS connect, SMP handshake, all SMP operations (NEW, KEY, SUB, SEND, ACK), block building, transmission parsing | Clean. Forced TLS 1.2 to match server. |
| `smpclient_test.go` | Tests for ping and full-test against local server | Clean. |

### cmd/smp-capture/ (Diagnostic Tool)

| File | Function | Status |
|------|----------|--------|
| `main.go` | Connects to any SMP server, captures raw 16 KB blocks, prints hex dumps with byte-level analysis. Used to debug wire format differences against official Haskell server. | Diagnostic only. |

### internal/config/

| File | Function | Status |
|------|----------|--------|
| `config.go` | Configuration loading with koanf, Overrides struct for CLI flags and env vars, port validation (1-65535), precedence: CLI > env > defaults | Clean. 7 tests. |

### internal/server/

| File | Function | Status |
|------|----------|--------|
| `server.go` | Main server struct. Dual-port listener (SMP TLS + GRP TCP). Connection handler with panic recovery. Command dispatcher routing NEW/SUB/KEY/SKEY/SEND/ACK/DEL/PING. All SMP command handlers. EntityId echo logic. SessionId prepend for signature verification. Debug hex logging (temporary). | Core file. ~800 lines. Debug logging should be removed for production. |
| `client.go` | Client struct: TLS connection, channels, sessionID, smpVersion. Three goroutine lifecycle management. | Clean. |
| `subscription_hub.go` | SubscriptionHub with sync.Map. Atomic subscription takeover (old subscriber gets END). Thread-safe subscribe/unsubscribe. | Clean. |
| `certmanager.go` | Ed25519 CA generation and persistence. Online certificate signing. TLS config (TLS 1.2, ChaCha20-Poly1305, X25519 only, session tickets disabled). PEM file I/O. Three fingerprint variants logged on startup (cert_hash, spki_hash, pubkey_hash). Accessor methods for online cert DER and signing key. | Clean. TLS 1.2 workaround documented. |
| `metrics.go` | Atomic counters for connections, queues, messages, commands. runtime.MemStats for memory. Security event ring buffer (50 entries). Uptime tracking. | Clean. |
| `admin.go` | HTTP server on 127.0.0.1 only. GET /api/metrics (JSON), GET /api/events (JSON), GET / (embedded dashboard). | Clean. Localhost-only enforced. |
| `web/index.html` | Single self-contained HTML file with inline CSS and JS. Dark mode. Auto-refresh every 2s. SMP URI display with copy button. Stat cards, security events, server config. | Clean. No external dependencies. |

### internal/server/ (Test Files)

| File | Function | Status |
|------|----------|--------|
| `integration_test.go` | PING/PONG over real TLS: single round-trip, sequential, block size, TLS unique non-empty, session binding | 6 tests, clean. |
| `integration_flow_test.go` | Full message flow: NEW->KEY->SEND->MSG->ACK, subscription takeover, FIFO order, idempotency, error cases, SUB pending delivery, delivery counter auto-discard | 13 tests, all parallel. |
| `new_command_test.go` | NEW creates queue, idempotency, unique IDs, DH key validity, store persistence, implicit subscription, v7 format | 8 tests. |
| `skey_command_test.go` | SKEY sets sender key, duplicate returns AUTH, nonexistent queue returns NO_QUEUE, error text format | 4 tests. |
| `del_command_test.go` | DEL removes queue, idempotent on missing, requires valid signature, unsigned returns AUTH, double DEL OK | 5 tests. |
| `echo_entity_id_test.go` | OK to KEY/SUB/SEND includes entityId, ERR includes entityId, IDS has empty entityId, PONG has empty entityId | 6 tests. |
| `message_delivery_test.go` | KEY/SEND/ACK cycle, FIFO ordering, delivery counter | Multiple tests. |

### internal/protocol/common/

| File | Function | Status |
|------|----------|--------|
| `block.go` | ReadBlock (io.ReadFull, exactly 16384 bytes), WriteBlock (content + '#' padding). PaddingByte = '#' (0x23). | Clean. Changed from 0x00 to '#' for SimpleX compatibility. |
| `commands.go` | Command/Response structs. Text-based command tags ("NEW ", "SUB", "SEND ", etc.). parseTransmission with shortString/corrId/entityId extraction. BuildTransmission/WrapTransmissionBlock/BuildSignedData helpers. errorCodeToText mapping (18 error codes). Version-aware serialization (sndSecure only for v9+). | Core file. Complete rewrite from binary to text format in Season 2. |
| `block_test.go` | Block read/write, padding verification, round-trip tests | Clean. |

### internal/protocol/smp/

| File | Function | Status |
|------|----------|--------|
| `handshake.go` | ServerHello/ClientHello encode/decode. X25519 SPKI DER encoding/parsing (EncodeX25519SPKI, ParseX25519SPKI). Ed25519 SPKI encoding/parsing (EncodeEd25519SPKI, ParseEd25519SPKI). Signed server key generation and verification. CA fingerprint computation (SHA256 of cert.Raw, raw and base64url). ALPN fallback (v6-only when smp/1 not negotiated). ErrVersionMismatch, ErrIdentityMismatch, ErrSessionMismatch errors. | Core file. Rewritten multiple times during SimpleX compatibility iterations. |
| `handshake_test.go` | ServerHello/ClientHello encoding round-trips, SPKI encoding, signed key verification, fingerprint stability, identity mismatch, version mismatch, ALPN fallback, session binding | 22 tests. |

### internal/queue/

| File | Function | Status |
|------|----------|--------|
| `store.go` | QueueStore interface (CreateQueue, GetQueue, DeleteQueue, SetSenderKey, PushMessage, PopMessage, AckMessage, FindQueueByRecipientKey, Close). Queue struct with all fields. Message struct with DeliveryAttempts. MemoryStore implementation for tests. MaxDeliveryAttempts=5 constant. Collision-safe ID generation. ConstantTimeCompare for key lookups. | Interface definition. Memory implementation for tests only. |
| `badger_store.go` | BadgerDB v4 implementation of QueueStore. Key schema: q:<recipientID> (queue JSON), s:<senderID> (sender mapping), rk:<sha256(key)> (recipient key index), m:<recipientID>:<seq16>:d/k/t (message data/key/meta). Per-message AES-256-GCM encryption with random 32-byte key. Cryptographic deletion (key zeroed before entry removal). Native TTL (48h default, 7d max). GC goroutine every 5 minutes. Sequence counter for FIFO. slog adapter for BadgerDB logging. | 994 lines. Production store. |
| `badger_store_test.go` | Queue CRUD, idempotency, sender key, delete, push/pop, FIFO order, ACK + idempotent ACK, delivery attempts auto-discard, persistence across restart, TTL expiry, cryptographic deletion, GC goroutine, nonexistent queue operations | 16 tests. |

### internal/relay/ (Phase 5)

| File | Function | Status |
|------|----------|--------|
| (empty) | Relay-to-relay forwarding for two-hop routing | Not started. Phase 5. |

### internal/protocol/grp/ (Phase 4)

| File | Function | Status |
|------|----------|--------|
| (empty) | GRP protocol handlers (Noise transport, ML-KEM-768) | Not started. Phase 4. |

---

## 8. Security Status

### Design Properties (Guaranteed by Architecture)

| Property | How it is guaranteed |
|----------|---------------------|
| Zero-knowledge | Server never has plaintext. All E2E crypto is client-side. Server stores/delivers opaque blobs. |
| No IP logging | No logging code that captures client addresses exists in the codebase. |
| No metadata storage | Queue records contain only cryptographic keys and IDs. No timestamps of who created what. |
| Constant-time auth | Signature verification always runs, even for non-existent queues (dummy verification, result discarded). |
| Forward secrecy | TLS session keys are ephemeral. X25519 DH per connection. |
| Cryptographic deletion | Per-message key zeroed on ACK, then BadgerDB entry deleted. |
| Traffic uniformity | All blocks exactly 16,384 bytes with '#' padding. |

### Known Limitations (Honest Inventory)

| ID | Severity | Description | Status |
|----|----------|-------------|--------|
| LIM-01 | **HIGH** | NaCl crypto_box for MSG delivery not implemented. Real SimpleX clients cannot decrypt delivered messages. Server test passes but actual messaging does not work yet. | **OPEN, Season 3 Block 1** |
| LIM-02 | **MEDIUM** | TLS 1.2 instead of 1.3. Go's crypto/tls does not expose Finished messages for TLS 1.3, required for tls-unique. Security equivalent but technically a downgrade from spec. | **OPEN, workaround** |
| LIM-03 | **MEDIUM** | Debug hex logging active in production. Transmission bytes logged to stdout. No sensitive content but adds noise and minor performance cost. | **OPEN, Season 3 Block 3** |
| LIM-04 | **MEDIUM** | No shutdown timeout. Server may hang on Ctrl+C if connections don't close. Requires kill -9. | **OPEN, Season 3 Block 3** |
| LIM-05 | **MEDIUM** | No rate limiting. Server accepts unlimited connections and commands. | **OPEN, Season 3 Block 3** |
| LIM-06 | **LOW** | No OFF command (queue suspend). | **OPEN, Season 3 Block 2** |
| LIM-07 | **LOW** | No NKEY/NSUB (notification support for mobile push). | **OPEN, Season 3 Block 2** |
| LIM-08 | **LOW** | No GET command (single message without subscribe). | **OPEN, Season 3 Block 2** |
| LIM-09 | **LOW** | No batched transmissions (spec allows multiple per block). | **OPEN, future** |
| LIM-10 | **NONE** | GRP protocol not implemented. | **Phase 4** |
| LIM-11 | **NONE** | Two-hop relay not implemented. | **Phase 5** |
| LIM-12 | **NONE** | Cover traffic not implemented. | **Phase 5** |

### What IS Correctly Implemented

- TLS 1.2 with ChaCha20-Poly1305 + X25519 + Ed25519 (correct cipher suite)
- tls-unique session binding in SMP handshake (RFC 5929)
- Ed25519 CA chain with persistent CA and rotatable online cert
- CA fingerprint as SHA256(cert.Raw) matching SimpleX/Haskell reference
- All command signatures verified with sessionId prepended
- entityId echoed in OK/ERR responses (not in IDS/PONG)
- Version-aware serialization (sndSecure only for v9+)
- '#' padding (not zero bytes) for block framing
- Per-message AES-256-GCM in BadgerDB with cryptographic deletion
- MaxDeliveryAttempts=5 redelivery loop protection
- Idempotent NEW, ACK, DEL
- Subscription takeover with END notification
- FIFO message ordering
- Embedded admin dashboard on localhost only

---

## 9. Roadmap

### Season 3 (Next)

| Block | Priority | Tasks |
|-------|----------|-------|
| 1 | HIGHEST | NaCl crypto_box for MSG delivery. Two SimpleX clients chatting through GoRelay. |
| 2 | HIGH | SimpleGo ESP32 connection test. First hardware client on own server. |
| 3 | MEDIUM | Missing SMP commands: OFF, NKEY, NSUB, GET. Full SMP compliance. |
| 4 | MEDIUM | Stability: debug logging removal, shutdown timeout, systemd, rate limiting, gorelay.dev domain. |

### Season 4: GRP Protocol

| Task | Details |
|------|---------|
| GRP specification | Byte-level wire format, command set, handshake flow. Written BEFORE code. |
| Noise IK/XX | flynn/noise v1.1.0 integration on port 7443 |
| ML-KEM-768 hybrid | X25519 + ML-KEM-768 key exchange, Go stdlib crypto/mlkem |
| GRP commands | Define and implement GRP-specific command set |
| Cross-protocol | GRP message in, SMP delivery out (and vice versa) |

### Season 5: Advanced Security

| Task | Details |
|------|---------|
| Two-hop relay | Server-to-server connections, PFWD/RFWD commands |
| Cover traffic | Poisson-distributed dummy messages, indistinguishable from real |
| Queue rotation | Automatic queue ID rotation every 24-72 hours |
| Server mesh | Multiple GoRelay servers cooperating |

### Season 6: Production Release

| Task | Details |
|------|---------|
| Docker | Distroless image, docker-compose, GitHub Container Registry |
| Documentation | Complete API docs, deployment guides, security audit preparation |
| Load testing | Benchmark concurrent connections, message throughput |
| Community | Public announcement, contributor onboarding |

---

## 10. Technology Stack (LOCKED)

| Component | Choice | Details |
|-----------|--------|---------|
| Language | Go 1.24+ | Single binary, goroutine concurrency, stdlib crypto |
| Transport (SMP) | crypto/tls | TLS 1.2, ChaCha20-Poly1305, Ed25519, X25519 |
| Transport (GRP) | flynn/noise v1.1.0 | Noise Protocol Framework, IK and XX patterns |
| Post-Quantum | crypto/mlkem | FIPS 203, ML-KEM-768 (Phase 4) |
| Persistence | BadgerDB v4 | Embedded KV store, native TTL, LSM-tree |
| Configuration | koanf v2 | Multi-source config, proper key handling |
| Logging | log/slog | Structured logging, stdlib, zero dependencies |
| Metrics | prometheus/client_golang | Standard metrics export (Phase 3) |
| Rate Limiting | golang.org/x/time/rate | Token bucket, per-connection (Phase 3) |

---

## 11. Part of the SimpleGo Ecosystem

GoRelay is the server component. SimpleGo is the hardware client.

| Component | Language | Lines | PQ Algorithm | Status |
|-----------|----------|-------|-------------|--------|
| SimpleGo | C | 21,863 | sntrup761 | Alpha, 7 contacts verified |
| GoRelay | Go | ~5,000 | ML-KEM-768 (planned) | Alpha, SimpleX test passing |

Together they form a complete communication stack from silicon to server, entirely under one codebase's control. No Android, no iOS, no third-party operating system, no app store. From eFuse-burned hardware keys on the ESP32 through five encryption layers to a zero-knowledge relay that cryptographically deletes messages on acknowledgment.

---

*GoRelay, IT and More Systems, Recklinghausen*
*The first SMP-compatible relay server written in Go*
