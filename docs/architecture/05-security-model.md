---
title: "Security Model"
sidebar_position: 5
---

# Security Model

*How GoRelay achieves zero-knowledge operation through architectural decisions that make metadata collection structurally impossible rather than policy-dependent.*

**Status:** In development
**Date:** 2026-03-09 (Session 001)

---

## Principle: Security by Construction

GoRelay's security does not depend on the operator's good intentions. The server is architected so that metadata collection is structurally impossible even for a malicious operator who modifies the configuration.

| Property | Policy-based (trust operator) | Construction-based (GoRelay) |
|---|---|---|
| No IP logging | Operator configures logging off | Server has no logging facility for IPs |
| No message reading | Operator promises not to read | Server has no decryption keys |
| No metadata storage | Operator disables metadata logs | Server has no metadata fields to log |
| Message deletion | Operator configures short retention | Messages deleted on ACK + crypto delete + hard TTL cap |

---

## Zero-Knowledge Properties

### The Server Cannot Read Messages

Messages are end-to-end encrypted by the client before they reach the server. The server stores and forwards encrypted blobs. It does not possess the decryption keys and cannot decrypt message content at any point during processing.

Server-side re-encryption adds an additional layer: the server re-encrypts the blob using a DH-derived key with the message ID as nonce. This means the ciphertext entering the server (from the sender) is different from the ciphertext leaving the server (to the recipient). Even if TLS is compromised on both sides, an observer cannot correlate incoming and outgoing messages by comparing ciphertext.

### The Server Cannot Identify Users

GoRelay has no user accounts, no registration, no login, no persistent identifiers. Clients are ephemeral connections that present Ed25519 signatures to prove authorization for specific queues. The server does not know or care who the client is - only that they possess the correct private key.

Queue IDs are random 24-byte values with no semantic content. The sender ID and recipient ID for the same queue are uncorrelated - knowing one reveals nothing about the other.

### The Server Cannot Log IP Addresses

This is enforced architecturally, not by configuration:

```go
func (s *Server) handleConnection(ctx context.Context, conn net.Conn) {
    // IP is extracted ONLY for rate limiting
    // It is stored in a sync.Map with TTL, never written to disk
    ip := conn.RemoteAddr().(*net.TCPAddr).IP.String()
    s.ipLimiter.Touch(ip)

    // From this point on, the IP is never referenced again
    client := s.newClient(conn)
    // client struct has NO IP field
    // ...
}
```

The `Client` struct does not have an IP address field. There is no mechanism to associate a connection with an IP address after the initial rate limiting check. A malicious operator who wants to log IPs would need to modify the source code and recompile - the AGPL-3.0 license ensures that modified versions must be published.

### The Server Cannot Correlate Sender and Recipient

With two-hop routing, Relay A sees the sender's IP but not the destination queue. Relay B sees the destination queue but not the sender's IP. Neither server alone can build a sender-recipient mapping.

Even with single-hop operation, the sender and recipient IDs for the same queue are different and uncorrelated. The server knows that senderID X sent a message to the queue that recipientID Y reads, but without external information, it cannot determine which human is behind either ID.

---

## Defense in Depth

### Layer 1: Transport Encryption

Every connection is encrypted with either TLS 1.3 (SMP) or Noise + hybrid PQC (GRP). No plaintext communication is possible.

### Layer 2: End-to-End Encryption

Message content is encrypted by the client before transmission. The server processes opaque encrypted blobs.

### Layer 3: Server-Side Re-Encryption

The server re-encrypts messages before delivery, preventing ciphertext correlation between sender and recipient sides.

### Layer 4: Per-Message Keys

Each stored message is encrypted with a unique symmetric key. On ACK, the key is securely zeroed and deleted. Even if the encrypted blob persists on disk, it is unreadable.

### Layer 5: Automatic Expiry

Messages have a 48-hour default TTL with a 7-day hard maximum. BadgerDB automatically deletes expired entries. No manual cleanup required.

### Layer 6: Master Key Rotation

The BadgerDB encryption key is rotated every 24 hours. Old keys are securely destroyed. A disk snapshot reveals only data encrypted with the current key.

### Layer 7: Two-Hop Routing

Metadata is split across two independent servers. Neither has the complete picture.

### Layer 8: Cover Traffic

Dummy messages make traffic patterns independent of actual communication activity.

---

## Rate Limiting

Rate limiting protects against denial-of-service without collecting metadata:

### Connection Level

```go
type Client struct {
    limiter *rate.Limiter  // 50 commands/second, burst 100
}
```

When exceeded, the server responds with ERR BLOCKED rather than dropping the connection. This allows well-behaved clients to back off gracefully.

### IP Level

```go
type IPLimiter struct {
    limiters sync.Map     // IP string -> *rateLimiterEntry
    rate     rate.Limit   // 20 connections/minute
}

type rateLimiterEntry struct {
    limiter  *rate.Limiter
    lastSeen time.Time
}
```

IP limiters are stored in memory with a 10-minute TTL. After 10 minutes of inactivity, the entry is evicted. No persistent record of which IPs connected to the server.

### Queue Level

Maximum 100 SEND commands per queue per minute. This prevents a single sender from flooding a recipient's queue.

---

## Cryptographic Key Management

### Key Types

| Key | Scope | Lifetime | Storage |
|---|---|---|---|
| TLS certificate + private key | SMP listener | Months (operator-managed) | Disk (encrypted) |
| Noise static keypair | GRP listener | Server lifetime | Disk (encrypted) |
| ML-KEM-768 keypair | GRP handshakes | 24 hours (rotated) | Memory only |
| Per-queue DH keypair | Server-side re-encryption | Queue lifetime | BadgerDB (encrypted) |
| Per-message symmetric key | Single message | Until ACK | BadgerDB (deleted on ACK) |
| BadgerDB encryption key | All stored data | Derived from master key | Memory only |
| Master storage key | Key encryption key | 24 hours (rotated) | Disk (encrypted with passphrase) |

### Secure Zeroing

All key material is securely zeroed when no longer needed:

```go
func secureZero(b []byte) {
    for i := range b {
        b[i] = 0
    }
    // Compiler fence to prevent optimization
    runtime.KeepAlive(b)
}
```

Go's garbage collector does not zero memory before reuse. Without explicit zeroing, old key material could persist in memory indefinitely. The `runtime.KeepAlive` prevents the compiler from optimizing away the zeroing loop.

---

## Tamper Detection

### Binary Integrity

GoRelay binaries are published with SHA-256 checksums and GPG signatures. Operators can verify that the binary they run matches the published source code.

### Configuration Integrity

The configuration file is checksummed at startup. If the checksum changes while the server is running (indicating modification), the server logs a warning. This detects runtime configuration tampering.

### Store Integrity

BadgerDB includes built-in checksums for all stored data. Corruption (bit flips, partial writes, disk errors) is detected automatically and reported as an error.

---

## What GoRelay Cannot Protect Against

Honest security documentation requires stating limitations:

**Compromised binary.** If an attacker replaces the GoRelay binary with a modified version, all security guarantees are void. Mitigation: binary verification, reproducible builds (planned).

**Compromised operating system.** If the host OS is compromised (rootkit, kernel exploit), the attacker can read memory, intercept system calls, and bypass all application-level security. Mitigation: host hardening, minimal OS (distroless containers).

**Hardware compromise.** Cold boot attacks, DMA attacks, or hardware implants can extract key material from memory. Mitigation: full-disk encryption, hardware security modules (future).

**Traffic analysis by global adversary.** A sufficiently powerful adversary monitoring all network links can perform statistical correlation despite cover traffic. Mitigation: none that is provably effective. Cover traffic raises the cost, not the impossibility.

**Social engineering.** If the operator is tricked into modifying the server or revealing key material, technical controls cannot help. Mitigation: operational security awareness.

---

## Comparison with Self-Hosted SimpleX

| Security Property | Self-Hosted SimpleX SMP | GoRelay |
|---|---|---|
| Message confidentiality | E2E encrypted | E2E encrypted |
| IP logging | Configurable (off by default) | Structurally impossible |
| Metadata logging | Configurable | Structurally impossible |
| Message retention | Configurable TTL | 48h default + 7d hard cap + crypto delete |
| Server re-encryption | Yes | Yes |
| Two-hop routing | Optional (PMR) | Default |
| Cover traffic | No | Yes |
| Post-quantum transport | No | Yes (hybrid PQC) |
| Single binary deploy | Complex (Haskell) | Trivial (Go) |
| Crypto audit | App-level (Trail of Bits) | Stdlib-level (Trail of Bits) + FIPS |

GoRelay provides strictly stronger security properties in every dimension while being simpler to deploy and operate.

---

*GoRelay - IT and More Systems, Recklinghausen*
