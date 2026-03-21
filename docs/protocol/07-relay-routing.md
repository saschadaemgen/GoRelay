---
title: "Relay Routing"
sidebar_position: 7
---

# GRP Protocol Specification: Two-Hop Relay Routing

*Complete specification of GRP's mandatory two-hop message routing, encryption layers, forwarding commands, and server-to-server communication.*

**Version:** GRP/1 (Draft)
**Status:** In development
**Date:** 2026-03-09

---

## Overview

Every GRP message traverses two independent GoRelay servers before reaching its destination. This is not optional - two-hop routing is the default operating mode for all GRP connections.

```
Sender --> [Relay A] --> [Relay B] --> Recipient
           (forwarding)  (destination)
```

**Relay A** sees the sender's IP address and knows which server to forward to, but cannot read the destination queue ID. The destination metadata is encrypted so that only Relay B can decrypt it.

**Relay B** sees the destination queue and delivers the message, but only sees Relay A's IP address as the source. It has no knowledge of the original sender.

---

## Encryption Layers

Two-hop routing uses four encryption layers. Each layer protects specific metadata from specific adversaries:

### Layer 1: End-to-End (e2e)

**Scope:** Sender client to recipient client
**Algorithm:** Double Ratchet (application layer, opaque to GRP)
**Purpose:** Protects message content from everyone including both relay servers

This layer exists regardless of routing - it is the standard end-to-end encryption between communicating parties. GRP treats it as an opaque blob.

### Layer 2: Sender-to-Destination (s2d)

**Scope:** Sender client to Relay B
**Algorithm:** ChaCha20-Poly1305 with per-message ephemeral X25519 key
**Purpose:** Encrypts the destination queue ID and delivery metadata

```
s2d_plaintext:
  destination_queue_id:  24 bytes (sender_id on Relay B)
  notification_flags:    1 byte
  e2e_encrypted_body:    variable (the actual message)

s2d_ephemeral_key = X25519.GenerateKey()
s2d_shared_secret = X25519(s2d_ephemeral_key, relay_b_public_key)
s2d_encryption_key = HKDF-SHA-256(s2d_shared_secret, nil, "GRP/1 s2d")
s2d_ciphertext = ChaCha20-Poly1305.Seal(s2d_encryption_key, nonce, s2d_plaintext)

s2d_message = s2d_ephemeral_public_key || s2d_ciphertext
```

**Per-message ephemeral key:** Every message uses a fresh X25519 keypair for the s2d layer. This means that even if two messages from the same sender go to the same Relay B, the s2d ciphertext looks completely different. An observer at Relay A cannot correlate messages by comparing encrypted payloads.

### Layer 3: Forwarding-to-Destination (f2d)

**Scope:** Relay A to Relay B
**Algorithm:** ChaCha20-Poly1305 derived from the relay-to-relay session key
**Purpose:** Prevents traffic correlation even if TLS between relays is compromised

```
f2d_plaintext:
  s2d_message:  variable (the s2d-encrypted message from Layer 2)
  sender_meta:  relay A's internal metadata (timing, sequence)

f2d_ciphertext = ChaCha20-Poly1305.Seal(relay_session_key, nonce, f2d_plaintext)
```

### Layer 4: Transport (Noise)

**Scope:** Each network hop independently
**Algorithm:** Noise IK/XX with hybrid PQC (as specified in the Handshake document)
**Purpose:** Protects all data in transit on each hop

```
Hop 1: Sender <--> Relay A  (Noise session)
Hop 2: Relay A <--> Relay B (Noise session, persistent)
Hop 3: Relay B <--> Recipient (Noise session)
```

### Layer Summary

| Layer | Encrypted by | Decrypted by | Protects |
|---|---|---|---|
| e2e | Sender client | Recipient client | Message content |
| s2d | Sender client | Relay B | Destination queue ID |
| f2d | Relay A | Relay B | Cross-hop traffic correlation |
| Noise | Each hop sender | Each hop receiver | All data in transit |

An adversary must compromise BOTH relay servers to correlate sender IP with destination queue. Compromising only Relay A reveals sender IPs but not destinations. Compromising only Relay B reveals destinations but not sender IPs.

---

## Forwarding Commands

### PFWD - Push Forward

**Direction:** Client to Relay A
**Purpose:** Client sends a message intended for forwarding to Relay B

```
PFWD:
  relay_b_address:     short_string (hostname:port of destination server)
  s2d_message:         medium_string (s2d-encrypted payload)
```

**Behavior:**
1. Client encrypts the message with the s2d layer (destination queue + e2e body)
2. Client sends PFWD to Relay A with the s2d-encrypted message and Relay B's address
3. Relay A wraps the message in the f2d layer
4. Relay A forwards via RFWD to Relay B

**Relay A cannot read:** The s2d layer encrypts the destination queue ID with Relay B's public key. Relay A sees only the s2d ciphertext and the target server address.

### RFWD - Relay Forward

**Direction:** Relay A to Relay B
**Purpose:** Forward a message between relay servers

```
RFWD:
  f2d_ciphertext:  medium_string (f2d-encrypted payload containing s2d message)
```

**Behavior:**
1. Relay B decrypts the f2d layer using the relay-to-relay session key
2. Relay B decrypts the s2d layer using its own static key
3. Relay B reads the destination queue ID and delivers the message via standard SEND logic
4. Relay B returns the result via RRES

### RRES - Relay Response

**Direction:** Relay B to Relay A
**Purpose:** Return the delivery result to the forwarding relay

```
RRES:
  encrypted_response:  medium_string (f2d-encrypted response)
```

The response (OK, ERR, etc.) is encrypted with the f2d session key so that network observers between the relays cannot determine whether delivery succeeded.

### PRES - Push Response

**Direction:** Relay A to Client
**Purpose:** Return the forwarded delivery result to the sender

```
PRES:
  encrypted_response:  medium_string (response from Relay B, re-encrypted for client)
```

The response is encrypted under the client-Relay A Noise session. The client learns whether the message was delivered successfully without Relay A learning the destination.

---

## Server-to-Server Communication

### Connection Pooling

Relay-to-relay connections are persistent and multiplexed. Establishing a new Noise handshake for every forwarded message would be prohibitively expensive.

GoRelay maintains a connection pool for each peer relay:

```
type RelayPool struct {
    peers    sync.Map       // address -> *PeerConnection
    maxIdle  time.Duration  // 15 minutes
    maxConns int            // 4 connections per peer
}

type PeerConnection struct {
    noiseSession  *noise.CipherState
    conn          net.Conn
    lastUsed      time.Time
    messageCount  uint64
}
```

**Pool behavior:**
- Connections are established on first use and kept alive
- Idle connections are closed after 15 minutes
- Up to 4 concurrent connections per peer (for parallelism)
- Connections are rekeyed after 10,000 messages or 1 hour
- Failed connections are automatically re-established

### Relay Authentication

Relay servers authenticate each other using Noise IK handshakes with pre-shared static keys. A relay's configuration includes the static public keys of all trusted peer relays:

```yaml
relay_peers:
  - address: "relay2.simplego.dev:7443"
    public_key: "base64-encoded-noise-static-key"
  - address: "relay3.example.com:7443"
    public_key: "base64-encoded-noise-static-key"
```

Connections from unknown relays (static key not in the trusted peers list) are rejected. This prevents unauthorized servers from injecting messages into the relay network.

### Zero-Copy Forwarding

When forwarding messages, Relay A does not need to decrypt the s2d payload - it wraps the opaque ciphertext in the f2d layer and forwards it. On Linux, Go's `io.Copy` between TCP connections automatically uses the `splice()` syscall for zero-copy data transfer, reducing CPU overhead for large message volumes.

---

## Relay Selection

### Client-Side Selection

The client decides which server to use as Relay A (forwarding) and which as Relay B (destination). Selection strategies:

**Random per-message:** Each message picks a random forwarding path. Maximizes path diversity but prevents connection reuse.

**Pinned per-conversation:** A conversation uses a fixed forwarding path for its lifetime. Enables connection pooling but creates a longer correlation window.

**Rotated per-session:** The forwarding path changes with each connection session. Balances diversity and efficiency.

**GRP/1 default:** Pinned per-conversation with rotation aligned to queue rotation (every 24-72 hours).

### Server Discovery

The client discovers available relay servers through:

1. **Pre-configured:** Server URIs hardcoded or configured by the user
2. **Peer exchange:** The destination server can suggest forwarding relays in its server info response
3. **SimpleGo network:** The SimpleGo network page lists verified relay servers

---

## Single-Hop Fallback

If only one GoRelay server is available, messages are delivered directly without forwarding:

```
Sender --> [Single Relay] --> Recipient
```

This is equivalent to standard SMP operation. The client SHOULD warn the user that reduced privacy protection is in effect (the single server sees both sender IP and destination queue).

**Fallback detection:** The client attempts to establish a relay-to-relay path. If it fails (second server unreachable, not in trusted peers, connection timeout), the client falls back to single-hop and sets a `reduced_privacy` flag in its local state.

---

## Performance

### Latency Impact

| Deployment | Added Latency | User-Perceived |
|---|---|---|
| Same datacenter | less than 1 ms | Imperceptible |
| Same region (Frankfurt to Amsterdam) | 5-10 ms | Imperceptible |
| Cross-region (Frankfurt to New York) | 40-80 ms | Barely noticeable |
| Cross-continent (Frankfurt to Tokyo) | 120-200 ms | Noticeable but acceptable |

For messaging applications where delivery latency of 1-5 seconds is normal, even cross-continent routing is acceptable.

### Bandwidth

Each message traverses two servers, approximately doubling server bandwidth consumption. At messaging volumes (kilobytes per second, not megabytes), this is negligible relative to typical VPS bandwidth allocations.

### CPU

The f2d encryption/decryption adds one ChaCha20-Poly1305 operation per forwarded message (approximately 5-10 microseconds for a 16 KB block). The s2d encryption requires one X25519 DH per message on the client side (approximately 120 microseconds) and one decapsulation on Relay B.

---

## Threat Analysis

### What Two-Hop Prevents

| Attack | Single-hop | Two-hop |
|---|---|---|
| Server links sender to recipient | Possible | Requires both servers compromised |
| Legal order on one server reveals metadata | Full metadata | Partial (one side only) |
| Network observer at one hop correlates | Possible with timing | Requires observation of both hops |
| Server logs sender IPs with queue IDs | Full correlation | Impossible (different servers) |

### What Two-Hop Does Not Prevent

- **Both servers compromised simultaneously:** Full metadata correlation possible
- **Global network adversary:** Timing correlation across both hops possible (mitigated by cover traffic)
- **Endpoint compromise:** Messages readable on device regardless of routing
- **Denial of service:** Either server can drop messages

---

*GoRelay Protocol Specification - IT and More Systems, Recklinghausen*
