---
title: "Overview"
sidebar_position: 1
---

# GRP Protocol Specification: Overview

*The GoRelay Protocol (GRP) is an encrypted messaging relay protocol designed for post-quantum security, mandatory two-hop routing, and active traffic analysis resistance. This document provides a high-level overview of the protocol architecture.*

**Version:** GRP/1 (Draft)
**Status:** In development
**Date:** 2026-03-09

---

## What is GRP?

GRP (GoRelay Protocol) is a next-generation encrypted relay protocol that builds on the design principles of the SimpleX Messaging Protocol (SMP) while providing strictly stronger security properties. GRP is not a fork of SMP - it is an independent protocol that shares the same queue-based relay architecture but replaces the transport layer, key exchange, and routing mechanisms.

GRP and SMP coexist on the same GoRelay server. Port 5223 speaks SMP for backward compatibility with SimpleX Chat clients. Port 7443 speaks GRP for enhanced security between GRP-capable clients. Both protocols share the same internal queue store - messages are interoperable across protocols.

---

## Design Philosophy

### Security by Default, Not by Option

Every security property in GRP is mandatory. There are no optional features, no configuration flags to disable protection, and no negotiation that could be downgraded. The protocol is designed so that the only way to use it is the secure way.

| Property | SMP | GRP |
|---|---|---|
| Post-quantum key exchange | Optional flag | Mandatory, no fallback |
| Two-hop relay routing | Optional (PMR) | Mandatory default |
| Cover traffic | Not available | Server-generated |
| Queue rotation | Manual | Automatic |
| Cipher negotiation | TLS cipher suites | Fixed suite, no negotiation |
| Identity hiding | SNI visible | Both parties encrypted |

### One Fixed Cipher Suite Per Version

GRP follows WireGuard's approach: each protocol version specifies exactly one cipher suite. There is no negotiation, no version rollback, and no cipher selection. When algorithms need to change, a new protocol version is released.

```
GRP/1 cipher suite (non-negotiable):
  Transport:       Noise Protocol Framework
  Pattern:         IK (primary), XX (fallback)
  Key Exchange:    X25519 + ML-KEM-768 hybrid
  KDF:             HKDF-SHA-256
  AEAD:            ChaCha20-Poly1305
  Hash:            BLAKE2s
  Signatures:      Ed25519
  Block Size:      16,384 bytes (matching SMP)
```

### Zero-Knowledge Relay

The GoRelay server is a dumb pipe. It stores encrypted blobs, delivers them when requested, and deletes them on acknowledgment. The server never decrypts message content, never identifies users, and never logs metadata. The protocol is designed so that a compromised server reveals the minimum possible information.

---

## Protocol Architecture

### Layered Design

GRP operates in four layers:

```
+--------------------------------------------------+
|  Layer 4: Application Messages                    |
|  (end-to-end encrypted by client, opaque to GRP) |
+--------------------------------------------------+
|  Layer 3: Queue Operations                        |
|  (NEW, SUB, SEND, MSG, ACK, DEL, ROTATE)         |
+--------------------------------------------------+
|  Layer 2: Relay Routing                           |
|  (two-hop forwarding, cover traffic injection)    |
+--------------------------------------------------+
|  Layer 1: Transport                               |
|  (Noise IK/XX + X25519 + ML-KEM-768)             |
+--------------------------------------------------+
```

**Layer 1 (Transport)** establishes an authenticated, encrypted channel between the client and the relay server using the Noise Protocol Framework with hybrid post-quantum key exchange. All data above this layer is encrypted and authenticated.

**Layer 2 (Relay Routing)** handles two-hop message forwarding between relay servers. Messages from the sender are wrapped in additional encryption layers so that the forwarding relay cannot read the destination, and the destination relay cannot identify the sender.

**Layer 3 (Queue Operations)** manages the creation, subscription, message delivery, and deletion of unidirectional queues. This layer is functionally similar to SMP's command set with additions for automatic queue rotation.

**Layer 4 (Application Messages)** is the end-to-end encrypted message content produced by the client application (e.g., SimpleGo). GRP treats this as an opaque blob - the relay never inspects or modifies it.

### Connection Model

Like SMP, GRP uses persistent connections between client and server. Each connection spawns three concurrent handlers:

1. **Receiver:** Reads 16 KB blocks from the Noise channel, parses commands
2. **Processor:** Executes commands against the queue store, generates responses
3. **Sender:** Writes responses and message deliveries as 16 KB blocks

The connection remains open for the duration of the client's session. Subscriptions, message deliveries, and keep-alive all flow over the same connection.

### Queue Model

GRP inherits SMP's unidirectional simplex queue model:

- Each queue has exactly one sender and one recipient
- Sender and recipient are identified by separate random 24-byte IDs
- The IDs are uncorrelated - knowing one does not reveal the other
- A full duplex conversation uses two queues (potentially on different servers)
- Only one connection can subscribe to a queue at a time

GRP adds automatic queue rotation: queue IDs are periodically replaced with fresh random values to prevent long-term tracking.

---

## Key Differences from SMP

### Transport

| Aspect | SMP | GRP |
|---|---|---|
| Protocol | TLS 1.3 | Noise Framework |
| Key exchange | X25519 via TLS | X25519 + ML-KEM-768 hybrid |
| Identity model | Certificate fingerprint | Static Curve25519 key |
| Cipher negotiation | TLS cipher suites | Fixed, no negotiation |
| Identity hiding | SNI visible | Both parties encrypted (XX) or initiator encrypted (IK) |
| Handshake size | 1-4 KB | 96-192 bytes (+ PQC overhead) |

### Routing

| Aspect | SMP | GRP |
|---|---|---|
| Default routing | Single-hop (direct) | Two-hop (mandatory) |
| PMR (Private Message Routing) | Optional since v5.8 | Built-in, always active |
| Cover traffic | None | Poisson-distributed dummies |
| Server role | Relay only | Relay + forwarding |

### Queue Management

| Aspect | SMP | GRP |
|---|---|---|
| Queue rotation | Manual (client-initiated) | Automatic (time or message count) |
| Message TTL | Server-configured | 48h default, 7d hard max |
| Deletion | On ACK | On ACK + cryptographic deletion |

### Commands

GRP supports all SMP commands plus additional commands for relay routing and queue rotation:

| Command | SMP | GRP | Purpose |
|---|---|---|---|
| NEW | Yes | Yes | Create queue |
| SUB | Yes | Yes | Subscribe to queue |
| SEND | Yes | Yes | Send message |
| MSG | Yes | Yes | Deliver message |
| ACK | Yes | Yes | Acknowledge delivery |
| DEL | Yes | Yes | Delete queue |
| KEY | Yes | Yes | Set sender key |
| OFF | Yes | Yes | Disable queue |
| GET | Yes | Yes | Poll without subscription |
| PING/PONG | Yes | Yes | Keep-alive |
| PFWD | No | Yes | Push message for forwarding |
| RFWD | No | Yes | Relay forwarded message |
| RRES | No | Yes | Relay response |
| PRES | No | Yes | Return forwarded response |
| QROT | No | Yes | Initiate queue rotation |
| QACK | No | Yes | Acknowledge queue rotation |

---

## Server Identity

In SMP, the server is identified by the fingerprint of its TLS certificate, embedded in the server URI:

```
smp://<certificate-fingerprint>@<host>:<port>
```

In GRP, the server is identified by its static Curve25519 public key, embedded in the server URI:

```
grp://<public-key-base64>@<host>:<port>
```

The public key IS the identity. No certificates, no CA chain, no expiry. The key is generated once during server initialization and remains constant for the server's lifetime. Clients verify the server by checking that the key in the URI matches the key presented during the Noise handshake.

---

## Interoperability with SMP

GRP and SMP share the same queue store on a GoRelay server. This means:

- A message sent via SMP SEND is stored in the same queue and can be delivered to a GRP subscriber
- A message sent via GRP SEND is stored in the same queue and can be delivered to an SMP subscriber
- Queue creation via either protocol produces a queue accessible by both protocols
- Subscriptions follow the same rules regardless of protocol (one subscriber per queue, END on takeover)

The server URI scheme (smp:// vs grp://) tells the client which protocol to use for transport. The queue operations are protocol-agnostic at the storage layer.

This interoperability means a SimpleGo device can communicate with a SimpleX Chat user through the same GoRelay server - the SimpleGo device uses GRP for its connection, the SimpleX app uses SMP, and messages flow between them seamlessly.

---

## Specification Documents

The complete GRP specification consists of the following documents:

| Document | Contents |
|---|---|
| [Overview](01-overview) | This document - protocol architecture and design philosophy |
| [Threat Model](02-threat-model) | Adversary capabilities, trust assumptions, protected properties |
| [Cryptographic Primitives](03-cryptographic-primitives) | All algorithms with selection rationale |
| [Handshake](04-handshake) | Noise handshake with hybrid PQC key exchange |
| [Message Format](05-message-format) | Byte-level frame format, block structure, encoding rules |
| [Queue Operations](06-queue-operations) | Command semantics, state machine, idempotency rules |
| [Relay Routing](07-relay-routing) | Two-hop forwarding specification, encryption layers |
| [Cover Traffic](08-cover-traffic) | Poisson model, dummy generation, bandwidth parameters |
| [SMP Compatibility](09-smp-compatibility) | Interoperability rules, protocol bridging, shared queue store |
| [Test Vectors](10-test-vectors) | Reference values for handshake, encryption, and framing |

---

## Version History

| Version | Date | Changes |
|---|---|---|
| GRP/1 Draft | 2026-03-09 | Initial specification |

---

*GoRelay Protocol Specification - IT and More Systems, Recklinghausen*
*GRP/1 is based on research from GoRelay Session 001.*
