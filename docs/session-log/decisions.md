---
title: "Architecture Decisions"
sidebar_position: 5
---

# Architecture Decision Log

All significant technical decisions with rationale and alternatives considered. Ordered chronologically.

---

## ADR-001: Server Language - Go

**Date:** 2026-03-09 (Season 001)
**Status:** Accepted

**Decision:** GoRelay is written in Go (1.24+).

**Rationale:** Single binary compilation with zero runtime dependencies. Built-in TLS in standard library. Goroutines for concurrent connection handling. Cross-compilation is trivial. ML-KEM-768 available in stdlib since Go 1.24. Memory-safe by default.

**Alternatives considered:**
- C: Manual memory management and buffer overflow risk unacceptable for a network server
- Haskell: Niche ecosystem, steep learning curve, heavy GHC runtime
- Rust: Longer development time for marginal safety benefit over Go

---

## ADR-002: Dual-Protocol Architecture

**Date:** 2026-03-09 (Season 001)
**Status:** Accepted

**Decision:** GoRelay serves SMP on port 5223 and GRP on port 7443 from a single binary with a shared internal core.

**Rationale:** SMP compatibility provides immediate access to existing ecosystem. GRP provides strictly stronger security for dedicated hardware communication. Both frontends share QueueStore and SubscriptionHub.

---

## ADR-003: GRP Transport - Noise Protocol

**Date:** 2026-03-09 (Season 001)
**Status:** Accepted

**Decision:** GRP uses the Noise Protocol Framework (Noise_IK primary, Noise_XX fallback).

**Rationale:** No CA dependency, no cipher negotiation (eliminates downgrade attacks), built-in identity hiding, 35-page spec vs TLS 1.3's 160 pages. Library: flynn/noise v1.1.0.

---

## ADR-004: Mandatory Post-Quantum Cryptography

**Date:** 2026-03-09 (Season 001)
**Status:** Accepted

**Decision:** GRP mandates hybrid X25519 + ML-KEM-768 key exchange with no fallback.

**Rationale:** FIPS 203 finalized August 2024. Go stdlib includes FIPS-validated, audited ML-KEM. One fixed cipher suite per protocol version.

---

## ADR-005: Persistence Layer - BadgerDB

**Date:** 2026-03-09 (Season 001)
**Status:** Accepted

**Decision:** Message queue persistence uses BadgerDB v4 (pure Go, LSM-tree).

**Rationale:** Native TTL for automatic message expiry. 100x better write throughput than BBolt. Concurrent writers. Pure Go, no CGo.

---

## ADR-006: No Group Messaging

**Date:** 2026-03-09 (Season 001)
**Status:** Accepted

**Decision:** GoRelay supports point-to-point messaging only. No groups at the protocol level.

**Rationale:** Group messaging forces cryptographic compromises (shared keys, fan-out metadata). By eliminating groups, every message has full Double Ratchet with Perfect Forward Secrecy. Group-like behavior is handled client-side through individual encrypted channels. The server cannot determine whether multiple queues serve the same conversation.

---

## ADR-007: Two-Hop Relay Routing

**Date:** 2026-03-09 (Season 001)
**Status:** Accepted

**Decision:** GRP mandates two-hop message routing.

**Rationale:** Server A sees sender IP but not destination. Server B sees destination but not sender IP. Two-hop provides equivalent protection to three-hop with lower latency.

---

## ADR-008: Aggressive Message Retention

**Date:** 2026-03-09 (Season 001)
**Status:** Accepted

**Decision:** Delete on ACK. 48-hour default TTL. 7-day hard maximum.

**Rationale:** GDPR data minimization. If metadata is never generated, freeze orders have nothing to preserve.

---

## ADR-009: TLS 1.2 for SMP Transport

**Date:** 2026-03-22 (Season 002)
**Status:** Accepted (workaround)

**Decision:** SMP transport uses TLS 1.2 instead of TLS 1.3.

**Rationale:** Go's crypto/tls does not expose TLS Finished messages for TLS 1.3, which are required for tls-unique channel binding (RFC 5929). The Haskell TLS library provides getPeerFinished for all versions. TLS 1.2 with ChaCha20-Poly1305 + X25519 provides equivalent security. Upgrade when Go adds Finished message API or ExportedKeyingMaterial alternative.

---

## ADR-010: Redelivery Loop Protection

**Date:** 2026-03-22 (Season 002)
**Status:** Accepted

**Decision:** Messages auto-discard after 5 failed delivery attempts (MaxDeliveryAttempts=5).

**Rationale:** Evgeny Poberezkin (SimpleX inventor) described an attack: a crafted message crashes the client before ACK, causing redelivery for the entire TTL period (21 days on official servers). GoRelay limits exposure to 5 attempts. Combined with 48h TTL, a poisoned device recovers in minutes instead of weeks.

---

## ADR-011: CA Fingerprint Calculation

**Date:** 2026-03-22 (Season 002)
**Status:** Accepted (after 3 attempts)

**Decision:** CA fingerprint = base64url_nopad(SHA256(caCertificate.Raw))

**Rationale:** Full DER-encoded certificate including 30 82 header. Confirmed by SimpleGo protocol analysis (Session 8-9) and Haskell reference: getFingerprint uses X.HashSHA256 on complete certificate. NOT the SPKI block, NOT the raw public key.

---

## ADR-012: Block Padding Character

**Date:** 2026-03-22 (Season 002)
**Status:** Accepted

**Decision:** Block padding uses '#' (0x23), not zero bytes.

**Rationale:** The SMP specification defines pad = N*N"#". Zero padding caused SimpleX clients to reject blocks as malformed. Confirmed by capturing raw blocks from the official Haskell SMP server.

---

## ADR-013: Server MSG Encryption - Standard NaCl Secretbox

**Date:** 2026-03-23 (Season 003)
**Status:** Accepted (after 14 iterations)

**Decision:** Layer 3 (server-to-recipient) MSG encryption uses standard NaCl `crypto_box_afternm` equivalent: `HSalsa20(raw_ecdh_key, zeros)` for key derivation, then `secretbox.Seal` for XSalsa20-Poly1305 encryption.

**Rationale:** The Haskell SMP server's `cbEncrypt` function uses `crypto_box_afternm` which is standard NaCl. A custom XSalsa20 variant with non-standard nonce splitting (from Haskell's cryptonite library) was initially implemented based on SimpleGo documentation, but this variant is used only for Layer 2 (client-to-client E2E), not Layer 3 (server-to-recipient). A comparison test confirmed the custom approach produces different ciphertext than standard NaCl. Switching to `golang.org/x/crypto/nacl/secretbox` resolved the issue immediately.

**Alternatives tested:**
- Custom 3-step HSalsa20 with cryptonite nonce splitting (wrong layer)
- Direct secretbox with raw DH key (no beforenm derivation)
- box.Precompute + secretbox (equivalent to chosen approach but uses deprecated API)

---

## ADR-014: DH Key Derivation for MSG Encryption

**Date:** 2026-03-23 (Season 003)
**Status:** Accepted

**Decision:** Store raw X25519 ECDH output as ServerDHSecret, then derive beforenm key with `HSalsa20(raw_ecdh, zeros)` at encryption time.

**Rationale:** The raw ECDH output is the correct input for `crypto_box_beforenm`. Using `box.Precompute` directly on the raw ECDH output would double-apply the HSalsa20 derivation. Confirmed by SimpleGo documentation: "rcvDhSecret = crypto_scalarmult (raw X25519 DH output). NOT crypto_box_beforenm."

---

## ADR-015: MaxRcvMessageLen and Padded Size

**Date:** 2026-03-23 (Season 003)
**Status:** Accepted

**Decision:** MaxRcvMessageLen = 16104 bytes. Padded size = 16106 bytes (2-byte uint16BE length prefix + 16104 content). Encrypted output = 16122 bytes (16-byte Poly1305 MAC + 16106 ciphertext). Padding character is '#' (0x23).

**Rationale:** Confirmed from Haskell Protocol.hs source code and SimpleGo verified hex dumps. The SMP specification's `maxMessageLength = 16064` refers to the maximum sentMsgBody size, not the maximum rcvMsgBody size. The rcvMsgBody adds 8 bytes timestamp + 1 byte flags + 1 byte space = 10 bytes overhead, but MaxRcvMessageLen accounts for additional protocol envelope space.

---

## ADR-016: rcvMsgBody Encoding

**Date:** 2026-03-23 (Season 003)
**Status:** Accepted

**Decision:** rcvMsgBody = timestamp(8 bytes Int64 BE) + sentBody(raw passthrough). The sentBody from the SEND command already contains the flags ASCII character, space separator, and smpEncMessage in the correct format.

**Rationale:** Confirmed by both Haskell source (encodeRcvMsgBody uses smpEncode for timestamp and flags, then appends msgBody directly) and SimpleGo hex dumps showing the exact byte layout. No additional parsing or transformation of sentBody is needed.

---

*GoRelay - IT and More Systems, Recklinghausen*
