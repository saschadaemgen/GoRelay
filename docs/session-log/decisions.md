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

*GoRelay - IT and More Systems, Recklinghausen*
