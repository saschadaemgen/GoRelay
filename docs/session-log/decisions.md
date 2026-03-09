---
title: "Architecture Decisions"
sidebar_position: 4
---

# Architecture Decision Log

All significant technical decisions with rationale and alternatives considered. Ordered chronologically.

---

## ADR-001: Server Language - Go

**Date:** 2026-03-09 (Session 001)
**Status:** Accepted

**Decision:** GoRelay is written in Go (1.24+).

**Rationale:** Single binary compilation with zero runtime dependencies. Built-in TLS in standard library. Goroutines for concurrent connection handling. Cross-compilation is trivial. ML-KEM-768 available in stdlib since Go 1.24. Memory-safe by default.

**Alternatives considered:**
- C: Perfect for SimpleGo on ESP32, but manual memory management and buffer overflow risk are unacceptable for a network server
- Haskell: What simplexmq uses, but niche ecosystem, steep learning curve, heavy GHC runtime
- Rust: Overkill for a relay server, longer development time for marginal safety benefit over Go

---

## ADR-002: Dual-Protocol Architecture

**Date:** 2026-03-09 (Session 001)
**Status:** Accepted

**Decision:** GoRelay serves SMP on port 5223 and GRP on port 7443 from a single binary with a shared internal core.

**Rationale:** SMP compatibility ensures SimpleGo devices can communicate with SimpleX app users immediately. GRP provides strictly stronger security for SimpleGo-to-SimpleGo communication. Both frontends share the same QueueStore and SubscriptionHub, so a message sent via SMP is deliverable to a GRP subscriber.

**Alternatives considered:**
- GRP only: Loses SimpleX ecosystem compatibility
- SMP only: No path to improved security properties
- Separate binaries: Doubles operational complexity, harder to share queue state
- ALPN-based selection on single port: Cleaner but harder to debug, considered for Phase 2

---

## ADR-003: GRP Transport - Noise Protocol

**Date:** 2026-03-09 (Session 001)
**Status:** Accepted

**Decision:** GRP uses the Noise Protocol Framework (Noise_IK primary, Noise_XX fallback) instead of TLS.

**Rationale:** SMP already uses certificate fingerprints for server identity - Noise's model (static key IS identity) is a natural fit. No CA dependency, no cipher negotiation (eliminates downgrade attacks), built-in identity hiding, 35-page spec vs TLS 1.3's 160 pages.

**Library:** flynn/noise v1.1.0 (BSD-3, 165 importers)

**Alternatives considered:**
- TLS 1.3: Works but adds unnecessary complexity (CA chain, SNI leakage, negotiation surface)
- QUIC: Interesting for multiplexing but adds UDP complexity and is overkill for persistent relay connections

---

## ADR-004: Mandatory Post-Quantum Cryptography

**Date:** 2026-03-09 (Session 001)
**Status:** Accepted

**Decision:** GRP mandates hybrid X25519 + ML-KEM-768 key exchange with no fallback.

**Rationale:** FIPS 203 finalized August 2024. Go 1.24 stdlib includes FIPS-validated, Trail-of-Bits-audited ML-KEM. "Harvest now, decrypt later" makes PQC at the transport layer immediately relevant. One fixed cipher suite per protocol version - no negotiation, no downgrade.

**Library:** crypto/mlkem (Go stdlib) for primary use. cloudflare/circl as optional AVX2 optimization.

**Alternatives considered:**
- Optional PQC: Defeats the purpose - negotiation reintroduces downgrade risk
- NTRU Prime: Not NIST standardized, smaller ecosystem
- Classic McEliece: Key sizes too large for practical use in handshakes

---

## ADR-005: Persistence Layer - BadgerDB

**Date:** 2026-03-09 (Session 001)
**Status:** Accepted

**Decision:** Message queue persistence uses BadgerDB (pure Go, LSM-tree).

**Rationale:** Native TTL for automatic message expiry. 100x better individual write performance than BBolt. Concurrent writers for multiple sender goroutines. Pure Go (no CGo), clean cross-compilation.

**Key schema:** `q:<queueID>:meta:*` for metadata, `q:<queueID>:msg:<seq>` for messages.

**Alternatives considered:**
- BBolt: Single writer limitation, no native TTL, 100x slower individual writes
- Pebble: Good balance but no native TTL
- SQLite (modernc): No native TTL, single writer, adds SQL complexity for a key-value workload

---

## ADR-006: No Group Messaging

**Date:** 2026-03-09 (Session 001)
**Status:** Accepted

**Decision:** GoRelay supports 1:1 messaging only. No groups, no channels, no broadcast.

**Rationale:** Group messaging forces cryptographic compromises in every existing system. Signal uses Sender Keys (weaker forward secrecy). Matrix uses Megolm (weaker forward secrecy). SimpleX fans out each message individually (bandwidth explosion). By eliminating groups, every message has full Double Ratchet with Perfect Forward Secrecy and Post-Compromise Security.

**Alternatives considered:**
- None. This is a core design principle, not a trade-off.

---

## ADR-007: Two-Hop Relay Routing

**Date:** 2026-03-09 (Session 001)
**Status:** Accepted

**Decision:** GRP mandates two-hop message routing. Server A sees sender IP but not destination. Server B sees destination but not sender IP.

**Rationale:** SimpleX introduced this as optional PMR in v5.8. Research shows two-hop provides equivalent protection to three-hop (Tor-style) against practical timing attacks, with approximately 5-15ms latency addition for same-region servers.

**Alternatives considered:**
- Direct (single-hop): Server sees both sender IP and destination queue
- Three-hop (Tor-style): Marginal benefit over two-hop with 3x latency cost
- Full onion routing: Enormous complexity for messaging context

---

## ADR-008: Aggressive Message Retention

**Date:** 2026-03-09 (Session 001)
**Status:** Accepted

**Decision:** Delete on ACK. 48-hour default TTL. 7-day hard maximum. Zero metadata logging.

**Rationale:** GDPR data minimization (Art. 5(1)(c)), German Vorratsdatenspeicherung suspended since 2017 (CJEU SpaceNet ruling 2022). If metadata is never generated, freeze orders have nothing to preserve. Signal's legal precedent: when subpoenaed, provide account creation date and last connection date only.

---

*GoRelay - IT and More Systems, Recklinghausen*
