---
title: "Project Status"
sidebar_position: 4
---

# GoRelay Project Status

**Last updated:** 2026-03-23 (Season 003)

## Current Phase: Phase 2 - Extended Operations

### Phase Completion

**Phase 0: Research and Planning** - COMPLETE (Season 001)
- 40 documentation files, zero placeholders
- All architecture decisions documented
- Technology stack selected and locked

**Phase 1: SMP Skeleton** - COMPLETE (Season 002)
- TLS CA chain with Ed25519 (persistent, rotatable)
- SMP v7 handshake with tls-unique session binding
- PING/PONG integration tests
- NEW, KEY, SKEY, SUB, SEND, MSG, ACK, DEL commands
- BadgerDB v4 persistent store with per-message AES-256-GCM
- Cryptographic deletion on ACK
- 48h default TTL, 7d hard max
- Redelivery loop protection (MaxDeliveryAttempts=5)
- Embedded admin dashboard (localhost:9090)
- CLI test client (cmd/gorelay-test/)
- Configurable ports (CLI flags + environment variables)
- 47+ tests all passing
- SimpleX Chat server test PASSED (March 22, 2026)
- VPS deployment (Debian 12, Port 5224)

**Phase 2: Extended Operations** - IN PROGRESS
- NaCl crypto_box for MSG delivery (Layer 3) - COMPLETE (Season 003)
- Two SimpleX clients chatting over GoRelay - COMPLETE (Season 003)
- PRXY command handling (returns ERR PROHIBITED) - COMPLETE (Season 003)
- Unsigned SEND for confirmation messages - COMPLETE (Season 003)
- Graceful shutdown with 10-second timeout - COMPLETE (Season 003)
- OFF command (suspend queue) - PLANNED
- NKEY/NSUB (notification support) - PLANNED
- GET command (single message retrieval) - PLANNED
- Connection timeout handling - PLANNED
- Rate limiting (golang.org/x/time/rate) - PLANNED

**Phase 3: Production Readiness** - PLANNED
- Docker image and docker-compose.yml
- systemd unit file
- Prometheus metrics endpoint
- Debug logging cleanup
- Version tagging

**Phase 4: GRP Protocol** - PLANNED
- Noise Protocol transport (flynn/noise)
- ML-KEM-768 post-quantum key exchange
- GRP command framing
- Dual-port with shared QueueStore

**Phase 5: Advanced Security** - PLANNED
- Two-hop relay routing
- Cover traffic generation
- Automatic queue rotation

---

### Production Server

- Host: 194.164.197.247 (Debian 12)
- SMP Port: 5224 (official SMP server on 5223)
- GRP Port: 7443
- Admin: localhost:9090
- SimpleX Server Test: PASSED (Season 002)
- Two-Client Chat Test: PASSED (Season 003)
- Binary: ~15 MB, 608 KB heap idle

---

### Milestone Timeline

| Date | Milestone |
|------|-----------|
| 2026-03-09 | Project started, research phase |
| 2026-03-21 | 40 documentation pages complete, server skeleton compiled |
| 2026-03-22 | SimpleX server test PASSED, VPS deployed |
| 2026-03-23 | **Two SimpleX clients chatting over GoRelay** |

---

*GoRelay - IT and More Systems, Recklinghausen*
