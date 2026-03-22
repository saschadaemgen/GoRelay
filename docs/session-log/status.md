---
title: "Project Status"
sidebar_position: 4
---

# GoRelay Project Status

**Last updated:** 2026-03-22 (Season 002)

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

**Phase 2: Extended Operations** - NEXT
- OFF command (suspend queue)
- NKEY/NSUB (notification support)
- GET command (single message retrieval)
- NaCl crypto_box for MSG delivery (Layer 3)
- Connection timeout handling
- QueueStore cleanup on connection drop

**Phase 3: Production Readiness** - PLANNED
- Docker image and docker-compose.yml
- systemd unit file
- Prometheus metrics endpoint
- Rate limiting (golang.org/x/time/rate)
- Graceful shutdown with timeout
- Debug logging removal

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
- SimpleX Test: PASSED
- Binary: ~15 MB, 608 KB heap idle

---

*GoRelay - IT and More Systems, Recklinghausen*
