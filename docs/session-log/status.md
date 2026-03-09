---
title: "Project Status"
sidebar_position: 3
---

# GoRelay Project Status

**Last updated:** 2026-03-09 (Session 001)

## Current Phase: Phase 0 - Research and Planning

### Overall Progress

| Component | Status | Session |
|-----------|--------|---------|
| Research: SMP server analysis | Complete | 001 |
| Research: Go server patterns | Complete | 001 |
| Research: Noise Protocol evaluation | Complete | 001 |
| Research: Post-quantum landscape | Complete | 001 |
| Research: Cover traffic analysis | Complete | 001 |
| Research: Dual-relay routing | Complete | 001 |
| Research: Message retention + legal | Complete | 001 |
| Research: Competitive analysis | Complete | 001 |
| Repository and documentation structure | Complete | 001 |
| GRP protocol specification | Not started | - |
| Go module setup | Not started | - |
| SMP transport layer (Phase 1) | Not started | - |
| SMP handshake | Not started | - |
| Queue store (BadgerDB) | Not started | - |
| Subscription management | Not started | - |
| GRP transport layer (Noise + PQC) | Not started | - |
| Two-hop relay routing | Not started | - |
| Cover traffic | Not started | - |
| Docker deployment | Not started | - |

### Development Phases

**Phase 0: Research and Planning** - Complete
- Comprehensive analysis of existing systems
- Architecture decisions documented
- Technology stack selected
- Documentation structure established

**Phase 1: SMP Skeleton** - Next
- Go project setup with modules
- TLS listener on port 5223 with ALPN "smp/1"
- 16 KB block reader/writer
- SMP handshake (version negotiation, key exchange)
- PING/PONG keep-alive
- Test: SimpleGo device connects and handshakes

**Phase 2: Queue Operations**
- BadgerDB queue store
- NEW, SUB, SEND, MSG, ACK, DEL commands
- Subscription management with takeover semantics
- Test: Full message flow through GoRelay

**Phase 3: Persistence and Production**
- Configuration (YAML via koanf)
- Structured logging (slog)
- Prometheus metrics
- Docker image
- Systemd service
- Rate limiting

**Phase 4: GRP Protocol**
- Noise Protocol transport (flynn/noise)
- Post-quantum key exchange (ML-KEM-768)
- GRP command framing
- Dual-port architecture

**Phase 5: Advanced Security**
- Two-hop relay routing
- Cover traffic generation
- Automatic queue rotation
- Aggressive message retention enforcement

---

*GoRelay - IT and More Systems, Recklinghausen*
