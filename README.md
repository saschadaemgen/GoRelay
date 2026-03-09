# GoRelay

**Lightweight, zero-knowledge encrypted relay server for the SimpleGo ecosystem.**

GoRelay is a dual-protocol relay server written in Go that implements both the SimpleX Messaging Protocol (SMP) for backward compatibility and the GoRelay Protocol (GRP) - an enhanced protocol with Noise-based transport, mandatory post-quantum cryptography, two-hop relay routing, and active cover traffic.

GoRelay is part of the SimpleGo platform - an independent encrypted communication and IoT ecosystem built by IT and More Systems, Recklinghausen, Germany.

---

## Why GoRelay?

Existing encrypted relay servers fall into two categories: powerful but complex (SimpleX SMP in Haskell, Signal Server requiring FoundationDB + PostgreSQL + Redis), or simple but metadata-leaky (Matrix Synapse/Dendrite exposing user IDs, room memberships, timestamps). GoRelay occupies the gap between them.

**Zero-knowledge architecture.** The server never decrypts message content, never logs IP addresses, never stores metadata. When served with a court order, there is nothing to provide.

**Dual-protocol design.** Port 5223 speaks SMP for compatibility with SimpleX Chat users. Port 7443 speaks GRP with strictly stronger security properties. Both protocols share the same internal queue store - a message sent via SMP can be received via GRP and vice versa.

**Post-quantum by default.** GRP mandates hybrid X25519 + ML-KEM-768 key exchange. No negotiation, no downgrade, no "enable later" option. Every handshake is quantum-resistant from day one.

**Single binary, zero dependencies.** Compiles to a static binary under 20 MB. Runs on any Linux system, any VPS, any Raspberry Pi. No runtime, no interpreter, no external database.

---

## GRP vs SMP - What's Different?

| Property | SMP (Compatibility) | GRP (Enhanced) |
|----------|--------------------|--------------------|
| Transport | TLS 1.3 | Noise Protocol (IK/XX) |
| Key Exchange | X25519 | X25519 + ML-KEM-768 hybrid |
| Post-Quantum | Not available | Mandatory |
| Identity Hiding | Server name visible (SNI) | Both parties encrypted |
| Cipher Negotiation | TLS cipher suites | Fixed suite, no negotiation |
| Cover Traffic | None | Poisson-distributed dummies |
| Relay Routing | Optional (PMR) | Mandatory two-hop |
| Queue Rotation | Manual | Automatic (24-72h) |
| Message TTL | Server-configured | 48h default, 7d hard max |

When two SimpleGo devices communicate through GRP, they get all security enhancements. When a SimpleGo device communicates with a SimpleX app user, it falls back to SMP - still four encryption layers, still better than anything else on the market.

---

## Architecture

```
                SimpleGo Device          SimpleX App
                     |                       |
                     | GRP (Noise+PQC)       | SMP (TLS 1.3)
                     |                       |
              +------v-----------------------v------+
              |           GoRelay Server            |
              |                                     |
              |  GRP Frontend :7443  SMP Frontend :5223  |
              |       |                   |         |
              |       +-------+-----------+         |
              |               |                     |
              |        QueueStore (BadgerDB)         |
              |        SubscriptionHub (channels)    |
              +-------------------------------------+
```

Three goroutines per connection (receiver, sender, processor). Fixed 16 KB block framing. BadgerDB for persistence with native TTL. Channel-based message routing between subscribers.

---

## Quick Start

```bash
# Build
go build -o gorelay ./cmd/gorelay

# Initialize (generates keys and default config)
./gorelay init

# Start
./gorelay start --config config.yaml
```

---

## Documentation

Full documentation is available at [wiki.gorelay.dev](https://wiki.gorelay.dev) (coming soon), including:

- **Research** - Analysis of existing systems, protocol comparisons, security landscape
- **GRP Protocol Specification** - Formal specification with byte-level formats and test vectors
- **Architecture** - Server internals, connection lifecycle, storage design
- **Deployment** - Docker, systemd, configuration reference
- **Session Log** - Complete development history with technical decisions

---

## Project Status

GoRelay is in early development (Session 1 - March 2026). The research phase is complete. Protocol specification and implementation are in progress.

| Component | Status |
|-----------|--------|
| Research and analysis | Complete |
| GRP protocol specification | In progress |
| Repository and documentation structure | Complete |
| SMP transport layer | Planned (Phase 1) |
| GRP transport layer | Planned (Phase 2) |
| Queue store (BadgerDB) | Planned (Phase 2) |
| Two-hop relay routing | Planned (Phase 4) |
| Cover traffic | Planned (Phase 5) |

---

## Relationship to SimpleGo

- **SimpleGo** (C, ESP32) = the client device - [github.com/saschadaemgen/SimpleGo](https://github.com/saschadaemgen/SimpleGo)
- **GoRelay** (Go, Linux) = the relay server - this repository

Both speak the SMP protocol. GoRelay additionally speaks GRP for enhanced security between SimpleGo devices. Both are AGPL-3.0. Both are by IT and More Systems, Recklinghausen.

---

## Technology Stack

| Component | Choice | Rationale |
|-----------|--------|-----------|
| Language | Go 1.24+ | Single binary, goroutines, stdlib crypto |
| Transport (GRP) | Noise Protocol (flynn/noise) | No CA, no negotiation, identity hiding |
| Transport (SMP) | TLS 1.3 (crypto/tls) | Protocol compatibility |
| Post-Quantum | ML-KEM-768 (crypto/mlkem) | FIPS 203, stdlib, audited |
| Persistence | BadgerDB | Pure Go, native TTL, write-optimized |
| Configuration | koanf | Lightweight, no key lowercasing |
| Logging | log/slog | Stdlib, zero dependencies |
| Metrics | Prometheus client_golang | Industry standard |

---

## License

AGPL-3.0 - see [LICENSE](LICENSE) for details.

---

## Author

**Sascha Daemgen**
IT and More Systems, Recklinghausen, Germany

---

*GoRelay - Zero-knowledge relay infrastructure for the SimpleGo platform.*
