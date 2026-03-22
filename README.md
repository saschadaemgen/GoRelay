<p align="center">
  <img src="docs/images/banners/banner-gorelay.png" alt="GoRelay" width="1500" height="230">
</p>

<h1 align="center">GoRelay</h1>

<p align="center">
  <strong>The first SMP-compatible relay server written in Go.</strong><br>
  Zero-knowledge by construction, not by policy.
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-AGPL--3.0-blue.svg" alt="License"></a>
  <a href="#technology-stack"><img src="https://img.shields.io/badge/Go-1.24+-00ADD8.svg" alt="Go Version"></a>
  <a href="#simplex-compatibility"><img src="https://img.shields.io/badge/SMP-v7-10B981.svg" alt="SMP Protocol"></a>
  <a href="#simplex-compatibility"><img src="https://img.shields.io/badge/SimpleX-Compatible%20%E2%9C%93-brightgreen.svg" alt="SimpleX Compatible"></a>
  <a href="#status"><img src="https://img.shields.io/badge/version-0.0.1--alpha-orange.svg" alt="Version"></a>
  <a href="https://wiki.gorelay.dev"><img src="https://img.shields.io/badge/docs-wiki.gorelay.dev-blue.svg" alt="Documentation"></a>
</p>

---

GoRelay is an open-source dual-protocol encrypted relay server for anonymous, metadata-resistant messaging infrastructure. It implements the SimpleX Messaging Protocol (SMP) for full compatibility with SimpleX Chat clients, and adds the GoRelay Protocol (GRP) with mandatory post-quantum cryptography, Noise transport, and two-hop relay routing.

GoRelay is part of the SimpleGo ecosystem - dedicated hardware messenger devices running on ESP32 microcontrollers. Together, they form a complete privacy-focused communication stack from silicon to server.

Sensitive data belongs on infrastructure you control, transmitted through channels nobody else can read. Whether that data is a text message between activists, a command to an industrial sensor, or a notification from a medical device.

Built entirely in Go. Compiles to a single binary. Runs on any Linux server. Small enough to audit.

---

## Why GoRelay?

The official SimpleX server is written in Haskell - a powerful language with strong correctness guarantees. GoRelay brings SMP to the Go ecosystem for a different set of priorities:

| | Haskell (simplexmq) | Go (GoRelay) |
|:--|:--|:--|
| **Deployment** | GHC runtime, Cabal dependencies | Single static binary, zero dependencies |
| **Community** | Niche, academic | Large, industry-standard |
| **Concurrency** | Green threads (GHC RTS) | Goroutines (Go runtime) |
| **Extensibility** | SMP only | SMP + GRP dual protocol |
| **Post-Quantum Transport** | Not yet | ML-KEM-768 planned (Phase 4) |

GoRelay is not a replacement for the official SimpleX server. It is an extension of the SimpleX ecosystem that brings SMP compatibility to Go and adds post-quantum transport capabilities.

---

## SimpleX Compatibility

GoRelay passes the official SimpleX Chat server test with a green checkmark.

Verified on March 22, 2026 with SimpleX Desktop. The following SMP v7 commands are fully implemented:

| Command | Direction | Status | Description |
|:--------|:----------|:-------|:------------|
| **NEW** | Client to Server | Working | Create queue with Ed25519 auth key + X25519 DH key |
| **IDS** | Server to Client | Working | Return recipient ID, sender ID, server DH public key |
| **KEY** | Client to Server | Working | Set sender authentication key (recipient command) |
| **SKEY** | Client to Server | Working | Sender-side queue securing (v9+) |
| **SUB** | Client to Server | Working | Subscribe with Ed25519 signature verification + takeover |
| **SEND** | Client to Server | Working | Store message, deliver to subscriber if present |
| **MSG** | Server to Client | Working | Deliver oldest unacknowledged message, one at a time |
| **ACK** | Client to Server | Working | Acknowledge receipt + cryptographic deletion |
| **DEL** | Client to Server | Working | Delete queue and all associated messages |
| **PING** | Client to Server | Working | Keep-alive, server responds with PONG |

---

## Encryption and Security

### Server-Side Security Properties

GoRelay is a zero-knowledge relay. The server stores and forwards encrypted blobs without the ability to read, modify, or correlate message content.

| Property | Implementation | Details |
|:---------|:---------------|:--------|
| **Zero-knowledge** | By construction | Server never has access to plaintext. All message content is end-to-end encrypted by clients. |
| **No IP logging** | Structurally impossible | No logging code exists that captures client addresses. |
| **Per-message encryption** | AES-256-GCM | Each message encrypted with a unique random key in BadgerDB storage. |
| **Cryptographic deletion** | Key destruction on ACK | Message key is zeroed before entry deletion. Data is unrecoverable. |
| **Constant-time auth** | Dummy key verification | Timing attacks cannot reveal whether a queue ID exists. |
| **Fixed block size** | 16,384 bytes | Traffic analysis cannot determine message size. All blocks padded with '#'. |
| **Redelivery protection** | Auto-discard after 5 attempts | Prevents compression bomb + crash loop attacks (48h max instead of 21 days). |
| **TTL enforcement** | 48h default, 7d hard max | Messages expire automatically. No indefinite storage. |

### End-to-End Encryption (Client-Side)

When used with SimpleGo hardware clients, messages pass through five independent cryptographic layers:

| Layer | Algorithm | Protects Against |
|:------|:----------|:-----------------|
| **1a** | X448 Double Ratchet + AES-256-GCM | End-to-end interception. Perfect forward secrecy + post-compromise security. |
| **1b** | sntrup761 KEM (hybrid with 1a) | Quantum computer attacks on key exchange. Active from first message. |
| **2** | NaCl cryptobox (X25519 + XSalsa20 + Poly1305) | Traffic correlation between message queues. |
| **3** | NaCl cryptobox (server-to-recipient) | Correlation of incoming and outgoing server traffic. |
| **4** | TLS 1.2 + ChaCha20-Poly1305 | Network-level attackers. No downgrade possible. |

---

## Features

### Dual Protocol Architecture

```
Port 5223: SMP (SimpleX Messaging Protocol)
+-- TLS 1.2 + ChaCha20-Poly1305 + Ed25519
+-- Full SimpleX Chat client compatibility
+-- SMP v7 with tls-unique session binding

Port 7443: GRP (GoRelay Protocol) [Phase 4]
+-- Noise Protocol Framework (IK primary, XX fallback)
+-- X25519 + ML-KEM-768 hybrid key exchange
+-- Post-quantum resistant transport
+-- Two-hop relay routing for metadata resistance
```

Both protocols share the same QueueStore. Messages are interoperable between SMP and GRP clients.

### Persistent Storage

- **BadgerDB v4** embedded key-value store - no external database required
- **Per-message AES-256-GCM encryption** with random 32-byte keys
- **Cryptographic deletion** on ACK - key zeroed, then entry deleted
- **Native TTL** - 48 hour default, 7 day hard maximum
- **Garbage collection** every 5 minutes
- **Sequence-ordered FIFO** delivery with lexicographic key ordering

### Connection Model

Each SMP connection spawns three goroutines communicating via Go channels:

```
Client --TLS--> [Receiver] --chan--> [Processor] --chan--> [Sender] --TLS--> Client
                                         |
                                   [QueueStore]
                                [SubscriptionHub]
```

- **Receiver** - reads 16 KB blocks via io.ReadFull, parses transmissions
- **Processor** - dispatches commands, manages queue state
- **Sender** - serializes responses, writes 16 KB blocks

### Subscription Management

- One subscriber per queue at any time
- NEW creates implicit subscription
- SUB performs atomic takeover (END sent to displaced subscriber)
- Messages delivered one at a time, ACK required before next delivery

### Admin Dashboard

Embedded web dashboard served on localhost:9090 with live metrics:

- Active connections (SMP/GRP split)
- Queue count, message throughput
- Memory usage, goroutine count
- BadgerDB storage size
- Security event log
- Server configuration display

Access via SSH tunnel only - never exposed to the public internet.

---

## Quick Start

### Build from Source
```bash
git clone https://github.com/saschadaemgen/GoRelay.git
cd GoRelay
go build -o gorelay ./cmd/gorelay
```

### Run
```bash
./gorelay
```

GoRelay generates an Ed25519 CA certificate on first run and prints the SMP URI:

```
smp://<fingerprint>@<host>:5223
```

Add this URI in SimpleX Chat under Settings > Network & Servers > SMP Servers > Add Server.

### Configuration

| Flag | Environment Variable | Default | Description |
|:-----|:---------------------|:--------|:------------|
| `--smp-port` | `GORELAY_SMP_PORT` | 5223 | SMP listener port |
| `--grp-port` | `GORELAY_GRP_PORT` | 7443 | GRP listener port |
| `--host` | `GORELAY_HOST` | localhost | Hostname for SMP URI |
| `--data-dir` | `GORELAY_DATA_DIR` | ./data | Data directory (CA, BadgerDB) |
| `--admin-port` | `GORELAY_ADMIN_PORT` | 9090 | Admin dashboard port |

CLI flags take precedence over environment variables. Environment variables take precedence over defaults.
```bash
# Example: production deployment
./gorelay --smp-port 5223 --host relay.example.com --data-dir /var/lib/gorelay
```

### Cross-Compile for Linux

From Windows or macOS:
```bash
GOOS=linux GOARCH=amd64 go build -o gorelay ./cmd/gorelay
scp gorelay user@server:/opt/gorelay/
```

### Admin Dashboard via SSH Tunnel
```bash
ssh -L 9090:127.0.0.1:9090 user@your-server
# Then open http://localhost:9090 in your browser
```

---

## Test Client

GoRelay includes a CLI test tool for server verification:
```bash
go build -o gorelay-test ./cmd/gorelay-test
```

| Command | Description |
|:--------|:------------|
| `gorelay-test ping --server host:port` | TLS connect + handshake + PING/PONG with latency |
| `gorelay-test create-queue --server host:port` | Create queue, print IDs and DH key |
| `gorelay-test subscribe --server host:port --queue-id ID --key-file keys.json` | Subscribe and wait for messages |
| `gorelay-test send-message --server host:port --queue-id ID --key-file keys.json --message "text"` | Send a message |
| `gorelay-test full-test --server host:port` | Automated full cycle: NEW, KEY, SEND, MSG, ACK |

---

## Architecture

### Package Structure

```
GoRelay/
+-- cmd/
|   +-- gorelay/              Entry point, CLI flags, signal handling
|   +-- gorelay-test/         SMP test client for server verification
|   +-- smp-capture/          Diagnostic tool for protocol analysis
+-- internal/
|   +-- config/               Configuration loading (koanf)
|   +-- server/               Server, Client, SubscriptionHub, Metrics, Admin
|   |   +-- web/              Embedded admin dashboard (index.html)
|   +-- protocol/
|   |   +-- common/           Block framing, transmission format, command types
|   |   +-- smp/              SMP handshake, SPKI encoding
|   |   +-- grp/              GRP protocol handlers (Phase 4)
|   +-- queue/                QueueStore interface + implementations
|   |   +-- store.go          Interface definition + MemoryStore
|   |   +-- badger_store.go   BadgerDB v4 production store
|   +-- relay/                Relay-to-relay forwarding (Phase 5)
+-- docs/
|   +-- images/banners/       Project banners
|   +-- research/             Protocol analysis and design decisions
|   +-- protocol/             Byte-level encoding specifications
|   +-- architecture/         Package structure and data flow
|   +-- deployment/           TLS, systemd, Docker documentation
+-- .claude/                  Claude Code instructions (CLAUDE.md)
```

### Design Rules

- **smp/** and **grp/** packages never import each other - both import **common/**
- **QueueStore** interface for all persistence - MemoryStore for tests, BadgerDB for production
- **io.ReadFull** for all network reads - never plain conn.Read
- **crypto/subtle.ConstantTimeCompare** for all secret comparisons
- **Explicit zeroing** of all key material after use
- **slog** for all logging - never fmt.Println or log.Printf
- **No metadata logging** - never log IPs, queue IDs, message content

---

## Roadmap

- [x] **Phase 0** - Research and planning (40 documentation files)
- [x] **Phase 1** - SMP skeleton (NEW, SUB, KEY, SKEY, SEND, MSG, ACK, DEL, PING/PONG)
- [ ] **Phase 2** - Full queue operations (OFF, NKEY, NSUB, GET, connection timeouts)
- [ ] **Phase 3** - Production (Docker, systemd, Prometheus metrics, rate limiting, graceful shutdown)
- [ ] **Phase 4** - GRP protocol (Noise IK/XX transport, ML-KEM-768 post-quantum, X25519 hybrid)
- [ ] **Phase 5** - Advanced security (two-hop relay routing, cover traffic, queue rotation)

---

## Technology Stack

| Component | Choice | Details |
|:----------|:-------|:--------|
| Language | Go 1.24+ | Single binary compilation, goroutine concurrency |
| Transport (SMP) | crypto/tls | TLS 1.2, ChaCha20-Poly1305, Ed25519, X25519 |
| Transport (GRP) | flynn/noise v1.1.0 | Noise Protocol Framework, IK and XX patterns |
| Post-Quantum | crypto/mlkem | FIPS 203, ML-KEM-768 (Phase 4) |
| Persistence | BadgerDB v4 | Embedded key-value store with native TTL |
| Configuration | koanf v2 | Multi-source configuration |
| Logging | log/slog | Structured logging, stdlib |
| Metrics | prometheus/client_golang | Standard metrics export |
| Rate Limiting | golang.org/x/time/rate | Per-connection throttling |

---

## Part of the SimpleGo Ecosystem

GoRelay works together with SimpleGo - the world's first post-quantum hardware messenger running on ESP32-S3 microcontrollers.

```
SimpleGo (ESP32-S3) --SMP--> GoRelay <--SMP-- SimpleX Chat (Phone/Desktop)
5 encryption layers          [QueueStore]      Full SimpleX compatibility
sntrup761 PQ-KEM             [BadgerDB + AES-GCM]

SimpleGo (ESP32-S3) --GRP--> GoRelay <--GRP-- Other GRP Clients
ML-KEM-768 PQ                [Post-Quantum Transport]  (Phase 4)
```

| Component | Role | Status |
|:----------|:-----|:-------|
| **SimpleGo** | Dedicated hardware client, ESP32-S3, 5 encryption layers, sntrup761 PQ | Alpha, 47 C files, 21,863 lines |
| **GoRelay** | Server infrastructure, SMP + GRP dual protocol | Alpha, SimpleX server test passing |
| **SimpleX Chat** | Full compatibility with existing SimpleX ecosystem | Verified working with GoRelay |

---

## Status

Alpha software under active development. The SMP protocol core is functional and verified against the SimpleX Chat desktop application.

| Component | Status |
|:----------|:-------|
| SMP v7 handshake (TLS 1.2 + session binding) | Working |
| Queue lifecycle (NEW, KEY, SUB, SEND, MSG, ACK, DEL) | Working |
| SKEY sender-side queue securing | Working |
| Subscription takeover (END notification) | Working |
| BadgerDB persistent storage | Working |
| Per-message AES-256-GCM encryption | Working |
| Cryptographic deletion on ACK | Working |
| Redelivery loop protection (MaxDeliveryAttempts=5) | Working |
| Embedded admin dashboard | Working |
| CLI test client | Working |
| SimpleX Chat server test | Passing |
| GRP protocol (Noise + ML-KEM-768) | Phase 4 |
| Two-hop relay routing | Phase 5 |
| Cover traffic | Phase 5 |
| Docker image | Phase 3 |
| Prometheus metrics | Phase 3 |

---

## Contributing

GoRelay is open source under AGPL-3.0. Contributions are welcome.

| Rule | Details |
|:-----|:--------|
| Language | All code, comments, commits, and documentation in English |
| Commits | Conventional Commits only: `feat(scope): description` |
| Branches | Feature branches, squash-merge to main |
| Testing | `go test -race ./...` must pass |
| Logging | Use `log/slog` only, never log metadata |
| Security | Report vulnerabilities via GitHub Security Advisories |

---

## Documentation

| Resource | Link |
|:---------|:-----|
| Full documentation | [wiki.gorelay.dev](https://wiki.gorelay.dev) |
| SMP protocol specification | [simplex-messaging.md](https://github.com/simplex-chat/simplexmq/blob/stable/protocol/simplex-messaging.md) |
| Architecture overview | [docs/architecture/01-overview.md](docs/architecture/01-overview.md) |
| Queue store schema | [docs/architecture/03-queue-store.md](docs/architecture/03-queue-store.md) |
| TLS certificate setup | [docs/deployment/05-tls-certificates.md](docs/deployment/05-tls-certificates.md) |

---

## License

| Component | License |
|:----------|:--------|
| Software | [AGPL-3.0](LICENSE) |

## Acknowledgments

[SimpleX Chat](https://simplex.chat/) by Evgeny Poberezkin - protocol specification and the foundation that makes this project possible. GoRelay builds on the open SMP protocol to extend the SimpleX ecosystem with a Go server implementation.

[Espressif](https://www.espressif.com/) (ESP32 platform for SimpleGo) - [BadgerDB](https://github.com/dgraph-io/badger) (embedded storage) - [flynn/noise](https://github.com/flynn/noise) (Noise Protocol Framework)

---

<p align="center">
  <i>GoRelay is an independent open-source project by IT and More Systems, Recklinghausen, Germany.</i><br>
  <i>GoRelay uses the open-source SimpleX Messaging Protocol (AGPL-3.0) for interoperable message delivery.</i><br>
  <i>It is not affiliated with or endorsed by any third party.</i>
</p>

<p align="center">
  <strong>GoRelay - Secure Dual Relay Infrastructure.</strong><br>
  <strong>Zero-knowledge by construction. Post-quantum by design.</strong>
</p>
