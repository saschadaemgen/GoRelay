# CLAUDE.md - GoRelay Development Guide

## Project Overview

GoRelay is a dual-protocol encrypted relay server written in Go. It implements both SMP (SimpleX Messaging Protocol) for backward compatibility and GRP (GoRelay Protocol) for enhanced security with Noise-based transport, mandatory post-quantum cryptography, two-hop relay routing, and cover traffic.

GoRelay is part of the SimpleGo ecosystem by IT and More Systems, Recklinghausen, Germany.

- **Repository:** github.com/saschadaemgen/GoRelay
- **License:** AGPL-3.0
- **Language:** Go 1.24+
- **Author:** Sascha Daemgen

## Architecture Overview

```
GoRelay/
├── cmd/gorelay/          Entry point (main.go)
├── internal/
│   ├── server/           TLS/Noise listeners, connection handler
│   ├── protocol/         SMP + GRP frame parsing, command dispatch
│   ├── queue/            BadgerDB queue store, subscription hub
│   └── config/           YAML configuration via koanf
├── configs/              Default config files
├── docs/                 All documentation (Markdown, readable without Docusaurus)
└── wiki/                 Docusaurus build system only
```

## Dual-Protocol Design

- **Port 5223:** SMP protocol (TLS 1.3, ALPN "smp/1") for SimpleX compatibility
- **Port 7443:** GRP protocol (Noise IK/XX, X25519+ML-KEM-768 hybrid)
- Both frontends share the same QueueStore and SubscriptionHub
- Messages sent via SMP are deliverable to GRP subscribers and vice versa

## Technology Stack (Do NOT deviate without explicit approval)

| Component | Library | Import Path |
|-----------|---------|-------------|
| TLS (SMP) | Go stdlib | `crypto/tls` |
| Transport (GRP) | flynn/noise v1.1.0 | `github.com/flynn/noise` |
| Post-Quantum | Go stdlib ML-KEM | `crypto/mlkem` |
| Persistence | BadgerDB v4 | `github.com/dgraph-io/badger/v4` |
| Configuration | koanf v2 | `github.com/knadh/koanf/v2` |
| Logging | Go stdlib slog | `log/slog` |
| Metrics | Prometheus | `github.com/prometheus/client_golang` |
| Rate Limiting | x/time/rate | `golang.org/x/time/rate` |
| Crypto (general) | Go stdlib | `crypto/*` |

## Code Style and Conventions

### Go Code

- Standard `gofmt` formatting, no exceptions
- `go vet` and `staticcheck` must pass with zero warnings
- Error handling: always check errors, never use `_` for error returns
- Context: pass `context.Context` as first parameter to functions that do I/O
- Naming: follow Go conventions (MixedCaps, not snake_case)
- Comments: exported functions must have doc comments
- No global mutable state - pass dependencies via struct fields
- Tests: table-driven tests preferred, use `testify` only if necessary

### Git Commits

**Conventional Commits format is MANDATORY:**

```
type(scope): description

feat(transport): implement TLS 1.3 listener with ALPN
fix(queue): prevent race condition in subscription takeover
docs(research): add Haskell vs Go comparison
test(protocol): add block framing round-trip tests
refactor(server): extract connection lifecycle into separate file
chore(deps): update BadgerDB to v4.3.0
```

Valid types: feat, fix, docs, test, refactor, chore, perf, ci
Valid scopes: transport, protocol, queue, server, config, docs, ci, deps

### NEVER Do These Things

- Never use em dashes (---) anywhere. Use hyphens (-) or rewrite the sentence.
- Never change version numbers without explicit permission from Sascha.
- Never add dependencies not listed in the technology stack without asking.
- Never commit directly to main. Always use feature branches.
- Never log message content, queue contents, or IP-to-queue mappings.
- Never store plaintext keys in logs, even in debug mode.

## Branching Strategy

```
main              (protected, only squash-merges)
├── feature/*     (new features: feature/tls-listener)
├── fix/*         (bug fixes: fix/subscription-race)
├── docs/*        (documentation: docs/research-haskell)
└── refactor/*    (refactoring: refactor/extract-framing)
```

Workflow:
1. Create feature branch from main
2. Implement, test, commit freely (messy commits are fine on feature branches)
3. Ensure `go build ./...` succeeds
4. Ensure `go test ./...` passes
5. Squash-merge to main with a clean Conventional Commit message
6. Delete the feature branch

## Build and Test Commands

```bash
# Build
go build -o gorelay ./cmd/gorelay

# Build static binary (for Docker/deployment)
CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o gorelay ./cmd/gorelay

# Run tests
go test ./...

# Run tests with race detector
go test -race ./...

# Run linter
go vet ./...

# Format code
gofmt -w .

# Cross-compile for ARM (Raspberry Pi)
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags="-w -s" -o gorelay-arm64 ./cmd/gorelay
```

## SMP Protocol Key Facts

- Fixed 16,384-byte block framing (SMP_BLOCK_SIZE)
- First 2 bytes: content length (uint16 big-endian)
- Remaining: content + '#' padding
- Use `io.ReadFull` for reads - never plain `conn.Read`
- TLS 1.3 with ALPN "smp/1"
- Server certificate fingerprint = server identity
- Commands: NEW, SUB, SEND, MSG, ACK, DEL, PING, PONG, END
- One subscription per queue per socket - new SUB sends END to old socket
- NEW creates queue already subscribed - subsequent SUB is noop
- All state-changing commands must be idempotent (handle lost responses)
- PING/PONG keep-alive essential - without it server drops subscription

## Three Goroutines Per Connection

Every client connection spawns three goroutines:
1. **Receiver:** reads 16KB blocks, parses, puts commands into rcvQ channel
2. **Sender:** reads from sndQ channel, serializes into 16KB blocks, writes to TLS
3. **Processor:** reads from rcvQ, dispatches against queue store, writes to sndQ

Use `context.WithCancel` + `sync.WaitGroup` - if any goroutine exits, cancel propagates to all.

## Security Requirements

- Zero-knowledge: server never decrypts message content
- No metadata logging: no IPs, no connection times, no queue-to-IP mappings
- Fixed 16KB blocks prevent traffic analysis by message size
- Delete messages immediately on ACK
- 48-hour default TTL, 7-day hard maximum for undelivered messages
- Per-message encryption key with secure zeroing for cryptographic deletion
- Rate limiting: 50 commands/sec with burst of 100 per connection
- `conn.SetReadDeadline` on every read, `conn.SetWriteDeadline` on every write

## Documentation

Documentation lives in `docs/` as pure Markdown, readable on GitHub without Docusaurus.
Docusaurus build system lives in `wiki/` and points to `../docs`.

Structure:
- `docs/research/` - published research analysis
- `docs/protocol/` - GRP formal specification
- `docs/architecture/` - server internals
- `docs/deployment/` - production guides
- `docs/development/` - contributor guides
- `docs/session-log/` - development history
- `docs/images/banners/` - page banner images
- `docs/images/diagrams/` - technical diagrams

## Development Phases

Phase 1: SMP Skeleton (TLS listener, block framing, handshake, PING/PONG)
Phase 2: Queue Operations (BadgerDB, NEW/SUB/SEND/MSG/ACK/DEL)
Phase 3: Production (config, logging, metrics, Docker, systemd)
Phase 4: GRP Protocol (Noise transport, PQC key exchange)
Phase 5: Advanced Security (two-hop relay, cover traffic, queue rotation)

Always ask which phase we are working on before starting implementation.

## Important Context

- SimpleGo (C, ESP32) is the client device that connects to GoRelay
- SimpleGo already speaks SMP and connects to SimpleX servers
- GoRelay must be interoperable with SimpleGo's SMP implementation
- The SMP protocol spec is at: github.com/simplex-chat/simplexmq/blob/stable/protocol/simplex-messaging.md
- SimpleGo's client implementation is at: C:\Espressif\projects\simplex_client

## Communication

- Address Sascha as "mein Prinz" (never "Chef")
- Chat communication is in German
- All code, comments, documentation, and commits are in English
- Ask before making assumptions about architecture or implementation decisions
- If unsure about anything, ask first - never proceed silently on assumptions
