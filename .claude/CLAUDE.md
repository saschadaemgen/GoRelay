# GoRelay - Claude Code Instructions

## Project

GoRelay is a dual-protocol encrypted relay server written in Go.
- Port 5223: SMP (SimpleX Messaging Protocol) for SimpleX Chat compatibility
- Port 7443: GRP (GoRelay Protocol) with Noise transport, mandatory post-quantum crypto, two-hop relay routing
- Both protocols share the same internal queue store
- Repository: github.com/saschadaemgen/GoRelay
- License: AGPL-3.0
- Author: Sascha Daemgen, IT and More Systems, Recklinghausen

## Rules (NON-NEGOTIABLE)

### Git
- Conventional Commits ONLY: `feat(scope): description`, `fix(scope): description`
- Valid types: feat, fix, docs, test, refactor, ci, chore
- Valid scopes: core, smp, grp, store, relay, config, ci, wiki
- NEVER commit directly to main - always feature/* branches
- Squash-merge feature branches to main
- NEVER change version numbers without explicit permission

### Code Style
- NEVER use em dashes - use regular hyphens or rewrite the sentence
- All code, comments, commits, and documentation in English
- Use `log/slog` for logging - NEVER `fmt.Println` or `log.Printf`
- NEVER log IP addresses, queue IDs, message content, or any user metadata
- Use `io.ReadFull` for all network reads - NEVER plain `conn.Read`
- Handle all errors explicitly - NEVER use `_` to discard errors
- Use `crypto/subtle.ConstantTimeCompare` for all secret comparisons
- Zero all key material after use with explicit zeroing loops

### Architecture
- Three goroutines per connection: receiver, processor, sender
- Fixed 16,384-byte blocks for ALL wire communication
- QueueStore interface for all persistence (BadgerDB in production, memory for tests)
- SubscriptionHub with sync.Map for queue-to-client routing
- smp/ and grp/ packages NEVER import each other - both import common/

## Build and Test

```bash
go build -o gorelay ./cmd/gorelay
go test -race ./...
```

## Technology Stack (LOCKED)

| Component | Choice |
|---|---|
| Language | Go 1.26+ |
| Transport (SMP) | crypto/tls (stdlib) |
| Transport (GRP) | flynn/noise v1.1.0 |
| Post-Quantum | crypto/mlkem (stdlib, FIPS 203) |
| Persistence | BadgerDB v4 |
| Configuration | koanf v2 |
| Logging | log/slog (stdlib) |
| Metrics | prometheus/client_golang |
| Rate Limiting | golang.org/x/time/rate |

## Package Structure

```
cmd/gorelay/                    Entry point, CLI, signal handling
internal/config/                Configuration loading (koanf)
internal/server/                Server, Client, SubscriptionHub
internal/protocol/common/       Block framing, command types (shared)
internal/protocol/smp/          SMP-specific handlers
internal/protocol/grp/          GRP-specific handlers
internal/queue/                 QueueStore interface + implementations
internal/relay/                 Relay-to-relay forwarding (Phase 5)
```

## Current State

Phase 1 is COMPLETE. The server compiles, runs, and passes 40+ tests:
- Dual-port listener works (SMP TLS on :5223, GRP TCP on :7443)
- Three-goroutine-per-connection model implemented
- 16 KB block framing works (ReadBlock/WriteBlock)
- SMP-compatible TLS CA chain with Ed25519 (persistent CA, rotatable online cert)
- SMP URI with CA fingerprint printed on startup
- SMP version handshake (min=6, max=7) with X25519 DH key exchange
- PING/PONG integration tests verify full TLS round-trip
- NEW command creates queues with random 24-byte IDs, idempotent
- SUB command with Ed25519 signature verification and subscription takeover
- KEY command sets one-time sender key
- SEND command verifies sender signature, stores and delivers messages
- MSG delivery one-at-a-time with ACK before next
- ACK with cryptographic deletion, triggers next message delivery
- DeliveryAttempts counter with MaxDeliveryAttempts=5 (redelivery loop protection)
- BadgerDB v4 persistent store with per-message AES-256-GCM encryption
- Native TTL (48h default, 7d hard max) with GC every 5 minutes
- QueueStore interface with both MemoryStore (tests) and BadgerStore (production)
- 40+ tests passing including 13 integration tests

## Development Roadmap

- Phase 0: Research and Planning - COMPLETE
- Phase 1: SMP Skeleton (TLS, Block Framing, Handshake, Queue Ops, BadgerDB) - COMPLETE
- Phase 2: Production Hardening (DEL, OFF, Timeouts, Metrics, Rate Limiting, Docker) - CURRENT
- Phase 3: SMP Compatibility Testing (verify against official SimpleX Chat app)
- Phase 4: GRP Protocol (Noise transport, hybrid PQC key exchange)
- Phase 5: Advanced Security (two-hop relay routing, cover traffic, queue rotation)
- Phase 6: Triple Shield
  - 6a: Zero-Knowledge Proofs for queue authentication (Schnorr DLOG via Fiat-Shamir)
  - 6b: Shamir's Secret Sharing across multiple servers (2-of-3 default)
  - 6c: Steganographic Transport (pluggable transports: HTTPS, WebSocket, meek, obfs4)
  - Read: docs/research/12-triple-shield.md

## Phase 1 Implementation Plan (COMPLETE)

All 9 tasks completed on separate feature branches, squash-merged to main:

### Task 1: go mod tidy - COMPLETE
### Task 2: TLS with SMP-Compatible CA Chain - COMPLETE
### Task 3: SMP Version Handshake - COMPLETE
### Task 4: PING/PONG Verification - COMPLETE
### Task 5: NEW Command - COMPLETE
### Task 6: SUB Command - COMPLETE
### Task 7: KEY + SEND/MSG/ACK - COMPLETE
### Task 8: Integration Tests - COMPLETE
### Task 9: BadgerDB Store - COMPLETE

## Phase 2 Implementation Plan (Current)

### Task 1: DEL Command
- Delete queue by recipientID with Ed25519 signature verification
- Remove all messages, sender mapping, and recipient key index
- Idempotent (DEL on deleted queue returns OK)
- Branch: feature/queue-del

### Task 2: OFF Command
- Turn off notifications for a queue
- Unsubscribe the connection without deleting the queue
- Branch: feature/queue-off

### Task 3: QueueStore Cleanup on Connection Drop
- Unsubscribe all queues when a connection drops
- Ensure no leaked subscriptions in SubscriptionHub
- Branch: feature/connection-cleanup

### Task 4: Connection Timeout Handling
- Enforce read/write deadlines from config (ReadTimeout, WriteTimeout)
- Handshake timeout for SMP version negotiation
- Idle connection reaping
- Branch: feature/connection-timeouts

### Task 5: Prometheus Metrics Endpoint
- Expose metrics on :9100 using prometheus/client_golang
- Counters: connections, commands processed, messages sent/received, errors
- Gauges: active connections, active subscriptions, queue count
- Histograms: command latency, message size
- Branch: feature/prometheus-metrics

### Task 6: Rate Limiting
- Per-connection rate limiting with golang.org/x/time/rate
- Configurable via LimitsConfig (CommandsPerSecond, CommandsBurst)
- Return ERR with appropriate error code when rate exceeded
- Branch: feature/rate-limiting

### Task 7: Graceful Shutdown
- Drain in-flight messages before closing connections
- Wait for active transactions to complete
- Close BadgerDB cleanly
- Signal handling (SIGTERM, SIGINT)
- Branch: feature/graceful-shutdown

### Task 8: Admin Dashboard
- Embedded web UI via go:embed on :9090
- Server status, connection count, queue stats
- No sensitive data exposed (no queue IDs, no message content)
- Branch: feature/admin-dashboard

### Task 9: Dockerfile and docker-compose.yml
- Multi-stage Dockerfile (build + minimal runtime image)
- docker-compose.yml with volume for data directory
- Health check endpoint
- Branch: feature/docker

### Task 10: systemd Unit File
- systemd service file for Linux deployment
- Proper user/group, data directory permissions
- Restart on failure with backoff
- Branch: feature/systemd

## Critical Protocol Details

### Block Framing
```
Block = payloadLength (2 bytes, uint16 BE) + payload + padding ('#' to 16384)
ALWAYS exactly 16,384 bytes. No exceptions.
ALWAYS io.ReadFull. NEVER conn.Read.
```

### SMP Version Negotiation
```
Current SMP versions: 6 and 7 (older versions discontinued)
Server sends: min=6, max=7
Client responds with its version range
Agree on highest mutual version
Source: github.com/simplex-chat/simplexmq/blob/stable/protocol/simplex-messaging.md
```

### Subscription Rules
- Only ONE connection per queue at any time
- NEW creates implicit subscription
- New SUB sends END to old subscriber
- Messages delivered one at a time, wait for ACK

### Idempotency
- NEW with same key: return existing IDS
- ACK for deleted message: return OK
- DEL for deleted queue: return OK
- SEND: deduplicate by correlationID within 5-minute window

## Documentation

Read these files for implementation details:
1. docs/research/01-smp-server-analysis.md - How SMP works
2. docs/research/02-go-server-architecture.md - Go patterns
3. docs/research/12-triple-shield.md - Phase 6 Triple Shield architecture
4. docs/protocol/05-message-format.md - Byte-level encoding
5. docs/protocol/06-queue-operations.md - Command semantics
6. docs/architecture/01-overview.md - Package structure
7. docs/architecture/03-queue-store.md - BadgerDB schema
