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

The skeleton compiles and runs:
- Dual-port listener works (SMP TLS on :5223, GRP TCP on :7443)
- Three-goroutine-per-connection model implemented
- 16 KB block framing works (ReadBlock/WriteBlock)
- PING/PONG handler returns PONG
- QueueStore interface defined with in-memory implementation
- SubscriptionHub with sync.Map implemented
- Unit tests for block framing pass

## Phase 1 Implementation Plan (Current)

Complete these tasks IN ORDER on separate feature branches:

### Task 1: go mod tidy
- Run `go mod tidy` to generate go.sum
- Branch: chore/go-mod-tidy
- Commit: `chore(deps): generate go.sum with go mod tidy`

### Task 2: TLS with SMP-Compatible CA Chain
- Generate self-signed Ed25519 CA keypair during init
- Sign online TLS cert with CA
- Store CA and cert in data directory, persist across restarts
- CA fingerprint is the server identity - MUST remain stable
- Print SMP URI with CA fingerprint on startup: `smp://<fingerprint>@host:5223`
- Read: docs/deployment/05-tls-certificates.md
- Branch: feature/tls-ca-chain
- Commit: `feat(smp): implement SMP-compatible TLS CA chain`

### Task 3: SMP Version Handshake
- After TLS, server sends version range (min=6, max=7) + server public key
- Client responds with version + client public key + auth
- Agree on highest mutual version
- SMP protocol spec: github.com/simplex-chat/simplexmq/blob/stable/protocol/simplex-messaging.md
- Read: docs/research/01-smp-server-analysis.md (Connection Lifecycle section)
- Branch: feature/smp-handshake
- Commit: `feat(smp): implement version handshake`

### Task 4: PING/PONG Verification
- Verify full round-trip: client PING in 16 KB block, server PONG in 16 KB block
- Proper '#' padding, proper length encoding
- Write test that connects via TLS and exchanges PING/PONG
- Branch: feature/ping-pong-test
- Commit: `test(smp): add PING/PONG integration test`

### Task 5: NEW Command
- Generate random 24-byte recipientID and senderID using crypto/rand
- Generate server DH keypair (X25519) for re-encryption
- Store queue record
- Return IDS response with both IDs and server DH public key
- Implicitly subscribe creating connection
- Must be idempotent
- Read: docs/protocol/06-queue-operations.md
- Branch: feature/queue-new
- Commit: `feat(smp): implement NEW command with queue creation`

### Task 6: SUB Command
- Verify Ed25519 signature against queue's recipientKey
- One-subscriber-per-queue rule: send END to old subscriber on takeover
- If message pending, deliver via MSG immediately
- If no message, respond OK
- Branch: feature/queue-sub
- Commit: `feat(smp): implement SUB command with subscription takeover`

### Task 7: KEY + SEND/MSG/ACK
- KEY: set sender public key (one-time, error on repeat)
- SEND: verify sender signature, store message, deliver if subscriber exists
- MSG: deliver oldest unACKed message, one at a time
- ACK: delete message, deliver next if available
- Branch: feature/message-delivery
- Commit: `feat(smp): implement message delivery cycle (KEY, SEND, MSG, ACK)`

### Task 8: Integration Tests
- Test complete flow: NEW -> KEY -> SEND -> MSG -> ACK
- Test subscription takeover (SUB from second connection, first gets END)
- Test idempotency (retry NEW, retry ACK)
- Test error cases (SEND before KEY, SUB on nonexistent queue)
- Branch: feature/integration-tests
- Commit: `test(smp): add integration tests for complete message flow`

### Task 9: BadgerDB Store
- Implement QueueStore interface with BadgerDB v4
- Key schema per docs/architecture/03-queue-store.md
- Native TTL for message expiry (48h default, 7d hard max)
- Per-message symmetric key for cryptographic deletion
- GC loop every 5 minutes
- Run all existing tests against BadgerDB store
- Branch: feature/badger-store
- Commit: `feat(store): implement BadgerDB queue store with TTL and crypto deletion`

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
3. docs/protocol/05-message-format.md - Byte-level encoding
4. docs/protocol/06-queue-operations.md - Command semantics
5. docs/architecture/01-overview.md - Package structure
6. docs/architecture/03-queue-store.md - BadgerDB schema
