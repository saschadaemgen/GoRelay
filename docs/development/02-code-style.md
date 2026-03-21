---
title: "Code Style"
sidebar_position: 2
---

# Code Style and Conventions

*GoRelay's coding standards - enforced by linters, not by memory.*

**Status:** In development
**Date:** 2026-03-09 (Session 001)

---

## General Principles

1. **Clarity over cleverness.** Code is read 10x more than it is written. Boring, obvious code is better than elegant, obscure code.
2. **Explicit over implicit.** If err != nil, handle it. If a function can fail, it returns an error. No panics in library code.
3. **Standard library first.** Use Go's standard library unless there is a compelling, documented reason for an external dependency.
4. **Security by default.** Every buffer is bounds-checked. Every key is zeroed after use. Every input is validated.

---

## Go Style

### Formatting

All code is formatted with `gofmt`. No exceptions. IDEs should be configured to format on save.

### Naming

Follow standard Go naming conventions:

```go
// Exported types: PascalCase
type QueueStore interface { ... }
type Client struct { ... }

// Unexported types: camelCase
type rateLimiterEntry struct { ... }

// Constants: PascalCase for exported, camelCase for unexported
const BlockSize = 16384
const maxRetries = 3

// Acronyms: keep case consistent
type SMPParser struct { ... }    // not SmpParser
type GRPHandler struct { ... }   // not GrpHandler
var httpClient *http.Client      // not HTTPClient (lowercase)
```

### Error Handling

Always handle errors explicitly. Never use `_` to discard errors in production code:

```go
// Good
data, err := store.GetQueue(id)
if err != nil {
    return fmt.Errorf("get queue %x: %w", id, err)
}

// Bad - never do this
data, _ := store.GetQueue(id)
```

Wrap errors with context using `fmt.Errorf` and `%w`:

```go
if err := s.queueStore.PushMessage(senderID, flags, body); err != nil {
    return fmt.Errorf("push message to queue %x: %w", senderID, err)
}
```

### Logging

Use `log/slog` for all logging:

```go
slog.Info("client connected", "protocol", proto, "connections", count)
slog.Error("store operation failed", "err", err, "operation", "push")
slog.Debug("block parsed", "payload_len", payloadLen, "batch_count", batchCount)
```

**Never log:** IP addresses, queue IDs, message content, message IDs, sender/recipient keys, or any data that could identify users or communications.

### Comments

```go
// Package-level comments explain the package purpose.
// Every exported type and function has a comment.

// QueueStore defines the interface for persistent queue storage.
// Implementations must be safe for concurrent use.
type QueueStore interface {
    // CreateQueue generates a new queue with random IDs.
    // Returns ErrDuplicateID if the generated ID already exists (retry).
    CreateQueue(recipientKey ed25519.PublicKey, dhKey *ecdh.PublicKey) (*Queue, error)
}

// Inline comments explain WHY, not WHAT.
// The code shows what happens. The comment explains why it happens.

// Zero the key material before deletion to prevent recovery from disk.
// Go's GC does not zero memory, so explicit zeroing is required.
secureZero(msgKey)
```

---

## Security Conventions

### Key Material

```go
// Always zero keys after use
defer secureZero(privateKey)

// Use fixed-size arrays for keys, not slices
type NoiseStaticKey [32]byte

// Never log key material
slog.Info("key generated")  // Good
slog.Info("key generated", "key", hex.EncodeToString(key))  // NEVER
```

### Input Validation

```go
// Validate ALL inputs at the boundary
func parseBlock(block [BlockSize]byte) ([]byte, error) {
    payloadLen := binary.BigEndian.Uint16(block[:2])
    if payloadLen > BlockSize-2 {
        return nil, ErrInvalidPayloadLength
    }
    // ...
}

// Use fixed-size types where possible
type QueueID [24]byte  // not []byte
type MessageID [24]byte
```

### Constant-Time Operations

```go
// Use crypto/subtle for security-sensitive comparisons
import "crypto/subtle"

if subtle.ConstantTimeCompare(provided, expected) != 1 {
    return ErrAuthFailed
}

// Never use == for comparing secrets
if provided == expected {  // TIMING SIDE CHANNEL - never do this
```

---

## Project Structure Conventions

### File Organization

```
// One file per logical concept
client.go          // Client struct and methods
client_test.go     // Tests for client.go

// Group related types in the same file
commands.go        // All command handler functions
commands_test.go   // Tests for all command handlers

// Keep files under 500 lines
// If a file exceeds 500 lines, split it by logical concern
```

### Test Files

```
// Test files live next to the code they test
internal/queue/
    store.go
    store_test.go
    badger.go
    badger_test.go
    memory.go
    memory_test.go
```

### Interface Definitions

```go
// Interfaces live in the package that USES them, not the package that implements them.
// This follows Go's implicit interface pattern.

// internal/server/server.go
type QueueStore interface { ... }  // defined where it's used

// internal/queue/badger.go
type BadgerStore struct { ... }    // implements QueueStore implicitly
```

---

## Dependencies

### Approved Dependencies

| Package | Purpose | License |
|---|---|---|
| github.com/dgraph-io/badger/v4 | Embedded key-value store | Apache 2.0 |
| github.com/flynn/noise | Noise Protocol Framework | BSD-3 |
| github.com/knadh/koanf/v2 | Configuration loading | MIT |
| github.com/prometheus/client_golang | Metrics | Apache 2.0 |
| golang.org/x/time/rate | Rate limiting | BSD-3 |
| golang.org/x/crypto | Extended crypto (chacha20poly1305) | BSD-3 |

### Adding Dependencies

New dependencies require explicit justification:

1. Why can't this be done with the standard library?
2. What is the dependency's license?
3. How many transitive dependencies does it bring?
4. Is it actively maintained?
5. Has it been audited?

File a GitHub issue for discussion before adding any dependency.

---

## Linting

GoRelay uses `golangci-lint` with the following linters enabled:

```yaml
# .golangci.yml
linters:
  enable:
    - errcheck       # unchecked errors
    - govet          # suspicious constructs
    - staticcheck    # advanced static analysis
    - unused         # unused code
    - gosec          # security issues
    - bodyclose      # unclosed HTTP response bodies
    - noctx          # HTTP requests without context
    - gosimple       # simplification suggestions
    - ineffassign    # ineffective assignments
```

Run before every commit:

```bash
golangci-lint run ./...
```

---

*GoRelay - IT and More Systems, Recklinghausen*
