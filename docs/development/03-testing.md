---
title: "Testing"
sidebar_position: 3
---

# Testing Strategy

*How GoRelay is tested - from unit tests to cross-protocol integration tests and fuzz testing.*

**Status:** In development
**Date:** 2026-03-09 (Session 001)

---

## Testing Philosophy

GoRelay's testing strategy follows three rules:

1. **Test the contract, not the implementation.** Tests verify what a function does, not how it does it. Refactoring should not break tests.
2. **Race detector is mandatory.** Every test run uses `go test -race`. A race condition in a security-critical server is a vulnerability.
3. **No mocks for crypto.** Cryptographic operations are never mocked. Tests use real keys, real encryption, real signatures. Mock crypto hides real bugs.

---

## Test Layers

### Unit Tests

Test individual functions and types in isolation:

```go
// internal/protocol/common/block_test.go
func TestWriteBlock_PadsToExactSize(t *testing.T) {
    payload := []byte("Hello, GRP!")
    block := WriteBlock(payload)

    if len(block) != BlockSize {
        t.Fatalf("expected %d bytes, got %d", BlockSize, len(block))
    }
}

func TestWriteBlock_EncodesLengthCorrectly(t *testing.T) {
    payload := make([]byte, 100)
    block := WriteBlock(payload)

    length := binary.BigEndian.Uint16(block[:2])
    if length != 100 {
        t.Fatalf("expected length 100, got %d", length)
    }
}

func TestReadBlock_RejectsInvalidLength(t *testing.T) {
    var block [BlockSize]byte
    binary.BigEndian.PutUint16(block[:2], BlockSize) // exceeds max payload

    _, err := ReadBlock(block)
    if err != ErrInvalidPayloadLength {
        t.Fatalf("expected ErrInvalidPayloadLength, got %v", err)
    }
}
```

**Coverage target:** 80%+ for all packages. 100% for `protocol/common/` (block framing, transmission encoding).

### Integration Tests

Test cross-component interactions using real connections:

```go
// internal/server/integration_test.go
func TestSMPCreateAndSubscribe(t *testing.T) {
    srv := startTestServer(t)
    defer srv.Shutdown()

    // Connect as recipient via SMP
    recipient := dialSMP(t, srv.SMPAddr())
    ids := recipient.SendNEW(testRecipientKey, testDHKey)

    // Connect as sender via SMP
    sender := dialSMP(t, srv.SMPAddr())
    sender.SendKEY(ids.SenderID, testSenderKey)
    sender.SendSEND(ids.SenderID, []byte("test message"))

    // Recipient should receive the message
    msg := recipient.ReceiveMSG()
    if !bytes.Equal(msg.Body, []byte("test message")) {
        t.Fatalf("unexpected message body: %s", msg.Body)
    }

    // ACK and verify deletion
    recipient.SendACK(msg.ID)
}
```

### Cross-Protocol Tests

Verify that SMP and GRP interoperate correctly:

```go
func TestCrossProtocol_SMPSendGRPReceive(t *testing.T) {
    srv := startTestServer(t)

    // Create queue via SMP
    smpClient := dialSMP(t, srv.SMPAddr())
    ids := smpClient.SendNEW(testRecipientKey, testDHKey)

    // Subscribe via GRP
    grpClient := dialGRP(t, srv.GRPAddr())
    grpClient.SendSUB(ids.RecipientID)

    // Send via SMP
    smpSender := dialSMP(t, srv.SMPAddr())
    smpSender.SendKEY(ids.SenderID, testSenderKey)
    smpSender.SendSEND(ids.SenderID, []byte("cross-protocol"))

    // Receive via GRP
    msg := grpClient.ReceiveMSG()
    if !bytes.Equal(msg.Body, []byte("cross-protocol")) {
        t.Fatal("cross-protocol delivery failed")
    }
}

func TestCrossProtocol_SubscriptionTakeover(t *testing.T) {
    srv := startTestServer(t)

    // Create and subscribe via SMP
    smpClient := dialSMP(t, srv.SMPAddr())
    ids := smpClient.SendNEW(testRecipientKey, testDHKey)

    // Subscribe via GRP (should take over)
    grpClient := dialGRP(t, srv.GRPAddr())
    grpClient.SendSUB(ids.RecipientID)

    // SMP client should receive END
    end := smpClient.ReceiveEND()
    if end.EntityID != ids.RecipientID {
        t.Fatal("expected END for the taken-over queue")
    }
}
```

### Handshake Tests

Verify Noise handshake with hybrid PQC:

```go
func TestGRPHandshake_IK(t *testing.T) {
    srv := startTestServer(t)

    // Connect with known server key (IK pattern)
    client := dialGRP(t, srv.GRPAddr(), WithServerKey(srv.NoisePublicKey()))

    // Should be able to send commands after handshake
    client.SendPING()
    pong := client.ReceivePONG()
    if pong == nil {
        t.Fatal("no PONG after IK handshake")
    }
}

func TestGRPHandshake_XX(t *testing.T) {
    srv := startTestServer(t)

    // Connect without server key (XX fallback)
    client := dialGRP(t, srv.GRPAddr())

    // Should complete XX handshake and cache server key
    client.SendPING()
    pong := client.ReceivePONG()
    if pong == nil {
        t.Fatal("no PONG after XX handshake")
    }
}
```

### Queue Store Tests

Test both BadgerDB and in-memory implementations against the same interface:

```go
func TestQueueStore(t *testing.T) {
    implementations := map[string]func(t *testing.T) queue.Store{
        "badger": func(t *testing.T) queue.Store {
            dir := t.TempDir()
            s, _ := queue.NewBadgerStore(dir, queue.DefaultConfig())
            t.Cleanup(func() { s.Close() })
            return s
        },
        "memory": func(t *testing.T) queue.Store {
            return queue.NewMemoryStore()
        },
    }

    for name, newStore := range implementations {
        t.Run(name, func(t *testing.T) {
            t.Run("CreateQueue", testCreateQueue(newStore))
            t.Run("PushAndPop", testPushAndPop(newStore))
            t.Run("AckDeletes", testAckDeletes(newStore))
            t.Run("TTLExpiry", testTTLExpiry(newStore))
            t.Run("Idempotent", testIdempotent(newStore))
        })
    }
}
```

---

## Fuzz Testing

Go's built-in fuzzing (`go test -fuzz`) is used for parser hardening:

```go
func FuzzParseBlock(f *testing.F) {
    // Seed corpus
    f.Add(make([]byte, BlockSize))

    validBlock := WriteBlock([]byte("valid payload"))
    f.Add(validBlock[:])

    f.Fuzz(func(t *testing.T, data []byte) {
        if len(data) != BlockSize {
            return // only fuzz valid-length blocks
        }
        var block [BlockSize]byte
        copy(block[:], data)

        // Must not panic, regardless of input
        _, _ = ReadBlock(block)
    })
}

func FuzzParseTransmission(f *testing.F) {
    f.Fuzz(func(t *testing.T, data []byte) {
        // Must not panic on any input
        _, _ = ParseTransmission(data)
    })
}
```

Fuzz targets: block parser, transmission parser, command parser, signature verifier. The goal is to ensure that no malformed input can crash the server.

---

## Benchmarks

Performance-critical paths have benchmarks:

```go
func BenchmarkWriteBlock(b *testing.B) {
    payload := make([]byte, 1000)
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        WriteBlock(payload)
    }
}

func BenchmarkReadBlock(b *testing.B) {
    block := WriteBlock(make([]byte, 1000))
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        ReadBlock(block)
    }
}

func BenchmarkNoiseHandshake(b *testing.B) {
    serverKey := generateTestKey()
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        performHandshake(serverKey)
    }
}

func BenchmarkHybridKeyExchange(b *testing.B) {
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        performHybridKeyExchange()
    }
}
```

Run benchmarks:

```bash
go test -bench=. -benchmem ./...
```

---

## Test Infrastructure

### Test Server Helper

```go
func startTestServer(t *testing.T) *Server {
    t.Helper()
    cfg := config.TestConfig()
    cfg.Store.Path = t.TempDir()
    cfg.SMP.Address = "127.0.0.1:0"  // random port
    cfg.GRP.Address = "127.0.0.1:0"  // random port

    srv, err := NewServer(cfg)
    if err != nil {
        t.Fatal(err)
    }

    go srv.Start(context.Background())
    t.Cleanup(func() { srv.Shutdown(context.Background()) })

    // Wait for listeners to be ready
    srv.WaitReady()
    return srv
}
```

### Test Key Material

```go
// internal/protocol/testkeys.go (build tag: //go:build testing)
var (
    TestRecipientKey = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0xD0}, 32))
    TestSenderKey    = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0xE0}, 32))
    TestDHKey, _     = ecdh.X25519().GenerateKey(deterministicReader(0xAA))
)
```

Test keys are deterministic for reproducibility. They are in a file with a build tag that excludes them from production builds.

---

## CI Pipeline

Every push and pull request triggers:

```yaml
# .github/workflows/test.yml
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.24'
      - run: go test -race -count=1 ./...
      - run: go test -fuzz=FuzzParseBlock -fuzztime=30s ./internal/protocol/common/
      - run: golangci-lint run ./...
      - run: go build -o /dev/null ./cmd/gorelay
```

**All tests must pass before merging.** No exceptions, no "fix it later" merges.

---

## Running Tests

```bash
# All tests with race detector
go test -race ./...

# Specific package
go test -race ./internal/queue/...

# Specific test
go test -race -run TestCrossProtocol ./internal/server/...

# With coverage report
go test -race -coverprofile=coverage.out ./...
go tool cover -html=coverage.out

# Benchmarks
go test -bench=. -benchmem ./internal/protocol/common/

# Fuzz testing (run for 5 minutes)
go test -fuzz=FuzzParseBlock -fuzztime=5m ./internal/protocol/common/
```

---

*GoRelay - IT and More Systems, Recklinghausen*
