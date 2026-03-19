---
title: "Go Server Architecture Patterns"
sidebar_position: 2
---

# Go Server Architecture Patterns

*How to build a production-grade custom protocol server in Go, with patterns drawn from NATS, WireGuard, Tailscale, and CockroachDB.*

**Research date:** 2026-03-09 (Session 001)

---

## Why Go for a Relay Server

Go was designed at Google specifically for building network servers. The language's core strengths align precisely with what a messaging relay needs: goroutines for massive concurrency without manual thread management, a built-in TLS implementation in the standard library, trivial cross-compilation to any platform, and a single static binary with zero runtime dependencies.

The Go ecosystem dominates security infrastructure: WireGuard's userspace implementation (wireguard-go), Tailscale (achieving 10 Gbps throughput), HashiCorp Vault, age encryption, Docker, Kubernetes, Prometheus, and etcd are all Go. If Go is secure enough for WireGuard, it is secure enough for GoRelay.

---

## Goroutine-Per-Connection Model

### How It Works

Go's standard approach for TCP servers is to spawn a goroutine for each incoming connection. This is not a hack or a workaround - it is the intended design pattern:

```go
for {
    conn, err := listener.Accept()
    if err != nil {
        continue
    }
    go handleConnection(ctx, conn)
}
```

Each goroutine is a lightweight green thread managed by Go's runtime scheduler. When a goroutine calls `conn.Read()` and the data is not yet available, the runtime parks the goroutine (consuming almost no resources) and schedules another one. Under the hood, Go uses epoll on Linux and kqueue on macOS/BSD - the same non-blocking I/O primitives that power nginx and Node.js, but exposed through a synchronous, blocking API that is dramatically easier to reason about.

### Memory Characteristics

Each goroutine starts with approximately 2 KB of stack space that grows dynamically as needed (up to a configurable maximum, default 1 GB). In practice, a relay server goroutine handling 16 KB message blocks will stabilize around 8-16 KB of stack.

For GoRelay with three goroutines per connection (reader, writer, processor):

| Concurrent Clients | Goroutines | Approximate Stack Memory |
|---|---|---|
| 100 | 300 | ~5 MB |
| 1,000 | 3,000 | ~48 MB |
| 10,000 | 30,000 | ~480 MB |
| 100,000 | 300,000 | ~4.8 GB |

The practical limit is file descriptors (`ulimit -n`), not goroutines. The `smallnest/1m-go-tcp-server` project demonstrated 1 million concurrent connections with Go's standard `net` package on a single machine.

### Why NOT Use io_uring or Raw epoll

Some Go projects bypass the runtime's network poller for extreme performance (gnet, nbio). This is unnecessary for GoRelay because:

- SMP messages are 16 KB blocks at human typing speed, not microsecond-latency financial data
- The goroutine-per-connection model is simpler to debug, profile, and maintain
- Go's built-in poller already uses epoll/kqueue - we get non-blocking I/O for free
- Raw epoll breaks Go's garbage collector integration and tooling (pprof, race detector)

---

## Three Goroutines Per Connection

### The Pattern

This pattern mirrors the Haskell server's three-thread model and is used by NATS, CockroachDB's RPC layer, and many production Go servers:

```go
func (s *Server) runClient(ctx context.Context, conn *tls.Conn) {
    client := s.newClient(conn)
    defer s.clientDisconnected(client)

    ctx, cancel := context.WithCancel(ctx)
    defer cancel()

    var wg sync.WaitGroup
    wg.Add(3)

    go func() { defer wg.Done(); defer cancel(); s.receiver(ctx, client) }()
    go func() { defer wg.Done(); defer cancel(); s.sender(ctx, client) }()
    go func() { defer wg.Done(); defer cancel(); s.processor(ctx, client) }()

    wg.Wait()
}
```

The key insight is `defer cancel()` in each goroutine. If any goroutine exits (error, connection closed, context cancelled), the context cancellation propagates to all three, ensuring clean shutdown without orphaned goroutines.

### Receiver Goroutine

Reads exactly 16,384 bytes per iteration using `io.ReadFull`, parses the block into one or more transmissions, verifies signatures, and sends parsed commands into the `rcvQ` channel:

```go
func (s *Server) receiver(ctx context.Context, c *Client) {
    var buf [16384]byte
    for {
        select {
        case <-ctx.Done():
            return
        default:
        }
        c.conn.SetReadDeadline(time.Now().Add(5 * time.Minute))
        _, err := io.ReadFull(c.conn, buf[:])
        if err != nil {
            return
        }
        cmds, err := parseBlock(buf[:])
        if err != nil {
            continue
        }
        for _, cmd := range cmds {
            c.rcvQ <- cmd
        }
    }
}
```

**Critical:** Always use `io.ReadFull`, never plain `conn.Read()`. TCP can deliver partial data - `conn.Read()` might return 8,192 bytes of a 16,384-byte block, silently corrupting the frame boundary. `io.ReadFull` blocks until exactly the requested number of bytes arrive or an error occurs.

### Processor Goroutine

Reads commands from `rcvQ`, executes them against the queue store, and writes responses to `sndQ`:

```go
func (s *Server) processor(ctx context.Context, c *Client) {
    for {
        select {
        case <-ctx.Done():
            return
        case cmd := <-c.rcvQ:
            resp := s.dispatch(c, cmd)
            c.sndQ <- resp
        }
    }
}
```

### Sender Goroutine

Reads responses from `sndQ`, serializes them into 16 KB padded blocks, and writes to TLS:

```go
func (s *Server) sender(ctx context.Context, c *Client) {
    for {
        select {
        case <-ctx.Done():
            return
        case resp := <-c.sndQ:
            block := serializeBlock(resp)
            c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
            _, err := c.conn.Write(block[:])
            if err != nil {
                return
            }
        }
    }
}
```

---

## TLS 1.3 with Custom ALPN

Go's `crypto/tls` package natively supports non-HTTP TLS servers with custom ALPN (Application-Layer Protocol Negotiation):

```go
tlsConfig := &tls.Config{
    Certificates: []tls.Certificate{cert},
    MinVersion:   tls.VersionTLS13,
    NextProtos:   []string{"smp/1"},
}

listener, err := tls.Listen("tcp", ":5223", tlsConfig)
```

After the TLS handshake, verify that the client negotiated the correct protocol:

```go
tlsConn := conn.(*tls.Conn)
if err := tlsConn.Handshake(); err != nil {
    conn.Close()
    return
}
state := tlsConn.ConnectionState()
if state.NegotiatedProtocol != "smp/1" {
    conn.Close()
    return
}
```

SMP uses a two-certificate chain where an offline CA cert signs the online TLS cert. The CA fingerprint appears in the server address (`smp://<fingerprint>@host`) and is how clients verify server identity. This requires generating a self-signed CA keypair and issuing a server certificate signed by it.

---

## Fixed 16 KB Block Transport

The block transport is the foundation of traffic analysis resistance:

```go
const BlockSize = 16384

type BlockTransport struct {
    conn    net.Conn
    readBuf [BlockSize]byte
}

func (bt *BlockTransport) WriteBlock(payload []byte) error {
    var block [BlockSize]byte
    binary.BigEndian.PutUint16(block[:2], uint16(len(payload)))
    copy(block[2:], payload)
    for i := 2 + len(payload); i < BlockSize; i++ {
        block[i] = '#'
    }
    _, err := bt.conn.Write(block[:])
    return err
}

func (bt *BlockTransport) ReadBlock() ([]byte, error) {
    _, err := io.ReadFull(bt.conn, bt.readBuf[:])
    if err != nil {
        return nil, err
    }
    payloadLen := binary.BigEndian.Uint16(bt.readBuf[:2])
    if int(payloadLen) > BlockSize-2 {
        return nil, fmt.Errorf("invalid payload length: %d", payloadLen)
    }
    payload := make([]byte, payloadLen)
    copy(payload, bt.readBuf[2:2+payloadLen])
    return payload, nil
}
```

The read buffer is a fixed array on the struct to avoid per-read heap allocation. For returned payloads in hot paths, use `sync.Pool` for byte slice recycling.

---

## Channel Patterns for Message Routing

### Buffered Channels as Queues

The `rcvQ` and `sndQ` channels should be buffered to absorb temporary speed differences between reader, processor, and writer:

```go
type Client struct {
    conn  *tls.Conn
    rcvQ  chan Command    // buffered, capacity 128
    sndQ  chan Response   // buffered, capacity 128
}
```

A buffer of 128 means the receiver can read up to 128 commands before blocking, even if the processor is temporarily slow. If the buffer fills (slow consumer), backpressure naturally propagates - the receiver blocks on channel send, which means it stops reading from the connection, which means TCP flow control kicks in.

### Subscription Registry

The global subscriber registry maps queue IDs to active client connections. SMP's one-subscriber-per-queue rule means this is a simple 1:1 map:

```go
type SubscriptionHub struct {
    subscribers sync.Map  // recipientId -> *Client
}

func (h *SubscriptionHub) Subscribe(recipientId string, client *Client) *Client {
    old, _ := h.subscribers.Swap(recipientId, client)
    if old != nil {
        return old.(*Client)  // caller sends END to old client
    }
    return nil
}
```

`sync.Map` is ideal here because subscriptions are read-heavy (message delivery checks the map) with infrequent writes (subscribe/unsubscribe). It avoids lock contention that a `sync.RWMutex` would introduce under high read load.

---

## Graceful Shutdown

Production servers must handle SIGTERM and SIGINT gracefully - finish in-flight operations, close connections cleanly, and flush persistent state:

```go
func main() {
    ctx, cancel := signal.NotifyContext(context.Background(),
        syscall.SIGTERM, syscall.SIGINT)
    defer cancel()

    server := NewServer(config)

    g, ctx := errgroup.WithContext(ctx)
    g.Go(func() error { return server.ListenSMP(ctx) })
    g.Go(func() error { return server.ListenGRP(ctx) })

    if err := g.Wait(); err != nil && !errors.Is(err, context.Canceled) {
        slog.Error("server error", "err", err)
    }
}
```

The `errgroup.WithContext` pattern (used by VictoriaMetrics, Prometheus, and others) runs multiple listeners concurrently. If any listener fails fatally, its error cancels the context, which propagates to all other listeners and all client connections through the context chain.

---

## Connection Protection

### Read and Write Deadlines

Every read and write operation must have a deadline to prevent resource exhaustion from slow or malicious clients:

- **Read deadline:** 5 minutes (allows for idle connections with keep-alive)
- **Write deadline:** 10 seconds (writes should complete quickly)
- **Handshake deadline:** 30 seconds (prevent slowloris-style attacks)

Reset the read deadline after every successful read. Reset the write deadline before every write.

### Rate Limiting

Go's `golang.org/x/time/rate` provides a token bucket limiter. Apply two layers:

```go
type Client struct {
    limiter *rate.Limiter  // per-connection: 50 commands/sec, burst 100
}

type Server struct {
    ipLimiters sync.Map    // per-IP: shared across connections from same IP
}
```

When a client exceeds the rate limit, respond with an SMP ERR response rather than dropping the connection - this allows well-behaved clients to back off gracefully.

### Bounded Resources

- Channel buffers: 128 capacity (prevents unbounded memory growth)
- Maximum connections: enforced via channel semaphore
- Maximum queues per connection: configurable limit
- Maximum message size: 16,382 bytes (16 KB block minus 2-byte length header)

---

## Dual-Port Server Architecture

GoRelay's dual-protocol design uses separate listeners on separate ports sharing a common core:

```go
g.Go(func() error { return server.ListenSMP(ctx) })  // port 5223
g.Go(func() error { return server.ListenGRP(ctx) })  // port 7443
```

Both listeners create `Client` structs that interact with the same `QueueStore` and `SubscriptionHub`. The only difference is the transport layer (TLS vs Noise) and the frame encoding (SMP binary format vs GRP format). This is the same pattern used by NATS (serving NATS protocol, MQTT, and WebSocket from a single binary) and Dendrite (serving client API and federation API on different ports).

The package structure enforces this separation:

```
internal/
    core/       QueueStore interface, SubscriptionHub, Message types
    store/      BadgerDB implementation of QueueStore
    smp/        SMP listener, connection handler, frame parser
    grp/        GRP listener, connection handler, Noise transport
```

Both `smp/` and `grp/` import `core/` but never import each other.

---

## Production Infrastructure Choices

### Logging: log/slog

Go 1.21 introduced `log/slog` in the standard library. Zero external dependencies, native context support, pluggable handlers. Performance is near-identical to zerolog (40 B/op, 1 alloc/op). For a security-critical relay server, minimizing dependencies reduces attack surface.

### Configuration: koanf

koanf (`github.com/knadh/koanf/v2`) is the recommended alternative to Viper. Viper forces key lowercasing (violating YAML spec), bloats binaries by 313%, and has tightly coupled parsers. koanf is modular with proper key handling and Watch() support.

### Metrics: Prometheus

`github.com/prometheus/client_golang` on a separate port from the relay. Key metrics: active connections (gauge), messages received (counter by command type), command latency (histogram), queue depth (gauge), rate limit rejects (counter).

### Deployment: Single Static Binary

```dockerfile
FROM golang:1.24 AS builder
WORKDIR /build
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o gorelay ./cmd/gorelay

FROM gcr.io/distroless/static:nonroot
COPY --from=builder /build/gorelay /gorelay
ENTRYPOINT ["/gorelay"]
```

Result: a Docker image between 5-15 MB containing a single binary with no shell, no package manager, no attack surface beyond the Go runtime.

---

*GoRelay - IT and More Systems, Recklinghausen*
