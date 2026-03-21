---
title: "Connection Lifecycle"
sidebar_position: 2
---

# Connection Lifecycle

*The complete lifecycle of a client connection from TCP accept through handshake, command processing, and graceful shutdown.*

**Status:** In development
**Date:** 2026-03-09 (Session 001)

---

## Overview

Every client connection to GoRelay follows the same lifecycle regardless of protocol (SMP or GRP). The differences are in the handshake and frame encoding, not in the connection management.

```
TCP Accept -> Handshake -> Command Loop -> Shutdown -> Cleanup
```

---

## Phase 1: TCP Accept

The listener accepts a TCP connection and immediately applies connection-level protection:

```go
conn, err := listener.Accept()
if err != nil {
    continue
}

// Connection-level limits
if s.connectionCount.Load() >= s.config.MaxConnections {
    conn.Close()
    continue
}
s.connectionCount.Add(1)

// IP-based rate limiting
ip := conn.RemoteAddr().(*net.TCPAddr).IP.String()
if !s.ipLimiter.Allow(ip) {
    conn.Close()
    s.connectionCount.Add(-1)
    continue
}

go s.handleConnection(ctx, conn)
```

**Maximum connections:** Configurable hard limit (default: 10,000). Connections beyond this limit are immediately closed.

**IP rate limiting:** Maximum 20 new connections per minute per IP address. Prevents connection flooding from a single source.

**No logging of IP addresses:** The IP is used only for in-memory rate limiting. It is never written to disk, never logged, and never associated with a queue or identity.

---

## Phase 2: Handshake

### Handshake Deadline

A 30-second deadline is set before the handshake begins. If the handshake does not complete within this window, the connection is closed silently (no error message to prevent information leakage).

### SMP Handshake

```
1. Server creates TLS connection (crypto/tls)
2. TLS 1.3 handshake with ALPN "smp/1"
3. Verify ALPN negotiated correctly
4. Server sends: smpVersionRange + serverPublicKey
5. Client sends: clientVersion + clientPublicKey + auth
6. Version negotiation (agree on highest mutual version)
7. Handshake complete -> create Client struct
```

### GRP Handshake

```
1. Client sends version byte (0x01 for GRP/1)
2. Server reads version byte, selects protocol handler
3. Noise IK or XX handshake (with hybrid ML-KEM-768)
4. Post-handshake session key derivation
5. Handshake complete -> create Client struct
```

### Authentication

After the handshake, the connection is authenticated but not yet authorized for any specific queue. Queue-level authorization happens per-command via Ed25519 signatures.

---

## Phase 3: Three Goroutines

After successful handshake, three goroutines are spawned:

```go
func (s *Server) runClient(ctx context.Context, conn net.Conn, proto Protocol) {
    client := s.newClient(conn, proto)
    defer s.clientDisconnected(client)

    ctx, cancel := context.WithCancel(ctx)
    defer cancel()

    var wg sync.WaitGroup
    wg.Add(3)

    go func() { defer wg.Done(); defer cancel(); s.receiver(ctx, client) }()
    go func() { defer wg.Done(); defer cancel(); s.processor(ctx, client) }()
    go func() { defer wg.Done(); defer cancel(); s.sender(ctx, client) }()

    // Optional: cover traffic goroutine
    if s.config.CoverTraffic.Enabled && proto == GRP {
        wg.Add(1)
        go func() { defer wg.Done(); s.coverTrafficLoop(ctx, client) }()
    }

    wg.Wait()
}
```

The `defer cancel()` in each goroutine is critical: if ANY goroutine exits (error, timeout, connection close), the context cancellation propagates to all others. No orphaned goroutines.

### Receiver Goroutine

```
Loop:
  1. Set read deadline (5 minutes)
  2. Read exactly 16,384 bytes (io.ReadFull)
  3. Parse block: extract payload length, strip padding
  4. Parse payload: batch count, transmission(s)
  5. For each transmission:
     a. Verify signature (if signed command)
     b. Verify session ID
     c. Push to rcvQ channel
  6. If read error or parse error: return (triggers cancel)
```

**Read deadline:** Reset after every successful read. If no data arrives within 5 minutes (and no PING is sent by the client), the connection is considered dead.

### Processor Goroutine

```
Loop:
  1. Select on ctx.Done() or rcvQ
  2. Read command from rcvQ
  3. Dispatch command:
     - NEW -> createQueue()
     - SUB -> subscribe()
     - SEND -> pushMessage()
     - ACK -> ackMessage()
     - PING -> immediate PONG
     - PFWD -> forwardMessage()
     - etc.
  4. Push response to sndQ
```

The processor is the only goroutine that touches the queue store and subscription hub. This eliminates data races without explicit locking.

### Sender Goroutine

```
Loop:
  1. Select on ctx.Done() or sndQ
  2. Read response from sndQ
  3. Serialize response to transmission format
  4. Pad to 16,384-byte block
  5. Set write deadline (10 seconds)
  6. Write block to connection
  7. If write error: return (triggers cancel)
```

**Write deadline:** 10 seconds. If the client is not reading fast enough (backpressure from a slow network), the write times out and the connection is closed. This prevents slow-client denial of service.

---

## Phase 4: Keep-Alive

Clients MUST send PING at least every 60 seconds. The server responds with PONG immediately. The PING/PONG cycle serves two purposes:

1. **TCP keep-alive:** Prevents intermediate network devices (NATs, firewalls, load balancers) from closing idle connections.
2. **Subscription maintenance:** The server tracks last activity time per connection. After 5 minutes of inactivity (no PING, no commands), subscriptions are released.

### Timing

| Event | Timeout |
|---|---|
| Client PING interval | Every 30-60 seconds (recommended) |
| Server read deadline | 5 minutes (hard limit) |
| Server subscription timeout | 5 minutes without any activity |
| Server write deadline | 10 seconds per block |

---

## Phase 5: Shutdown

Connection shutdown occurs for any of these reasons:

- **Client disconnects:** TCP connection closes (FIN or RST)
- **Read error:** io.ReadFull fails (broken connection, timeout)
- **Write error:** Write times out or fails
- **Parse error:** Invalid block format, invalid command
- **Rate limit:** Too many commands per second
- **Server shutdown:** Context cancelled by SIGTERM/SIGINT

### Shutdown Sequence

```go
func (s *Server) clientDisconnected(client *Client) {
    // 1. Close the connection
    client.conn.Close()

    // 2. Release all subscriptions
    for queueID := range client.subscriptions {
        s.subHub.Unsubscribe(queueID, client)
    }

    // 3. Decrement connection counter
    s.connectionCount.Add(-1)

    // 4. Log disconnection (no IP, no identity)
    slog.Info("client disconnected",
        "protocol", client.protocol,
        "duration", time.Since(client.createdAt),
        "commands", client.commandCount,
    )
}
```

**What is NOT logged:** IP address, queue IDs, message counts, subscription details. The log entry contains only the protocol type, connection duration, and total command count - enough for operational monitoring without metadata leakage.

---

## Graceful Server Shutdown

When GoRelay receives SIGTERM or SIGINT:

```go
func (s *Server) Shutdown(ctx context.Context) error {
    // 1. Stop accepting new connections
    s.smpListener.Close()
    s.grpListener.Close()

    // 2. Wait for in-flight commands to complete (max 30 seconds)
    shutdownCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
    defer cancel()

    // 3. Cancel all client contexts (triggers goroutine shutdown)
    s.cancelAllClients()

    // 4. Wait for all client goroutines to exit
    s.clientWg.Wait()

    // 5. Flush and close the queue store
    s.queueStore.Close()

    // 6. Close relay connections
    s.relayPool.Close()

    return nil
}
```

The 30-second grace period allows in-flight message deliveries to complete. After 30 seconds, remaining connections are forcefully closed.

---

## Connection Metrics

GoRelay exposes connection metrics via Prometheus on a separate port:

```
gorelay_connections_active{protocol="smp"}          # current SMP connections
gorelay_connections_active{protocol="grp"}          # current GRP connections
gorelay_connections_total{protocol="smp"}           # total SMP connections since start
gorelay_connections_total{protocol="grp"}           # total GRP connections since start
gorelay_handshake_duration_seconds{protocol="smp"}  # handshake latency histogram
gorelay_handshake_duration_seconds{protocol="grp"}  # handshake latency histogram
gorelay_connection_duration_seconds                  # connection lifetime histogram
gorelay_commands_total{command="NEW"}               # command counter by type
gorelay_commands_total{command="SEND"}
gorelay_commands_total{command="PING"}
gorelay_rate_limit_rejects_total                    # rate limit rejections
```

Metrics contain NO per-client information, NO IP addresses, and NO queue identifiers.

---

*GoRelay - IT and More Systems, Recklinghausen*
