---
title: "Cover Traffic"
sidebar_position: 8
---

# GRP Protocol Specification: Cover Traffic

*Specification of GRP's server-generated cover traffic system using Poisson-distributed dummy messages for traffic analysis resistance.*

**Version:** GRP/1 (Draft)
**Status:** In development
**Date:** 2026-03-09

---

## Purpose

Cover traffic defends against timing-based traffic analysis. Fixed-size blocks (Layer 1 defense) prevent an observer from determining message content or size. Cover traffic (Layer 2 defense) prevents an observer from determining WHEN real communication occurs.

Without cover traffic, an observer sees:

```
[block]...[silence]...[block][block][block]...[silence]...
         ^                                    ^
         idle                                 idle
```

The burst pattern reveals that the user sent three messages. With cover traffic:

```
[block][block][block][block][block][block][block][block][block]
```

Every time slot has a block. Some are real, some are dummies. The observer cannot distinguish them.

---

## Poisson Process Model

### Why Poisson

Cover traffic timing follows a Poisson process - dummy messages are generated at exponentially-distributed random intervals. This model was chosen because:

**Memoryless property:** The time until the next dummy is independent of when the last one was sent. This means an observer cannot predict when the next block will appear, even after observing the pattern for an extended period.

**Statistical indistinguishability:** Many natural communication patterns (email arrivals, phone calls, web requests) approximate Poisson processes. Cover traffic that matches this distribution blends with legitimate background traffic.

**Simplicity:** A Poisson process is fully characterized by a single parameter (lambda, the average rate). This makes configuration, analysis, and tuning straightforward.

### Implementation

```go
func (s *Server) coverTrafficLoop(ctx context.Context, client *Client) {
    lambda := s.config.CoverTrafficRate  // messages per second

    for {
        select {
        case <-ctx.Done():
            return
        default:
        }

        // Exponential inter-arrival time
        u := rand.Float64()
        if u == 0 {
            u = math.SmallestNonzeroFloat64
        }
        delay := time.Duration(-math.Log(u) / lambda * float64(time.Second))

        select {
        case <-ctx.Done():
            return
        case <-time.After(delay):
            dummy := s.generateCoverMessage(client)
            select {
            case client.sndQ <- dummy:
                // delivered
            default:
                // send queue full, skip this dummy
            }
        }
    }
}
```

The `select` with `default` on `client.sndQ` prevents cover traffic from blocking when the client's send queue is full. Dropping an occasional dummy is harmless - it marginally reduces cover density but does not affect real message delivery.

---

## Dummy Message Generation

### Structure

A cover traffic message is structurally identical to a real MSG delivery:

```go
func (s *Server) generateCoverMessage(client *Client) Response {
    // Generate random body matching typical message size distribution
    bodySize := s.sampleMessageSize()
    body := make([]byte, bodySize)
    rand.Read(body)

    return Response{
        Command:       CMD_MSG,
        EntityID:      randomQueueID(),      // random, not a real queue
        MessageID:     generateMessageID(),
        Timestamp:     uint64(time.Now().Unix()),
        Flags:         FLAG_COVER_TRAFFIC,    // bit 0 set
        Body:          body,
    }
}
```

### Cover Traffic Flag

The `FLAG_COVER_TRAFFIC` (0x01) is set in the flags byte of the MSG command. This flag is INSIDE the encrypted payload - it is only visible after the recipient decrypts the Noise transport layer.

**Client behavior on receiving cover traffic:** The client reads the flags byte, sees the cover traffic bit, and silently discards the message. No processing, no display, no notification, no storage.

**Network observer sees:** An encrypted 16 KB block indistinguishable from any other block.

### Message Size Distribution

The dummy message body is NOT fixed-size - it is drawn from a distribution that matches typical real message lengths:

```go
func (s *Server) sampleMessageSize() int {
    // Log-normal distribution matching empirical message sizes
    // Mean: ~200 bytes, Median: ~120 bytes, 95th percentile: ~800 bytes
    mu := 5.0    // ln(150)
    sigma := 1.0
    size := int(math.Exp(rand.NormFloat64()*sigma + mu))
    if size < 16 {
        size = 16
    }
    if size > 15000 {
        size = 15000
    }
    return size
}
```

After padding to 16,384 bytes, all messages look identical on the wire regardless of body size. The variable body size matters only for the decrypted content - but since dummies are discarded, the body content is irrelevant. The size variation ensures that memory allocation patterns during dummy generation mimic real message processing, preventing side-channel leakage through memory allocation timing.

---

## Configuration

### Server Configuration

```yaml
cover_traffic:
  enabled: true
  rate: 0.2              # messages per second per client (lambda)
  min_rate: 0.05          # minimum rate (cannot be disabled below this)
  max_rate: 2.0           # maximum rate
  adaptive: true          # adjust rate based on real traffic volume
```

### Rate Parameters

| Rate (lambda) | Avg Interval | Cover per Hour | Monthly per Client |
|---|---|---|---|
| 0.05 | 20 seconds | 180 | ~0.4 GB |
| 0.1 | 10 seconds | 360 | ~0.8 GB |
| 0.2 | 5 seconds | 720 | ~1.6 GB |
| 0.5 | 2 seconds | 1,800 | ~4 GB |
| 1.0 | 1 second | 3,600 | ~8 GB |
| 2.0 | 0.5 seconds | 7,200 | ~16 GB |

The default rate of 0.2 messages/second produces approximately 720 cover messages per hour per connected client, consuming about 1.6 GB per month per client. For a server with 50 active clients, total cover traffic is approximately 80 GB per month - well within typical VPS bandwidth allocations.

### Adaptive Rate

When adaptive mode is enabled, the server adjusts the cover traffic rate based on observed real traffic:

**During active messaging:** Real messages are already producing blocks. The cover rate decreases to avoid excessive bandwidth during peak usage.

**During idle periods:** No real messages are flowing. The cover rate increases to maintain a consistent overall block rate, preventing an observer from detecting the transition from active to idle.

```go
func (s *Server) adaptiveRate(client *Client) float64 {
    recentRealRate := client.realMessageRate(5 * time.Minute)
    targetRate := s.config.CoverTrafficRate

    if recentRealRate > targetRate {
        // Real traffic exceeds cover target, reduce cover
        return targetRate * 0.25
    }
    // Fill gap between real traffic and target
    return targetRate - recentRealRate
}
```

The target is a consistent overall block rate. Whether those blocks are real or cover, the observer sees the same traffic pattern.

---

## Cover Traffic on Relay-to-Relay Links

Cover traffic is also generated on the relay-to-relay links used for two-hop routing:

```
Relay A --> [cover + real] --> Relay B
```

Without inter-relay cover traffic, an observer watching the link between Relay A and Relay B could correlate message volume with specific sender connections on Relay A.

Inter-relay cover uses the same Poisson model but at a higher aggregate rate (since the link carries traffic for all forwarded users):

```yaml
relay_cover_traffic:
  enabled: true
  rate: 2.0    # messages per second per peer relay link
```

---

## Client-Side Cover Traffic (GRP-native)

For GRP-native clients (SimpleGo devices), the client can also generate cover traffic in the sender direction:

```
Client --> [cover + real] --> Relay A
```

This protects against an observer watching the client's network connection. Server-side cover traffic only protects the server-to-client direction.

Client-side cover is optional and configured per-client:

```
client_cover_traffic:
  enabled: true
  rate: 0.1     # lower rate for bandwidth-constrained devices
```

For SMP clients (SimpleX Chat) connecting via the SMP port, client-side cover traffic is not available because the SMP protocol does not define it. Server-side cover on the delivery path still provides protection for the recipient direction.

---

## Cover Traffic and Subscriptions

Cover traffic is generated for ALL connected and subscribed clients, regardless of whether they have active conversations:

- **Connected, subscribed, active conversation:** Real messages + cover traffic
- **Connected, subscribed, no active conversation:** Cover traffic only
- **Connected, not subscribed:** No cover traffic (no queue to mimic delivery to)
- **Not connected:** No cover traffic (no connection to send on)

This means a connected client always sees a stream of blocks. Whether the client is actively messaging or completely idle, the network traffic pattern is indistinguishable.

---

## Bandwidth Budget

### Per-Server Budget

For capacity planning, the total cover traffic budget:

```
total_cover_bandwidth = num_clients * cover_rate * block_size

Example: 100 clients, 0.2 msg/sec, 16 KB blocks
  = 100 * 0.2 * 16,384
  = 327,680 bytes/sec
  = ~28 GB/day
  = ~840 GB/month
```

On a VPS with 1 TB monthly bandwidth, this leaves approximately 160 GB for real traffic - more than sufficient for a messaging relay.

### Optimization: Batched Cover

Instead of sending individual 16 KB cover blocks, the server can batch cover generation into fewer, larger transmission bursts. This reduces the number of system calls (write operations) while maintaining the same average cover rate.

```go
// Instead of: 1 block every 5 seconds
// Batch: 5 blocks every 25 seconds (same average rate, fewer syscalls)
```

Batching is invisible to network observers (they see the same average block rate) but reduces server CPU overhead from per-block encryption and system call overhead.

---

## Metrics

The server exposes cover traffic metrics via Prometheus:

```
gorelay_cover_messages_generated_total{type="client"}     # total dummies sent to clients
gorelay_cover_messages_generated_total{type="relay"}       # total dummies sent to peer relays
gorelay_cover_messages_dropped_total                       # dummies dropped (queue full)
gorelay_cover_rate_current{client_id="..."}                # current adaptive rate per client
gorelay_cover_bandwidth_bytes_total                        # total cover traffic bandwidth
```

These metrics allow operators to monitor cover traffic health without revealing which specific messages are real or cover (the metric counts totals, not per-message classifications).

---

## Limitations

**Not provably anonymous.** Cover traffic raises the cost of traffic analysis but does not provide provable anonymity guarantees like mix networks (Loopix, Nym). A sufficiently funded adversary with long-term observation capabilities may still extract signal from noise through advanced statistical methods.

**Bandwidth cost.** Cover traffic consumes bandwidth even when no real communication occurs. For bandwidth-constrained deployments (cellular IoT devices), the cover rate may need to be reduced, weakening traffic analysis resistance.

**One-directional limitation.** Server-generated cover traffic protects the server-to-client direction. Protecting the client-to-server direction requires client-side cover traffic, which SMP clients do not support.

**Client must be connected.** Cover traffic only flows while the client maintains an active connection. An observer who can detect connection/disconnection events knows that the user is online, even if they cannot determine whether real messages are being exchanged.

---

*GoRelay Protocol Specification - IT and More Systems, Recklinghausen*
