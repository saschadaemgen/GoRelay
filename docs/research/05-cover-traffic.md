---
title: "Cover Traffic and Traffic Analysis Resistance"
sidebar_position: 5
---

# Cover Traffic and Traffic Analysis Resistance

*How GoRelay defends against traffic analysis attacks using fixed-size messages, server-generated cover traffic, and constant-rate communication patterns.*

**Research date:** 2026-03-09 (Session 001)

---

## The Traffic Analysis Threat

Encrypting message content is necessary but not sufficient for private communication. An adversary who cannot read messages can still learn valuable information by observing traffic patterns: when messages are sent, how large they are, how frequently they appear, and which servers are involved.

Traffic analysis has been used by intelligence agencies since World War I (analyzing telegram volumes between embassies). In the digital age, it has become more powerful: ISPs, government surveillance programs, and network-level adversaries can observe connection timing, packet sizes, and communication patterns without breaking any encryption.

For a messaging relay server, this means an observer positioned on the network path can potentially determine: whether a user is actively messaging or idle, approximately how many messages they send and receive, the rough size of messages (if not padded), and timing correlations between sender and recipient connections.

---

## The Anonymity Trilemma

Academic research establishes a fundamental constraint on anonymous communication systems. The Comprehensive Anonymity Trilemma (Das et al., PoPETs 2020) proves formally that a system cannot simultaneously achieve all three of the following properties:

1. **Strong anonymity** (adversary cannot link sender to recipient)
2. **Low latency** (messages delivered without significant delay)
3. **Low bandwidth overhead** (no excessive dummy traffic)

Any system must sacrifice at least one. Tor sacrifices strong anonymity (vulnerable to timing attacks by global adversaries). Mixnets like Loopix sacrifice latency (messages are delayed and batched). Constant-rate systems sacrifice bandwidth (sending traffic even when idle).

GoRelay's approach is honest about this trade-off: we sacrifice bandwidth to achieve strong traffic analysis resistance with low latency. The cost is manageable because messaging traffic volumes are inherently small.

---

## Layer 1: Fixed-Size Messages

The foundation of traffic analysis resistance is making all messages the same size. SMP already does this with its 16,384-byte block format - every frame on the wire is exactly 16 KB regardless of content. A one-word message, a maximum-length message, a PING keep-alive, and a cover traffic dummy all look identical on the wire.

This eliminates size-based correlation entirely. An observer cannot distinguish message types, estimate content length, or correlate messages based on size fingerprints.

The overhead is modest. A typical text message might be 200-500 bytes of actual content, padded to 16,384 bytes. This is approximately 97% padding. But at messaging rates (a few messages per minute at most), the absolute bandwidth is trivial - a few hundred KB per minute even with full padding.

GoRelay inherits this property from SMP and extends it to GRP. Both protocols use identical 16 KB block framing.

---

## Layer 2: Server-Generated Cover Traffic

### The Concept

Cover traffic consists of dummy messages that are cryptographically indistinguishable from real messages. They are encrypted with the same algorithms, padded to the same size, and delivered through the same channels. The only difference is a flag inside the encrypted payload that tells the receiving client to discard the message.

An observer on the network sees a stream of identical 16 KB encrypted blocks. Some contain real messages, some contain dummies. Without breaking the encryption, the observer cannot tell which is which.

### Poisson Distribution

GoRelay generates cover traffic using a Poisson process - dummy messages are sent at exponentially-distributed random intervals. This is the same model used by Loopix and Katzenpost, chosen because Poisson processes are memoryless (the time until the next dummy is independent of when the last one was sent) and statistically indistinguishable from many natural communication patterns.

The key parameter is the cover traffic rate (lambda). Higher lambda means more dummies, stronger anonymity, but more bandwidth:

| Cover Ratio | Real Traffic | Cover Traffic | Total | Anonymity |
|---|---|---|---|---|
| 0:1 (none) | 2 KB/s | 0 KB/s | 2 KB/s | None |
| 1:1 | 2 KB/s | 2 KB/s | 4 KB/s | Moderate |
| 3:1 | 2 KB/s | 6 KB/s | 8 KB/s | Strong |
| 10:1 | 2 KB/s | 20 KB/s | 22 KB/s | Very strong |

For a typical deployment with 50 users averaging 5 messages per hour, real traffic is approximately 2 KB/s. At a 3:1 cover ratio, total traffic is approximately 8 KB/s or about 20 GB per month. On a VPS with 1 TB monthly bandwidth, this is well within budget.

### Server-Side vs Client-Side Cover Traffic

There are two approaches to generating cover traffic:

**Client-side:** Each client sends dummy messages at random intervals. The server cannot distinguish real from dummy traffic. This provides the strongest guarantee because the server itself is not trusted with the knowledge of which messages are real.

**Server-side:** The server injects dummy messages into the delivery stream for each connected client. The client receives a mix of real and dummy messages and discards the dummies.

GoRelay uses server-side cover traffic for a practical reason: we control the server implementation but not all client implementations. SimpleX Chat apps connecting via SMP do not generate cover traffic. By generating it server-side, we provide traffic analysis resistance even for clients that do not implement it themselves.

For GRP-native clients (SimpleGo devices), both client-side and server-side cover traffic can operate simultaneously for maximum protection.

### Implementation

For each connected client, the server runs a dedicated goroutine that generates dummy messages:

```go
func (s *Server) coverTrafficGenerator(ctx context.Context, client *Client) {
    lambda := s.config.CoverTrafficRate  // e.g., 0.5 messages/second
    for {
        select {
        case <-ctx.Done():
            return
        default:
        }
        // Exponentially-distributed wait time (Poisson process)
        delay := time.Duration(-math.Log(rand.Float64()) / lambda * float64(time.Second))
        time.Sleep(delay)
        
        dummy := s.generateDummyMessage(client)
        client.sndQ <- dummy
    }
}
```

The dummy message is encrypted identically to a real message, with a single-byte flag inside the encrypted payload indicating it should be discarded. From the network perspective, it is a standard 16 KB block.

---

## Layer 3: Constant-Rate Communication

The strongest form of traffic analysis resistance is constant-rate communication: the client sends and receives blocks at a fixed rate regardless of whether real messages exist. When there is a real message, it replaces one of the scheduled blocks. When there is no real message, a dummy is sent instead.

This makes the traffic pattern completely independent of actual communication activity. An observer sees a steady stream of identical blocks and learns nothing about when (or whether) real communication is occurring.

The trade-off is bandwidth: at one block per second (16 KB/s), a single connection consumes approximately 1.4 GB per day. This is feasible for dedicated IoT devices on wired connections but may be excessive for mobile clients on metered connections.

GoRelay supports constant-rate mode as an optional GRP feature for high-security deployments. The default Poisson cover traffic provides a practical middle ground.

---

## Layer 4: Queue Rotation

Even with perfect traffic analysis resistance on individual connections, long-lived queue identifiers create a metadata trail. If a queue ID persists for months, an adversary who compromises the server (even temporarily) can correlate historical observations.

Queue rotation periodically replaces queue IDs with fresh random values. The process follows the SMP queue rotation protocol:

1. **QADD:** Recipient creates a new queue on the same or different server, sends the new queue URI to the sender
2. **QKEY:** Sender generates new keys for the new queue
3. **QUSE:** Both parties switch to the new queue with a brief overlap period
4. **QTEST:** Confirm the new queue works, delete the old one

GoRelay automates this process with configurable triggers:

- **Time-based:** Rotate every 24-72 hours (with random jitter to prevent timing fingerprints)
- **Message-based:** Rotate every 100-500 messages
- **Server-diversity:** When rotating, prefer a different GoRelay server to distribute metadata across multiple servers over time

Random jitter is critical. If all queues rotate at exactly 24-hour intervals, an adversary can correlate the old and new queues by timing. Adding uniform random jitter of plus or minus 6 hours makes this correlation impractical.

---

## Layer 5: Connection Padding

Beyond message-level padding, GoRelay pads connection-level metadata:

**Handshake padding:** GRP handshakes are padded to fixed sizes so an observer cannot distinguish a Noise IK handshake (shorter) from a Noise XX handshake (longer).

**Error response padding:** Error messages are padded to the same 16 KB block size as successful responses. An observer cannot determine whether an operation succeeded or failed by watching block sizes.

**Timing padding:** Response times are normalized to prevent timing-based inference. If a queue lookup takes 1ms but a "queue not found" error takes 0.1ms, an observer could probe for queue existence. Adding random delay to fast operations eliminates this side channel.

---

## What Cover Traffic Cannot Do

Honest engineering requires acknowledging limitations:

**Global adversary:** A sufficiently powerful adversary monitoring all network links simultaneously can perform intersection attacks over time, correlating the activity patterns of all users. Cover traffic increases the observation time required but does not eliminate this attack vector.

**Endpoint compromise:** If the client or server is compromised (malware, physical access), cover traffic provides no protection. The adversary can read messages directly.

**Volume analysis over long periods:** Even with cover traffic, an adversary who observes a connection for weeks or months may detect statistical anomalies in traffic patterns that correlate with real communication events (Oya et al., 2014).

**Receiver-side correlation:** Server-generated cover traffic protects the sender side effectively. Receiver-bound cover (generating dummy deliveries to recipients) is more complex and requires receiver cooperation.

GoRelay's threat model is realistic: we aim to make traffic analysis expensive and unreliable, not provably impossible. The combination of fixed-size messages, Poisson cover traffic, queue rotation, and two-hop relay routing raises the cost of surveillance to a level that deters most adversaries while remaining practical for real-world deployment.

---

## Bandwidth Budget

For a GoRelay deployment planning:

| Users | Messages/Hour/User | Real Traffic | Cover (3:1) | Total Monthly |
|---|---|---|---|---|
| 10 | 5 | 0.4 KB/s | 1.2 KB/s | ~4 GB |
| 50 | 5 | 2 KB/s | 6 KB/s | ~20 GB |
| 100 | 10 | 8 KB/s | 24 KB/s | ~80 GB |
| 500 | 10 | 40 KB/s | 120 KB/s | ~400 GB |

A standard VPS with 1 TB monthly bandwidth comfortably supports 100+ active users with 3:1 cover traffic. CPU overhead for encrypting dummy messages is negligible - less than 1% of a single core at 100 dummies per second.

---

*GoRelay - IT and More Systems, Recklinghausen*
