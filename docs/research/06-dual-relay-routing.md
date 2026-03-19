---
title: "Two-Hop Relay Routing Analysis"
sidebar_position: 6
---

# Two-Hop Relay Routing Analysis

*How GoRelay's mandatory two-hop message routing prevents sender-recipient correlation, based on analysis of SimpleX PMR, Tor, and academic research on optimal path lengths.*

**Research date:** 2026-03-09 (Session 001)

---

## The Problem: Single-Hop Metadata Exposure

In a standard single-hop relay architecture, the relay server sees both sides of every communication:

```
Sender --> [Relay Server] --> Recipient
           sees sender IP
           sees destination queue
           can correlate both
```

Even though the message content is encrypted, the server knows which IP address sent a message to which queue. Over time, this metadata reveals communication patterns, social graphs, and behavioral information that can be as revealing as message content itself.

This is not a theoretical concern. Court orders and national security letters routinely request metadata rather than content because metadata is structured, searchable, and often more useful for surveillance than encrypted message bodies.

---

## Two-Hop Architecture

Two-hop relay routing splits the metadata between two independent servers so that neither one has the complete picture:

```
Sender --> [Relay A] --> [Relay B] --> Recipient
           sees sender IP    sees destination queue
           sees Relay B      sees Relay A
           NOT destination   NOT sender IP
```

**Relay A (forwarding server)** sees the sender's IP address and knows which server to forward to, but does not know the destination queue on that server. The destination information is encrypted so that only Relay B can read it.

**Relay B (destination server)** sees the destination queue and knows where to deliver the message, but only sees Relay A's IP address as the source. It has no knowledge of the original sender.

Neither server alone can link sender to recipient. An adversary would need to compromise both servers simultaneously to reconstruct the full communication path.

---

## How SimpleX Private Message Routing Works

SimpleX introduced Private Message Routing (PMR) in version 5.8 (June 2024), enabled by default from version 6.0. It implements a packet-based two-hop relay with five distinct encryption layers:

### The Five Encryption Layers

**Layer 1 - e2e (end-to-end):** Double Ratchet encryption between sender and recipient. This is the standard end-to-end encryption that exists regardless of relay routing.

**Layer 2 - s2d (sender-to-destination):** Encrypts metadata including the destination queue ID and notification flags. The forwarding relay cannot read this layer. A per-message ephemeral key prevents cross-queue correlation - even if an adversary sees multiple messages forwarded to the same destination server, they cannot determine if the messages are going to the same queue.

**Layer 3 - f2d (forwarding-to-destination):** Encrypts the forwarded message between the two relay servers. Prevents traffic correlation even if TLS between the relays is compromised.

**Layer 4 - d2r (destination-to-recipient):** Encrypts the delivered message between the destination server and the recipient. Prevents ciphertext correlation inside TLS on the last hop.

**Layer 5 - TLS:** Standard transport encryption on each network hop (sender to Relay A, Relay A to Relay B, Relay B to recipient).

### Protocol Commands

The routing uses four commands:

| Command | Direction | Purpose |
|---|---|---|
| PFWD | Client to Relay A | Push message for forwarding |
| RFWD | Relay A to Relay B | Relay the forwarded message |
| RRES | Relay B to Relay A | Return response to forwarding relay |
| PRES | Relay A to Client | Return response to sender |

### Per-Message Ephemeral Keys

A critical design detail: the s2d encryption uses a per-message ephemeral key. This means that even if two messages from the same sender go to the same destination server, the encrypted metadata looks completely different each time. An observer cannot correlate messages by comparing ciphertext patterns.

---

## Why Two Hops, Not Three (or More)

### Academic Research

The question of optimal path length has been studied extensively in the context of Tor and anonymous communication:

**"On the Optimal Path Length for Tor" (Bauer, Juen, Borisov - PETS 2010)** found that three-hop paths offer no additional protection against practical timing attacks compared to two-hop paths. The reason: if an adversary controls (or observes) both the entry and exit points of a circuit, they can correlate traffic regardless of how many intermediate hops exist. Additional hops only help against adversaries who control some but not all intermediate nodes - and for a two-server system where we control both servers, this is not the relevant threat model.

**The latency cost is linear.** Each additional hop adds network round-trip time. For same-region servers, one hop adds approximately 5-15 milliseconds. Two hops add 10-30 milliseconds. Three hops add 15-45 milliseconds. For messaging where delivery latency of seconds is acceptable, even three hops would be tolerable - but the security benefit does not justify the added complexity.

**ShorTor (Hogan et al., 2022)** demonstrated that multi-hop overlay routing can actually improve latency by choosing relay paths that avoid congested network segments. This suggests that two-hop routing through well-placed GoRelay servers could be faster than single-hop routing through a congested direct path.

### Practical Considerations

Full onion routing (Tor-style) requires:
- A directory authority that lists all available relays
- A circuit-building protocol with layered encryption
- Cell-based forwarding with fixed-size cells
- Complex key exchange with each hop

This is enormous complexity for marginal benefit in a messaging context. Two-hop relay routing achieves the core property (sender-recipient unlinkability at each server) with a fraction of the implementation cost.

---

## GoRelay's Two-Hop Implementation

### Dual-Role Servers

Every GoRelay server operates in two roles simultaneously:

**Direct server:** Accepts client connections, manages queues, delivers messages. This is the standard relay function.

**Forwarding relay:** Accepts PFWD/RFWD commands and forwards messages to other GoRelay servers. This is the routing function.

A deployment with two GoRelay servers (relay1.simplego.dev and relay2.simplego.dev) enables full two-hop routing. The sender connects to Relay 1, which forwards to Relay 2, which delivers to the recipient. Or vice versa.

### Connection Pooling Between Relays

Relay-to-relay connections carry messages for many different users. Establishing a new TLS connection for each forwarded message would be prohibitively expensive. Instead, GoRelay maintains persistent connection pools between relay servers:

- Persistent TLS connections to frequently-contacted peer relays
- Idle timeout of 5-15 minutes
- Multiplexed streams over a single TCP connection using yamux
- Automatic reconnection on failure

When Go's `io.Copy` operates between two `*net.TCPConn` instances, it automatically uses the Linux `splice()` syscall for zero-copy data transfer - approximately 50-70% more efficient than copying through userspace for messages of 16 KB or larger.

### Encryption Nesting

The encryption layers use application-layer symmetric encryption (ChaCha20-Poly1305) within TLS, not literal TLS-in-TLS. Each layer adds less than 0.1 milliseconds of processing time per message:

```
Original message (e2e encrypted by sender)
  -> Wrap in s2d encryption (destination metadata, ephemeral key)
    -> Wrap in TLS to Relay A
      Relay A unwraps TLS, cannot read s2d layer
      -> Wrap in f2d encryption + TLS to Relay B
        Relay B unwraps TLS + f2d, reads s2d to find destination queue
        -> Wrap in d2r encryption + TLS to recipient
          Recipient unwraps all layers, decrypts e2e message
```

---

## Performance Impact

### Latency

Two-hop routing adds the network round-trip time between Relay A and Relay B. For servers in the same geographic region:

| Server Distance | Added Latency | Total (with processing) |
|---|---|---|
| Same datacenter | less than 1 ms | 1-2 ms |
| Same region (e.g., Frankfurt to Amsterdam) | 5-10 ms | 7-15 ms |
| Cross-region (e.g., Frankfurt to New York) | 40-80 ms | 45-90 ms |
| Cross-continent (e.g., Frankfurt to Tokyo) | 120-200 ms | 130-220 ms |

For messaging applications where delivery latency of 1-5 seconds is normal and acceptable, even cross-continent routing is imperceptible to users.

### Bandwidth

Each message traverses two servers instead of one, approximately doubling the bandwidth consumption:

| Users | Messages/Hour | Single-Hop | Two-Hop |
|---|---|---|---|
| 50 | 5/user | 20 GB/month | 40 GB/month |
| 100 | 10/user | 80 GB/month | 160 GB/month |

This is well within typical VPS bandwidth allocations (1-5 TB/month per server).

### CPU

The additional encryption layers (s2d, f2d, d2r) are ChaCha20-Poly1305 AEAD operations on 16 KB blocks. Each operation takes approximately 5-10 microseconds on modern hardware. At 1,000 messages per second (far beyond typical messaging load), this adds less than 1% CPU utilization.

---

## Threat Model

### What Two-Hop Routing Protects Against

**Compromised single server:** An adversary who gains access to one GoRelay server learns either sender IPs or destination queues, but never both. They cannot reconstruct communication patterns.

**Network observation at one hop:** An ISP or network-level adversary monitoring traffic to one server sees connections and encrypted blocks but cannot correlate them to specific communications without observing the other server simultaneously.

**Legal compulsion of one server:** A court order served to the operator of one GoRelay server yields incomplete metadata. The server can provide connection logs (if any exist - GoRelay logs nothing by default) but cannot identify who is communicating with whom.

### What Two-Hop Routing Does NOT Protect Against

**Adversary controlling both servers:** If the same adversary compromises both Relay A and Relay B, they can correlate sender IPs with destination queues. Mitigation: use servers operated by different entities in different jurisdictions.

**Global network adversary:** An adversary monitoring all network links simultaneously can perform timing correlation between the sender's connection to Relay A and Relay B's delivery to the recipient. Cover traffic mitigates but does not eliminate this attack.

**Endpoint compromise:** If the sender's or recipient's device is compromised, routing provides no protection. The adversary reads messages directly on the device.

---

## Comparison With Alternatives

| System | Hops | Latency Added | Metadata Protection | Complexity |
|---|---|---|---|---|
| Direct relay (standard SMP) | 1 | 0 ms | Server sees both sides | Low |
| GoRelay two-hop | 2 | 5-15 ms | Neither server sees both | Medium |
| Tor | 3 | 100-300 ms | Strong against partial adversary | Very high |
| Nym mixnet | 3+ | 500-800 ms | Strong with cover traffic | Very high |
| Loopix | 3+ | Variable (batched) | Provable anonymity bounds | Very high |

GoRelay's two-hop routing occupies the practical middle ground: meaningful metadata protection without the latency and complexity costs of full mix networks. For messaging applications where sub-second latency matters and the primary threat is single-server compromise or legal compulsion, two-hop routing provides the best trade-off.

---

## Deployment Considerations

### Minimum Viable Deployment

Two GoRelay servers are the minimum for two-hop routing. The recommended initial deployment:

- **relay1.simplego.dev** - Primary server (e.g., Hetzner, Frankfurt)
- **relay2.simplego.dev** - Secondary server (e.g., different provider, Amsterdam)

Different providers and different jurisdictions maximize the protection against single-point compromise or legal compulsion.

### Server Selection

The client selects which server to use as Relay A (forwarding) and which as Relay B (destination). The selection can be:

- **Random:** Each message picks a random forwarding path
- **Pinned:** A conversation uses a fixed path for consistency
- **Rotated:** The path changes periodically (combined with queue rotation)

GoRelay's recommended default is random selection per-message with periodic path rotation aligned to queue rotation cycles.

### Fallback to Single-Hop

If only one GoRelay server is available, messages are delivered directly without forwarding. This is equivalent to standard SMP operation. The client should warn the user that reduced privacy protection is in effect.

---

*GoRelay - IT and More Systems, Recklinghausen*
