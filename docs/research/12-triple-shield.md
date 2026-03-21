---
title: "Triple Shield Architecture"
sidebar_position: 12
---

# Triple Shield Architecture

*Combining Zero-Knowledge Proofs, Shamir's Secret Sharing, and Steganographic Transport into a sixth defense layer that makes GoRelay the most heavily fortified messaging relay ever designed.*

**Research date:** 2026-03-21 (Session 002)
**Status:** Planned (Phase 6)

---

## Overview

GoRelay's core architecture provides five encryption and defense layers on every message. Triple Shield adds a sixth composite layer consisting of three independent mechanisms that operate at different levels of the communication stack:

| Component | Level | Protects Against |
|---|---|---|
| Zero-Knowledge Proofs | Authentication | Server learning client identity from queue access patterns |
| Shamir's Secret Sharing | Storage/Transport | Any single server possessing a complete message (even encrypted) |
| Steganographic Transport | Network | Deep packet inspection identifying GoRelay traffic |

Combined, these three mechanisms address the remaining attack surfaces that encrypted transport and end-to-end encryption cannot cover.

---

## Current Defense Layers (1-5)

Before Triple Shield, a GoRelay message passes through five layers:

```
Layer 1: End-to-End Double Ratchet (client to client)
Layer 2: Sender-to-Destination Encryption (s2d, per-message ephemeral key)
Layer 3: Forwarding-to-Destination Encryption (f2d, relay to relay)
Layer 4: Noise Transport with hybrid PQC (each network hop)
Layer 5: Per-Message Storage Encryption with Cryptographic Deletion
```

These layers protect message content comprehensively. An attacker who compromises any single layer gains nothing because the other four remain intact.

Triple Shield adds three more mechanisms that protect against attacks the first five layers cannot address:

```
Layer 6a: Zero-Knowledge Queue Authentication
Layer 6b: Shamir's Secret Sharing across multiple servers
Layer 6c: Steganographic Transport Obfuscation
```

---

## Layer 6a: Zero-Knowledge Queue Authentication

### The Problem

Currently, a client proves queue ownership by presenting an Ed25519 signature. The server verifies the signature against the stored public key. This works, but the server learns the public key associated with each queue access. Over time, a compromised server could correlate access patterns by public key - even if it cannot read messages.

### The Solution

With Zero-Knowledge Proofs (ZKPs), the client proves possession of the private key WITHOUT revealing the public key or the signature to the server. The server learns exactly one bit of information: "this client has the right key" or "this client does not."

```
Current flow:
  Client: "Here is my signature over this challenge"
  Server: Checks signature against stored public key
  Server learns: which public key accessed which queue

ZKP flow:
  Client: "I can prove I know the key, without showing it"
  Server: Verifies the proof
  Server learns: "someone with the right key accessed this queue"
  Server does NOT learn: which key, any linkable identifier
```

### Candidate Protocols

**Schnorr DLOG Proof:** The simplest ZKP for proving knowledge of a discrete logarithm (private key). Non-interactive via Fiat-Shamir heuristic. Approximately 64 bytes proof size, sub-millisecond verification. Can be built from existing Ed25519 primitives.

**Bulletproofs:** More general ZKP system that can prove arbitrary statements about committed values. Larger proofs (~700 bytes) but more flexible. Could prove complex access policies without revealing which policy applies.

**zk-SNARKs/zk-STARKs:** Maximum flexibility and minimum proof size, but massive computational overhead for proof generation. Overkill for simple key possession proofs. Better suited for complex multi-party computations.

**Recommended for GRP/2:** Schnorr DLOG Proof via Fiat-Shamir. Minimal overhead, well-understood security, compatible with existing key infrastructure. Upgrade path to Bulletproofs if more complex access policies are needed later.

### Impact on Metadata

Without ZKP, a compromised server can build a table:

```
Public Key A accessed queues: Q1, Q4, Q7
Public Key B accessed queues: Q2, Q5
Public Key C accessed queues: Q3, Q6, Q8, Q9
```

This reveals how many queues each key manages (proxy for how many contacts a user has).

With ZKP, the server sees:

```
Valid proof -> queue Q1 accessed
Valid proof -> queue Q2 accessed
Valid proof -> queue Q3 accessed
```

No linkage between accesses. No public keys visible. No way to determine if Q1 and Q4 belong to the same user.

---

## Layer 6b: Shamir's Secret Sharing

### The Problem

Even with end-to-end encryption, a complete encrypted message blob exists on one server. If that server is seized, the adversary has the ciphertext. They cannot read it today, but they can store it indefinitely waiting for cryptographic advances (quantum computers, mathematical breakthroughs, implementation flaws discovered later).

### The Solution

Shamir's Secret Sharing (SSS) splits data into N shares such that any K shares can reconstruct the original, but K-1 shares reveal absolutely nothing - not even a single bit of the original data. This is information-theoretically secure, meaning it cannot be broken even with unlimited computational power.

GoRelay splits each encrypted message into shares distributed across multiple servers:

```
Encrypted Message (e2e encrypted blob)
    |
    Shamir Split (K=2, N=3)
    |
    +---> Share 1 ---> [GoRelay Server A]
    |
    +---> Share 2 ---> [GoRelay Server B]
    |
    +---> Share 3 ---> [GoRelay Server C]

Recipient collects any 2 of 3 shares -> reconstructs encrypted blob -> decrypts with Double Ratchet
```

### Why This Matters

**Server seizure resistance:** Law enforcement seizes Server A. They get Share 1. It is mathematically proven to contain zero information about the original message without a second share. The seizure is completely useless.

**Compromise resilience:** An attacker hacks Server B. They get Share 2. Same result - zero information without another share. They would need to simultaneously compromise two of the three servers.

**No single point of trust:** No single server operator can be coerced or bribed into revealing message content, because no single server HAS the content.

### Implementation

Shamir's Secret Sharing operates over a finite field (typically GF(256) for byte-level sharing):

```go
// Split a secret into N shares requiring K to reconstruct
func Split(secret []byte, k, n int) ([]Share, error) {
    shares := make([]Share, n)
    for i, b := range secret {
        // For each byte, create a random polynomial of degree k-1
        // where the constant term is the secret byte
        coefficients := make([]byte, k)
        coefficients[0] = b
        rand.Read(coefficients[1:])

        // Evaluate polynomial at n different points
        for j := 0; j < n; j++ {
            x := byte(j + 1) // x = 1, 2, 3, ...
            shares[j].Data = append(shares[j].Data, evaluatePolynomial(coefficients, x))
            shares[j].X = x
        }
    }
    return shares, nil
}

// Reconstruct secret from k or more shares using Lagrange interpolation
func Reconstruct(shares []Share) ([]byte, error) {
    // Lagrange interpolation at x=0 recovers the constant term (secret)
    // ...
}
```

### Share Size

Each share is exactly the same size as the original secret. For a 16 KB encrypted message block:

- Original: 16,384 bytes
- Share 1: 16,384 bytes
- Share 2: 16,384 bytes  
- Share 3: 16,384 bytes

Total storage: 3x the original. Total bandwidth: 3x for sending, 2x for receiving (only K shares needed).

This 3x overhead is acceptable for messaging volumes. At 100 messages per hour, the additional storage is approximately 3 MB per hour per server - trivial.

### Threshold Configurations

| Configuration | Shares (N) | Threshold (K) | Servers Needed | Fault Tolerance |
|---|---|---|---|---|
| 2-of-3 | 3 | 2 | 3 | 1 server can be down or seized |
| 3-of-5 | 5 | 3 | 5 | 2 servers can be down or seized |
| 2-of-2 | 2 | 2 | 2 | No fault tolerance (both needed) |

Recommended default: **2-of-3** - provides seizure resistance with one server of fault tolerance.

---

## Layer 6c: Steganographic Transport

### The Problem

Even with encrypted content, cover traffic, and two-hop routing, the CONNECTION to a GoRelay server is visible. A network observer (ISP, firewall, DPI system) can see:

- Client IP connects to GoRelay server IP on port 7443
- Traffic pattern: consistent 16 KB blocks (distinctive)
- TLS/Noise handshake fingerprint (identifiable)

In censorship-heavy environments (China, Iran, Russia), this is sufficient to block GoRelay traffic entirely.

### The Solution

Steganographic transport makes GoRelay traffic look like something else. The encrypted blocks are wrapped in a protocol that mimics legitimate, common traffic:

**HTTPS Mimicry:** GoRelay traffic appears as normal HTTPS web browsing. The 16 KB blocks are wrapped in HTTP/2 frames with realistic headers, cookies, and content types. A DPI system sees what looks like someone browsing a website.

**Domain Fronting:** The TLS SNI shows a benign domain (e.g., a CDN), but the HTTP Host header inside the encrypted connection routes to GoRelay. The censor would have to block the entire CDN to block GoRelay.

**WebSocket Tunnel:** GoRelay traffic flows over a WebSocket connection that looks like a web application. Many real-time web apps use WebSockets - chat widgets, stock tickers, collaborative editors.

### Implementation Approach

```
Normal GRP connection:
  Client -> [Noise Handshake] -> [16 KB blocks] -> Server

Steganographic GRP connection:
  Client -> [TLS to CDN] -> [WebSocket Upgrade] -> [Noise inside WebSocket] -> [16 KB blocks inside WS frames] -> Server
```

The Noise handshake and 16 KB block protocol run INSIDE the steganographic wrapper. From the network perspective, it is a standard HTTPS WebSocket connection to a CDN endpoint.

### Pluggable Transports

GoRelay adopts the Pluggable Transports framework (originally developed for Tor) to support multiple steganographic methods:

```yaml
transport:
  type: "websocket"          # or "https", "meek", "obfs4"
  endpoint: "cdn.example.com"
  path: "/ws/updates"
```

Each transport plugin wraps and unwraps GRP traffic in a different disguise. New transports can be added without changing the core protocol.

### Existing Libraries

**obfs4 (Tor Project):** The most battle-tested pluggable transport. Makes traffic look like random noise. Deployed by millions of Tor users in censored countries.

**meek (Tor Project):** Domain fronting via CDN providers. Traffic appears to go to a CDN, actually reaches GoRelay.

**Snowflake (Tor Project):** Uses WebRTC to make traffic look like video calls. Extremely hard to block without blocking all video conferencing.

These are Go-native implementations that can be integrated directly into GoRelay.

---

## Combined Triple Shield Flow

A single message with all three components active:

```
1. Client wants to send a message to a queue

2. [ZKP Authentication]
   Client generates a zero-knowledge proof of queue access
   Server verifies proof without learning the client's key
   
3. [Message Preparation]
   Client encrypts message (Double Ratchet, e2e)
   Client encrypts with s2d layer (destination metadata)

4. [Shamir Split]
   Client splits the encrypted message into 3 shares (2-of-3)
   
5. [Triple Delivery via Steganographic Transport]
   Share 1 -> [Stego Wrap: HTTPS] -> Relay A1 -> Relay B1 -> Server 1
   Share 2 -> [Stego Wrap: WebSocket] -> Relay A2 -> Relay B2 -> Server 2
   Share 3 -> [Stego Wrap: meek/CDN] -> Relay A3 -> Relay B3 -> Server 3
   
   Each share goes through a DIFFERENT two-hop path
   Each share uses a DIFFERENT steganographic transport
   
6. [Recipient Reconstruction]
   Recipient collects Share 1 from Server 1 (via stego transport)
   Recipient collects Share 2 from Server 2 (via stego transport)
   Recipient reconstructs encrypted blob (Shamir reconstruct)
   Recipient decrypts (Double Ratchet)
```

### What an attacker needs to defeat this:

1. Break end-to-end Double Ratchet encryption
2. Break sender-to-destination encryption
3. Break forwarding-to-destination encryption
4. Break Noise + ML-KEM-768 transport on multiple hops
5. Break per-message storage encryption
6. Identify the traffic as GoRelay despite steganographic wrapping
7. Compromise at least 2 of 3 servers simultaneously to get enough Shamir shares
8. Link the queue access to a specific user despite zero-knowledge authentication

**All eight must succeed simultaneously.** Failure at any single point leaves the attacker with nothing.

---

## Performance Impact

| Component | Overhead | Latency Impact |
|---|---|---|
| ZKP (Schnorr proof) | ~100 bytes per auth, ~0.5 ms | Negligible |
| Shamir (2-of-3) | 3x storage, 3x send bandwidth, 2x receive | 1-2 extra hops latency |
| Steganography (WebSocket) | ~5% bandwidth overhead for framing | ~1-5 ms for wrapping |

Total additional latency for a Triple Shield message: approximately 10-50 ms depending on server locations. For a messaging application, this is imperceptible.

The bandwidth overhead (3x for Shamir) is the most significant cost. For a server handling 100 active users at 10 messages per hour, this means approximately 5 GB additional storage per day distributed across 3 servers - well within commodity VPS capabilities.

---

## Deployment Modes

Triple Shield is modular - each component can be enabled independently:

| Mode | ZKP | Shamir | Stego | Use Case |
|---|---|---|---|---|
| Standard GRP | No | No | No | Normal messaging |
| Enhanced Privacy | Yes | No | No | Maximum metadata protection |
| Seizure Resistant | No | Yes | No | Protection against server seizure |
| Censorship Resistant | No | No | Yes | Bypassing network censorship |
| Full Triple Shield | Yes | Yes | Yes | Maximum security (all three) |

This allows deployment flexibility. A journalist in a censored country enables Stego. A medical provider enables Shamir for compliance. A whistleblower enables all three.

---

## Implementation Roadmap

| Phase | Component | Dependencies | Estimated Complexity |
|---|---|---|---|
| 6a | Zero-Knowledge Queue Auth | Ed25519 key infrastructure | Medium |
| 6b | Shamir's Secret Sharing | Multi-server discovery | High |
| 6c | Steganographic Transport | Pluggable transport framework | High |
| 6d | Triple Shield Integration | All three components | Medium |

Each component is independently useful and independently deployable. Phase 6a is the simplest starting point. Phase 6b requires the most architectural work (multi-server coordination). Phase 6c can leverage existing Tor pluggable transport libraries.

---

## Competitive Position

No existing messaging system combines these three mechanisms:

| System | ZKP Auth | Secret Sharing | Stego Transport |
|---|---|---|---|
| Signal | No | No | No |
| SimpleX | No | No | No (Tor optional) |
| Matrix | No | No | No |
| Cwtch | No | No | Via Tor |
| Briar | No | No | Via Tor |
| **GoRelay (Phase 6)** | **Yes** | **Yes** | **Yes** |

GoRelay with Triple Shield would be the first messaging relay to provide all three. Combined with the existing five layers, it creates an eight-layer defense system unprecedented in encrypted communications.

---

*GoRelay - IT and More Systems, Recklinghausen*
