---
title: "Security Whitespace Analysis"
sidebar_position: 9
---

# Security Whitespace Analysis

*Mapping the gaps in the current encrypted messaging infrastructure landscape and identifying where GoRelay delivers capabilities that no existing system provides.*

**Research date:** 2026-03-09 (Session 001)

---

## What is a Whitespace Analysis?

A whitespace analysis identifies unoccupied spaces in a technology landscape - areas where user needs exist but no current solution adequately addresses them. For encrypted messaging infrastructure, this means finding security properties, deployment models, or use cases that are technically feasible but not yet implemented in any production system.

This document maps the whitespace across eight dimensions and shows where GoRelay fills gaps that the existing ecosystem leaves open.

---

## Dimension 1: Transport-Layer Post-Quantum Protection

### The Gap

End-to-end post-quantum encryption protects message content from future quantum computers. But the transport layer (server connections) typically uses classical TLS with X25519 or ECDH key exchange. An adversary recording TLS traffic today can potentially decrypt it in the future to extract metadata: connection patterns, timing, message sizes (if not padded), and queue identifiers.

Signal has PQC at the end-to-end layer (PQXDH, SPQR) but uses standard TLS for server connections. SimpleX has optional Kyber but not at the transport layer. Matrix has no PQC anywhere. No existing relay server provides mandatory post-quantum protection at the transport layer.

### GoRelay's Position

GRP mandates hybrid X25519 + ML-KEM-768 key exchange in the Noise handshake itself. Every server connection is quantum-resistant from the first byte. This protects not just message content but also the metadata that flows through the transport layer - queue identifiers, subscription events, and delivery confirmations.

**Whitespace filled:** Mandatory transport-layer PQC for relay servers.

---

## Dimension 2: Mandatory Two-Hop Routing

### The Gap

Single-hop relay servers (the default for SimpleX, the only option for Signal and Matrix) expose both sender IP and destination queue to the same server. SimpleX introduced Private Message Routing in v5.8 as an optional feature, but optional security features have consistently low adoption rates across the industry.

No existing relay server makes two-hop routing mandatory by default.

### GoRelay's Position

GRP routes every message through two independent GoRelay servers by default. The client does not need to opt in - two-hop routing is the standard operating mode. Fallback to single-hop occurs only when a second server is genuinely unavailable, and the client is notified of the reduced protection.

**Whitespace filled:** Default-on sender-recipient unlinkability at the relay layer.

---

## Dimension 3: Active Cover Traffic from the Server

### The Gap

Fixed-size message padding (used by SimpleX and planned for most privacy-focused protocols) prevents size-based traffic analysis but does nothing against timing-based analysis. An observer can still determine when a user is actively messaging by watching for bursts of 16 KB blocks.

Tor provides some cover through circuit multiplexing (multiple users share circuits), but this is a side effect of the architecture rather than a deliberate cover traffic mechanism. Nym and Katzenpost implement deliberate cover traffic but require specialized mixnet infrastructure.

No existing relay server generates cover traffic for its connected clients.

### GoRelay's Position

GoRelay's server generates Poisson-distributed dummy messages for each connected client. These dummies are encrypted identically to real messages and delivered through the same channels. A network observer sees a continuous stream of 16 KB blocks and cannot determine which contain real messages and which are dummies.

**Whitespace filled:** Server-generated cover traffic for relay clients without requiring client-side implementation.

---

## Dimension 4: Single-Binary Zero-Dependency Deployment

### The Gap

Deploying encrypted messaging infrastructure currently requires significant operational expertise:

- **SimpleX SMP:** Haskell binary + GHC runtime, amd64 only, complex build process
- **Matrix Synapse:** Python + PostgreSQL + Redis, 4+ GB RAM, extensive configuration
- **Matrix Dendrite:** Go binary but requires PostgreSQL or SQLite with manual setup
- **Signal Server:** Java + FoundationDB + PostgreSQL + Redis + DynamoDB + S3, practically impossible to self-host
- **ejabberd:** Erlang runtime + database
- **Cwtch:** Requires Tor

The gap between "I want to run my own relay server" and "I have a running relay server" is hours to days for most existing systems.

### GoRelay's Position

GoRelay compiles to a single static binary under 20 MB with zero runtime dependencies. The setup process:

```
./gorelay init    # generates keys and default config
./gorelay start   # starts the server
```

No database to install, no runtime to configure, no container orchestration needed. The embedded BadgerDB handles persistence automatically. Cross-compilation to ARM means the same binary runs on a $35 Raspberry Pi.

**Whitespace filled:** Encrypted relay server deployable in under 5 minutes by a single person with no infrastructure expertise.

---

## Dimension 5: Audited Cryptography with FIPS Validation

### The Gap

The cryptographic libraries underlying most encrypted messaging servers have never received independent security audits:

- **Haskell (cryptonite/crypton, hs-tls):** No independent audit
- **Erlang (crypto module):** Wraps OpenSSL (audited) but the Erlang bindings are not independently audited
- **Python (cryptography):** The Python bindings are audited but rely on OpenSSL/BoringSSL
- **Cwtch:** No audit of the Go crypto usage

Signal's client-side cryptography has been audited multiple times, but the server-side crypto is standard Java TLS.

The gap is that server operators must trust unaudited cryptographic implementations for the relay infrastructure that handles their users' encrypted traffic.

### GoRelay's Position

Go's cryptographic standard library received a comprehensive Trail of Bits audit in 2025 - three engineers, one month, covering all major algorithms including ML-KEM. Result: one low-severity finding in a legacy module. The library is pursuing FIPS 140-3 certification (CAVP certificate A6650).

GoRelay uses exclusively the Go standard library for cryptography (plus flynn/noise for the Noise Protocol framework, which is 1,500 lines of auditable code). No OpenSSL, no FFI to C libraries, no unaudited dependencies.

**Whitespace filled:** Relay server built entirely on independently audited, FIPS-track cryptographic primitives.

---

## Dimension 6: IoT-Ready Encrypted Relay

### The Gap

Existing encrypted messaging infrastructure is designed for human-to-human communication on smartphones and computers. IoT devices (sensors, monitors, controllers) have fundamentally different requirements:

- **Unidirectional data flow:** A temperature sensor sends readings; it does not receive replies
- **High-frequency small payloads:** Sensor data every few seconds, not sporadic text messages
- **Constrained hardware:** Limited CPU, memory, and bandwidth
- **No user interaction:** Devices operate autonomously without human intervention
- **Long deployment lifetimes:** IoT devices may run for years without firmware updates

No existing encrypted relay server is designed to handle IoT traffic patterns. SimpleX's SMP protocol could theoretically work (it already supports unidirectional queues) but the client-side library assumptions (mobile app, user interaction, group management) do not match IoT requirements.

### GoRelay's Position

GoRelay is designed as part of the SimpleGo ecosystem, which includes hardware devices (ESP32-based) communicating via SMP. The server is already optimized for constrained client devices. GRP extensions for IoT include:

- **Unidirectional queue mode:** No reply queue created for sensor-to-monitor communication
- **Optimized for high-frequency small payloads:** Efficient batching within 16 KB blocks
- **Minimal handshake overhead:** Noise IK completes in one round trip
- **Configurable cover traffic:** IoT deployments can reduce or disable cover traffic to save bandwidth

Medical monitoring (encrypted patient data from bedside devices to nursing stations), industrial sensing (encrypted telemetry from factory sensors to control systems), and smart building infrastructure (encrypted commands between building management systems) are all target use cases.

**Whitespace filled:** Encrypted relay infrastructure designed for IoT from day one, not retrofitted from a messaging app.

---

## Dimension 7: Protocol Specification Separate from Implementation

### The Gap

Most encrypted messaging protocols are defined by their implementation rather than by a formal specification:

- **Signal Protocol:** Documented in academic papers and technical docs, but the specification is tied to Signal's implementation decisions
- **Matrix:** Has a formal specification (spec.matrix.org) but it is enormous (hundreds of pages) and tightly coupled to the Synapse/Dendrite architecture
- **SimpleX SMP:** Documented in GitHub markdown with ABNF grammar, but evolves with the Haskell implementation

The gap is a clean, compact protocol specification (like Noise or WireGuard) that can be implemented independently by anyone without reverse-engineering an existing codebase.

### GoRelay's Position

GRP is being specified as a formal document before implementation begins, following the Noise specification's structure: threat model, cryptographic primitives with justifications, state machine definitions, byte-level message formats, test vectors, and a dedicated rationale section explaining rejected alternatives.

The specification is designed so that a competent developer can implement a GRP-compatible server or client from the specification alone, without reading GoRelay's source code.

**Whitespace filled:** Compact, independently implementable protocol specification for a post-quantum encrypted relay.

---

## Dimension 8: Honest Security Communication

### The Gap

The encrypted messaging space suffers from security theater - marketing claims that do not match technical reality:

- "Military-grade encryption" (meaningless - AES-256 is used by everyone)
- "Zero-knowledge" (often used incorrectly - the server may not read messages but still logs metadata)
- "Quantum-resistant" (often means optional PQC that 1% of users enable)
- "No backdoors" (unfalsifiable claim without published source code and reproducible builds)

Users cannot make informed decisions about their security when marketing obscures technical limitations.

### GoRelay's Position

GoRelay's documentation explicitly states what is protected and what is not. The threat model document identifies specific adversary capabilities and honestly describes the limitations of each defense mechanism:

- Cover traffic makes timing analysis more difficult but does not provably prevent it against a global adversary
- Two-hop routing prevents single-server metadata correlation but not both-server compromise
- Post-quantum key exchange protects against future quantum computers but Ed25519 signatures remain classically vulnerable until GRP version 2
- The server cannot read message content but can observe connection patterns if logging were enabled (it is disabled by default but trust in the operator is required)

**Whitespace filled:** Transparent, technically honest security documentation that enables informed trust decisions.

---

## Combined Whitespace Map

| Dimension | SimpleX | Matrix | Signal | Cwtch | GoRelay |
|---|---|---|---|---|---|
| Transport PQC | No | No | No | No | **Mandatory** |
| Default two-hop | Optional | No | No | Via Tor | **Mandatory** |
| Server cover traffic | No | No | No | Via Tor | **Yes** |
| Single-binary deploy | Partial | No | No | Partial | **Yes** |
| Audited crypto | No | Partial | Client only | No | **Yes (stdlib)** |
| IoT-ready | No | No | No | No | **Yes** |
| Independent spec | Partial | Yes (large) | Partial | No | **Yes (compact)** |
| Honest security docs | Good | Good | Good | Good | **Explicit** |

GoRelay fills all eight whitespace dimensions. No other system fills more than three.

---

## Strategic Implications

The whitespace analysis reveals that GoRelay is not competing directly with any existing system. It occupies a genuinely new position in the landscape:

- It is not a SimpleX replacement (it maintains SMP compatibility)
- It is not a Matrix alternative (it does not provide collaboration features)
- It is not a Signal competitor (it does not provide a consumer messaging app)
- It is not a Tor replacement (it does not provide network-layer anonymity)

GoRelay is encrypted relay infrastructure - a building block for secure communication systems. SimpleGo devices use it. SimpleX apps can use it. Future IoT platforms can use it. The value proposition is the relay layer itself, not the application built on top of it.

This positioning avoids the zero-sum competition that plagues the messaging space ("switch from X to Y") and instead creates additive value: GoRelay makes every compatible client more secure by providing a better relay option.

---

*GoRelay - IT and More Systems, Recklinghausen*
