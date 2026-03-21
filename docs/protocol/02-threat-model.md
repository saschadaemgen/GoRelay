---
title: "Threat Model"
sidebar_position: 2
---

# GRP Protocol Specification: Threat Model

*Defines the adversary capabilities GRP protects against, the trust assumptions the protocol makes, and the explicit limitations of each defense mechanism.*

**Version:** GRP/1 (Draft)
**Status:** In development
**Date:** 2026-03-09

---

## Design Principle

GRP's threat model follows a simple rule: assume the worst plausible adversary and design defenses that degrade gracefully rather than failing catastrophically. Every defense has explicit limitations that are documented here rather than hidden behind marketing language.

---

## Protected Properties

GRP aims to protect the following properties for communicating parties:

### Message Confidentiality

**Definition:** Only the intended sender and recipient can read message content.

**How GRP protects it:** End-to-end encryption using Double Ratchet with per-message ephemeral keys. The relay server never possesses decryption keys and cannot read message content at any point during processing. Transport encryption (Noise + hybrid PQC) protects messages in transit even if the e2e layer were somehow compromised.

**Limitation:** If the sender or recipient device is compromised (malware, physical access), message confidentiality is lost. GRP cannot protect against endpoint compromise.

### Message Integrity

**Definition:** Messages cannot be modified in transit without detection.

**How GRP protects it:** AEAD encryption (ChaCha20-Poly1305) at both the transport and e2e layers. Any modification to the ciphertext causes authentication failure and message rejection. The Double Ratchet's chain of message authentication codes ensures ordering integrity.

**Limitation:** A compromised server could drop messages (denial of service) or replay old messages. GRP detects replays through sequence numbers and the ratchet state, but cannot prevent message dropping.

### Forward Secrecy

**Definition:** Compromise of long-term keys does not reveal past message content.

**How GRP protects it:** Full Double Ratchet on every message. Each message uses a unique ephemeral key derived from the ratchet state. Compromising the current ratchet state reveals only messages from the current ratchet epoch (typically one message). Past ratchet keys are deleted after use.

**Limitation:** If an adversary records all ciphertext AND compromises the ratchet state at a specific point, they can decrypt messages from that point forward until the next DH ratchet step. They cannot decrypt messages from before the compromise.

### Post-Compromise Security

**Definition:** After a temporary key compromise, the protocol self-heals and future messages become secure again.

**How GRP protects it:** The Double Ratchet's DH ratchet step introduces fresh entropy with each message exchange. After a compromise, the next DH ratchet step re-establishes security because the adversary does not know the new ephemeral DH private key.

**Limitation:** Messages sent between the compromise and the next DH ratchet step are exposed. The protocol heals automatically but not instantaneously.

### Sender-Recipient Unlinkability

**Definition:** The relay server cannot determine which sender is communicating with which recipient.

**How GRP protects it:** Unidirectional queues with uncorrelated sender and recipient IDs. Two-hop relay routing where the forwarding server sees the sender IP but not the destination, and the destination server sees the queue but not the sender. Server-side re-encryption prevents ciphertext correlation.

**Limitation:** A single adversary controlling both relay servers in a two-hop path can correlate sender and recipient. Queue rotation mitigates long-term correlation but does not prevent real-time correlation by a dual-server adversary.

### Traffic Analysis Resistance

**Definition:** A network observer cannot determine when, how often, or whether a user is actively communicating.

**How GRP protects it:** Fixed 16 KB block framing (all messages are the same size). Server-generated Poisson cover traffic (dummy messages indistinguishable from real ones). Automatic queue rotation (queue identifiers change periodically).

**Limitation:** A global adversary monitoring all network links simultaneously can perform statistical correlation over extended observation periods. Cover traffic raises the cost of analysis but does not make it provably impossible. See "The Anonymity Trilemma" in the Cover Traffic research document.

### Quantum Resistance

**Definition:** The protocol remains secure against adversaries with access to cryptanalytically relevant quantum computers.

**How GRP protects it:** Hybrid X25519 + ML-KEM-768 key exchange at the transport layer. Both classical and post-quantum key exchanges must be broken simultaneously to compromise the session. Symmetric encryption (ChaCha20-Poly1305) and hashing (BLAKE2s, SHA-256) are inherently quantum-resistant.

**Limitation:** Ed25519 signatures used for queue authorization are not quantum-resistant. An adversary with a quantum computer could forge queue commands. This is addressed in GRP/2 with ML-DSA-65 signatures. The confidentiality of message content is not affected because it relies on symmetric encryption derived from the hybrid key exchange.

---

## Adversary Model

GRP defines four adversary classes with increasing capabilities:

### Class 1: Passive Network Observer

**Capabilities:** Can observe all network traffic on one or more links. Cannot modify traffic. Cannot compromise servers or endpoints. Examples: ISP, coffee shop WiFi operator, backbone tap.

**What they see:** Encrypted 16 KB blocks, connection timing, IP addresses of connecting clients, server IP addresses.

**What GRP prevents:** Reading message content (transport + e2e encryption). Determining message size (fixed-size blocks). Distinguishing real from dummy messages (cover traffic). Linking sender IP to destination queue (two-hop routing).

**What GRP does not prevent:** Observing that a client is connected to a GoRelay server. Estimating connection duration. Over long periods, statistical correlation of traffic patterns between two observed links.

### Class 2: Active Network Attacker

**Capabilities:** Everything in Class 1, plus the ability to modify, drop, delay, replay, or inject network traffic. Examples: state-level adversary, compromised router, BGP hijack.

**What GRP prevents:** Content modification (AEAD authentication). Connection hijacking (Noise handshake authentication). Downgrade attacks (fixed cipher suite, no negotiation). Replay attacks (sequence numbers, ratchet state). Server impersonation (static key verification).

**What GRP does not prevent:** Denial of service (dropping all traffic). Selective dropping of specific connections based on IP or timing. Forcing fallback to single-hop routing by blocking relay-to-relay connections.

### Class 3: Compromised Single Server

**Capabilities:** Full access to one GoRelay server - memory, disk, configuration, keys. Can read all data on the server, modify server behavior, and observe all connections. Examples: server breach, malicious hosting provider, seized server, insider threat.

**What GRP prevents:** Reading message content (e2e encrypted, server has no e2e keys). Linking sender to recipient (two-hop routing - compromised server sees only one side). Accessing historical messages (messages deleted on ACK, cryptographic deletion).

**What GRP does not prevent:** Identifying currently connected clients by IP (the compromised server sees connections). Dropping or delaying messages for connected clients. Disabling cover traffic for connected clients. If the compromised server is the only server (single-hop fallback), the adversary sees both sender IP and destination queue.

### Class 4: Compromised Dual Server

**Capabilities:** Full access to both relay servers in a two-hop path simultaneously.

**What GRP prevents:** Reading message content (e2e encryption is independent of server trust). Accessing historical messages (deletion + cryptographic deletion).

**What GRP does not prevent:** Correlating sender IP (from Relay A) with destination queue (from Relay B) in real time. Building a complete metadata picture of who communicates with whom. This is the strongest adversary that GRP's relay architecture cannot fully defend against.

**Mitigation:** Use servers operated by different entities in different legal jurisdictions. Periodically rotate which servers are used for which conversations. The probability of simultaneous compromise decreases with operational diversity.

### Beyond Class 4: Endpoint Compromise

If the sender or recipient device is compromised, no relay protocol can protect message content. The adversary reads messages directly on the device before encryption or after decryption. GRP's threat model explicitly excludes endpoint security - that is the responsibility of the operating system, hardware (Secure Elements in SimpleGo), and user behavior.

---

## Trust Assumptions

GRP makes the following explicit trust assumptions:

### The Client Software is Correct

GRP assumes the client correctly implements the protocol - proper key generation, correct ratchet advancement, honest handling of cover traffic flags. A malicious client could undermine its own security (e.g., by leaking keys or ignoring cover traffic).

### At Least One Relay Server is Honest

For two-hop routing to provide sender-recipient unlinkability, at least one of the two relay servers must not be actively colluding with an adversary. If both servers are compromised, metadata protection degrades to single-hop level.

### The Cryptographic Primitives are Sound

GRP assumes that X25519, ML-KEM-768, ChaCha20-Poly1305, BLAKE2s, HKDF-SHA-256, and Ed25519 are cryptographically secure. A break in any of these would impact specific protocol properties:

| Primitive Broken | Impact |
|---|---|
| X25519 | Hybrid key exchange still protected by ML-KEM-768 |
| ML-KEM-768 | Hybrid key exchange still protected by X25519 |
| Both X25519 and ML-KEM-768 | Transport key exchange compromised, e2e keys exposed |
| ChaCha20-Poly1305 | All encrypted data readable |
| BLAKE2s | Noise handshake integrity compromised |
| Ed25519 | Queue authorization forgeable (not message content) |
| HKDF-SHA-256 | Key derivation compromised, all derived keys exposed |

The hybrid key exchange means that two independent primitive breaks are required to compromise the transport layer. This is the primary benefit of the hybrid approach.

### Random Number Generation is Reliable

GRP relies on cryptographically secure random number generation for key generation, nonce generation, ephemeral keys, queue IDs, and cover traffic timing. A compromised CSPRNG would undermine nearly every security property.

Go's `crypto/rand` reads from the operating system's entropy source (`/dev/urandom` on Linux, `CryptGenRandom` on Windows). The FIPS 140-3 module includes DRBG (Deterministic Random Bit Generator) validation.

### Clocks are Approximately Synchronized

Queue rotation, message TTL, and cover traffic timing assume that server and client clocks are within a few minutes of each other. Significant clock skew could cause premature message expiry or incorrect rotation timing. This is a standard assumption for any networked protocol and is satisfied by NTP on virtually all modern systems.

---

## Non-Goals

GRP explicitly does not aim to provide:

**Network-layer anonymity.** GRP does not hide the fact that a client is connecting to a GoRelay server. An ISP can see the connection. For network-layer anonymity, use Tor or a VPN as an additional layer beneath GRP.

**Plausible deniability of communication.** While Noise handshakes are deniable (no signatures), the existence of queue records on the server proves that communication infrastructure was established. GRP does not claim to provide deniability of the fact that communication occurred.

**Protection against device seizure.** If a device is physically seized and the attacker can unlock it or extract keys, GRP provides no protection. This is the domain of device security (full-disk encryption, Secure Elements, tamper detection) not relay protocol design.

**Protection against social engineering.** If a user is tricked into revealing their keys, sharing their screen, or installing malware, GRP cannot help. Protocol security assumes rational use by informed participants.

**Censorship resistance.** GRP does not include mechanisms to bypass network-level blocking of GoRelay servers. If a firewall blocks port 7443 or the server's IP address, GRP connections fail. For censorship resistance, use Tor bridges or domain fronting as a transport layer beneath GRP.

---

## Comparison with SMP Threat Model

| Threat | SMP (single-hop) | GRP (two-hop) |
|---|---|---|
| Passive network observer reads content | Protected | Protected |
| Server reads content | Protected | Protected |
| Server links sender to recipient | NOT protected | Protected (two-hop) |
| Network observer determines message timing | Padding only | Cover traffic + padding |
| Future quantum computer decrypts recorded traffic | NOT protected (classical TLS) | Protected (hybrid PQC) |
| Server compromise reveals historical messages | Partial (configurable retention) | Protected (ACK delete + crypto delete + 7d max) |
| Active network attacker downgrades cipher | Protected (TLS 1.3 only) | Protected (fixed suite, no negotiation) |

---

## Threat Model Updates

This threat model will be updated as new attack research is published and as GRP evolves. Specific areas under active monitoring:

- **Lattice-based cryptanalysis:** New attacks on ML-KEM could weaken the post-quantum component. The hybrid approach provides a fallback.
- **Traffic analysis techniques:** New statistical methods for de-anonymizing cover traffic. The cover traffic parameters may be adjusted.
- **Side-channel attacks on Go runtime:** GC pauses, timing variations, or memory access patterns that could leak information. Go's constant-time crypto implementations mitigate but may not eliminate all side channels.
- **Quantum computing timelines:** If cryptanalytically relevant quantum computers arrive sooner than expected, GRP/2's ML-DSA signatures become urgent.

---

*GoRelay Protocol Specification - IT and More Systems, Recklinghausen*
