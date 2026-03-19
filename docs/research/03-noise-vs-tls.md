---
title: "Noise Protocol vs TLS 1.3"
sidebar_position: 3
---

# Noise Protocol vs TLS 1.3

*Why GoRelay's GRP protocol uses the Noise Protocol Framework instead of TLS, and what that means for security, performance, and simplicity.*

**Research date:** 2026-03-09 (Session 001)

---

## What is the Noise Protocol Framework?

The Noise Protocol Framework is a public-domain cryptographic framework for building secure channel protocols, created by Trevor Perrin (co-creator of the Signal Protocol). It is not a single protocol but a framework for constructing protocols from a small set of well-understood cryptographic primitives.

Noise powers some of the most security-critical infrastructure in production today: WireGuard (the VPN protocol that replaced IPsec and OpenVPN as the industry standard), WhatsApp's client-server encryption, Slack's Nebula overlay network, Lightning Network's transport, and libp2p (the networking layer for Ethereum and Polkadot).

The complete Noise specification is 35 pages. Compare this to TLS 1.3's 160-page RFC plus dozens of dependency RFCs for X.509, ASN.1, OCSP, and certificate transparency. This difference in complexity is not incidental - it reflects a fundamentally different design philosophy.

---

## How Noise Works

### Handshake Patterns

Noise defines handshake patterns using a compact token notation that describes exactly which keys are exchanged and in what order. Each pattern provides different security properties depending on what the parties know about each other in advance.

The three patterns relevant to GoRelay:

**Noise_IK (primary pattern):** The initiator (client) knows the responder's (server's) static public key in advance. The handshake completes in one round trip with 0-RTT encrypted payloads. The initiator's static key is encrypted in the first message, hidden from passive observers. This is the pattern WireGuard uses (`Noise_IKpsk2`).

```
IK:
  <- s          (server's static key is pre-known to client)
  -> e, es, s, ss  (client sends ephemeral + encrypted static)
  <- e, ee, se     (server sends ephemeral, establishes session)
```

**Noise_XX (fallback pattern):** Neither party needs prior knowledge of the other. Both static keys are encrypted during the handshake - the strongest identity-hiding of any interactive pattern. Completes in 1.5 round trips (3 messages). Best for first-contact scenarios.

```
XX:
  -> e              (client sends ephemeral)
  <- e, ee, s, es   (server sends ephemeral + encrypted static)
  -> s, se          (client sends encrypted static)
```

**Noise_NK (anonymous client):** Server-only authentication with anonymous initiators. The client has no static key to reveal. Useful for anonymous queue creation where the relay authenticates itself but learns nothing about the connecting client.

### Fixed Cipher Suite

A Noise protocol is fully specified by its name string:

```
Noise_IK_25519_ChaChaPoly_BLAKE2s
```

This means: IK handshake pattern, Curve25519 for Diffie-Hellman, ChaCha20-Poly1305 for symmetric encryption, BLAKE2s for hashing. There is no negotiation. The cipher suite is decided at protocol design time and fixed forever for that protocol version.

This is the most important security property Noise provides: **the complete elimination of cipher negotiation**. TLS has spent two decades fighting downgrade attacks (POODLE, FREAK, Logjam, ROBOT) caused by its cipher suite negotiation mechanism. Noise cannot have downgrade attacks because there is nothing to downgrade.

### Symmetric State Machine

Noise protocols operate as a deterministic state machine. Both parties maintain a `SymmetricState` containing a chaining key and an encryption key. Each handshake token (e, s, ee, es, se, ss) performs a DH operation and mixes the result into the symmetric state via HKDF. After the handshake completes, the symmetric state splits into two CipherState objects - one for each direction - that encrypt all subsequent transport messages.

This design means that every DH operation contributes to the final session keys. Compromising one DH exchange does not reveal the session key unless all DH exchanges are compromised. Forward secrecy is mandatory, not optional.

---

## Why Noise Beats TLS for a Relay Server

### Identity Model

TLS uses X.509 certificates signed by Certificate Authorities. The client verifies the server by checking a certificate chain that ultimately roots in a CA it trusts. This requires a PKI infrastructure, certificate issuance, expiry management, revocation checking (OCSP/CRL), and trust in dozens of CA organizations.

SMP already bypasses this model entirely - server identity is a certificate fingerprint embedded in the server address (`smp://<fingerprint>@host`). The CA chain is technically present but functionally irrelevant because the client trusts the specific fingerprint, not the CA hierarchy.

Noise makes this explicit: the server's 32-byte Curve25519 public key IS the identity. No certificates, no CA chain, no expiry, no revocation, no trust hierarchy. The key is the fingerprint. For a relay server where identity is already fingerprint-based, this is a natural fit that eliminates an entire layer of unnecessary complexity.

### Handshake Size

| Protocol | Handshake Size | Round Trips |
|---|---|---|
| TLS 1.3 | 1-4 KB | 1 (with 0-RTT: 0) |
| Noise IK | 96-144 bytes | 1 |
| Noise XX | 144-192 bytes | 1.5 |

Noise handshakes are 10-40x smaller than TLS handshakes. For a relay server handling thousands of connections, this reduces bandwidth and memory pressure on the handshake path.

### Implementation Complexity

| Metric | TLS 1.3 (Go crypto/tls) | Noise (flynn/noise) |
|---|---|---|
| Implementation size | ~15,000+ lines | ~1,500 lines |
| External dependencies | X.509, ASN.1, OCSP | None |
| Configuration surface | Dozens of options | Pattern + cipher suite |
| CVE history | Extensive (OpenSSL, GnuTLS, etc.) | Minimal |

A smaller implementation is easier to audit, easier to understand, and has fewer places for bugs to hide. For security-critical infrastructure, simplicity is a feature.

### Identity Hiding

In TLS 1.3, the server's identity is visible through the Server Name Indication (SNI) extension, which is sent in plaintext during the handshake. Encrypted Client Hello (ECH) addresses this but requires DNS coordination and is not universally deployed.

In Noise XX, both parties' static keys are encrypted during the handshake. A passive observer sees only ephemeral keys and cannot determine who is communicating. In Noise IK, the initiator's identity is encrypted (hidden from passive observers) while the responder's identity is known only to the initiator (who already had the key).

### Deniability

TLS handshakes include digital signatures - the server signs the handshake transcript, creating cryptographic proof that the communication occurred. This is useful for web authentication but undesirable for private messaging.

Noise handshakes use only Diffie-Hellman operations. There are no signatures, and DH is inherently deniable - any party could have generated the shared secret independently. This means a Noise transcript cannot cryptographically prove that a specific communication occurred.

---

## What TLS Does Better

To be fair, TLS has legitimate advantages in certain contexts:

**Ecosystem maturity:** TLS is supported by every programming language, every operating system, every network device. Debugging tools (Wireshark, openssl s_client) are ubiquitous.

**Certificate transparency:** TLS's CA infrastructure provides public auditability of certificate issuance through CT logs. Noise has no equivalent.

**Established trust model:** For web browsers connecting to unknown servers, the CA hierarchy provides a scalable trust model. Noise requires out-of-band key distribution.

**Regulatory compliance:** Some compliance frameworks (PCI-DSS, HIPAA) specifically require TLS. Using Noise may require additional justification.

None of these advantages apply to GoRelay's use case. GoRelay's server identity is already fingerprint-based (making CA trust irrelevant), the client always knows the server's key in advance (making certificate discovery unnecessary), and the protocol is purpose-built (making ecosystem compatibility with web browsers irrelevant).

---

## WireGuard: Proof That Noise Works at Scale

WireGuard is the strongest existence proof that Noise is production-ready for critical infrastructure. Key lessons from WireGuard's design:

**No negotiation, ever.** WireGuard uses exactly one cipher suite: `Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s`. When algorithms need to change, a new protocol version is released. There is no backward-compatible negotiation.

**Silent until authenticated.** WireGuard's server allocates zero state for unauthenticated packets. Port scans see nothing. This is a direct consequence of Noise IK's design - the first message from the client must contain a valid ephemeral key and encrypted static key, or the server silently drops it.

**PSK for post-quantum hedging.** The `psk2` modifier mixes a pre-shared symmetric key into the handshake. Since symmetric cryptography resists quantum attacks, this provides a quantum-resistant layer without requiring post-quantum algorithms. GoRelay extends this further with hybrid X25519 + ML-KEM-768.

**Timer-based rekeying.** WireGuard re-handshakes every few minutes regardless of traffic volume, providing continuous forward secrecy. GoRelay will implement similar periodic rekeying every 2-5 minutes.

**Cryptokey routing.** WireGuard binds public keys to allowed IP ranges, creating a combined routing + authentication table. GoRelay can bind client static keys to authorized queue sets, achieving analogous access control without separate authorization logic.

---

## Go Libraries for Noise

### flynn/noise v1.1.0 (recommended)

The primary Go implementation of Noise. BSD-3 licensed, imported by 165 packages, supports all 12 interactive handshake patterns, PSK modes, rekey operations, and channel binding.

```go
cs := noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2s)
hs, _ := noise.NewHandshakeState(noise.Config{
    CipherSuite:   cs,
    Pattern:       noise.HandshakeIK,
    Initiator:     false,
    StaticKeypair: serverKey,
    PresharedKey:  psk,
    PresharedKeyPlacement: 2,
    Prologue:      []byte("GRP/1"),
})
```

The `Prologue` field is critical - it binds the handshake to a specific protocol identifier. If a client connects expecting "GRP/1" but the server is running "GRP/2", the handshake fails. This provides protocol versioning without negotiation.

### katzenpost/noise (post-quantum extension)

A fork of flynn/noise that adds Hybrid Forward Secrecy with Kyber1024, implementing `Noise_XXhfs_25519+Kyber1024_ChaChaPoly_BLAKE2b`. Licensed AGPL-3.0. The companion `katzenpost/hpqc` library provides X-Wing (X25519 + ML-KEM-768) and other post-quantum primitives.

This is directly relevant for GoRelay's post-quantum transport layer, though we may implement the hybrid extension ourselves using Go 1.24's standard library ML-KEM for maximum auditability.

---

## GRP's Noise Configuration

Based on this analysis, GRP uses the following Noise configuration:

**Primary pattern:** Noise_IK for connections where the client has the server's public key (the common case - key is in the server URI).

**Fallback pattern:** Noise_XX for first-contact scenarios where the server key is not yet known.

**Cipher suite:** Curve25519 + ChaCha20-Poly1305 + BLAKE2s (matching WireGuard).

**Extensions:** Hybrid post-quantum key exchange via X25519 + ML-KEM-768, mixed into the handshake via an additional DH-like operation.

**Protocol identifier:** "GRP/1" as the Prologue, binding the handshake to this specific protocol version.

**Rekeying:** Every 2-5 minutes or every 1000 messages, whichever comes first.

This gives GRP strictly stronger transport security than SMP's TLS 1.3 while being simpler to implement, audit, and maintain.

---

*GoRelay - IT and More Systems, Recklinghausen*
