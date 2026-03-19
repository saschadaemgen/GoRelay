---
title: "Post-Quantum Cryptography Landscape"
sidebar_position: 4
---

# Post-Quantum Cryptography Landscape

*The current state of post-quantum cryptography, why it matters now, and how GoRelay implements mandatory quantum resistance.*

**Research date:** 2026-03-09 (Session 001)

---

## Why Post-Quantum Matters Today

Quantum computers capable of breaking current public-key cryptography do not exist yet. But the threat is not hypothetical - it is a matter of timeline. The NSA, GCHQ, and other intelligence agencies are widely believed to practice "harvest now, decrypt later" - recording encrypted communications today with the expectation of decrypting them when quantum computers become available.

For a messaging relay server, this means that every key exchange performed today using classical Diffie-Hellman could potentially be broken in the future. The messages themselves use symmetric encryption (which is quantum-resistant), but if an attacker recorded the key exchange, they can derive the symmetric keys and decrypt everything.

This is why post-quantum cryptography at the transport layer - not just end-to-end - is immediately relevant. GoRelay's GRP protocol makes it mandatory.

---

## NIST Standardization: Complete

The National Institute of Standards and Technology (NIST) began its Post-Quantum Cryptography Standardization Process in 2016. After eight years of evaluation, the first three standards were finalized on August 13, 2024:

**FIPS 203 - ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism):** Derived from CRYSTALS-Kyber. This is the primary standard for key encapsulation - the quantum-resistant replacement for Diffie-Hellman key exchange. Three parameter sets: ML-KEM-512 (AES-128 equivalent), ML-KEM-768 (AES-192 equivalent), and ML-KEM-1024 (AES-256 equivalent).

**FIPS 204 - ML-DSA (Module-Lattice-Based Digital Signature Algorithm):** Derived from CRYSTALS-Dilithium. The primary standard for digital signatures - the quantum-resistant replacement for ECDSA and Ed25519.

**FIPS 205 - SLH-DSA (Stateless Hash-Based Digital Signature Algorithm):** Derived from SPHINCS+. A backup digital signature standard based on hash functions rather than lattices, providing algorithmic diversity.

Additional standards in progress: FN-DSA (derived from FALCON, draft submitted August 2025) and HQC (code-based KEM selected March 2025 as a non-lattice backup for ML-KEM).

Government timelines mandate PQC preference by 2025-2026 and exclusive use by 2030-2035.

---

## ML-KEM-768: GoRelay's Choice

GoRelay uses ML-KEM-768 for its post-quantum key exchange. Here is why this specific parameter set was chosen:

### Security Level

ML-KEM-768 targets NIST Security Level 3, approximately equivalent to AES-192. This provides a comfortable security margin above the minimum (Level 1/AES-128) without the performance cost of Level 5 (AES-256). For a messaging relay where key exchanges happen once per connection (not millions of times per second), even Level 5 would be feasible, but 768 offers the best balance.

### Key and Ciphertext Sizes

| Parameter | ML-KEM-512 | ML-KEM-768 | ML-KEM-1024 |
|---|---|---|---|
| Encapsulation key | 800 bytes | 1,184 bytes | 1,568 bytes |
| Ciphertext | 768 bytes | 1,088 bytes | 1,568 bytes |
| Shared secret | 32 bytes | 32 bytes | 32 bytes |
| Security level | AES-128 | AES-192 | AES-256 |

The total handshake overhead for hybrid X25519 + ML-KEM-768 is approximately 2,336 bytes (compared to 64 bytes for X25519 alone). For a one-time connection handshake on a messaging relay, this is negligible.

### Performance

On a typical 4-core VPS using Go's standard library implementation:

| Operation | Time |
|---|---|
| Key generation | ~60 microseconds |
| Encapsulation | ~60 microseconds |
| Decapsulation | ~80 microseconds |
| Complete hybrid handshake (X25519 + ML-KEM-768 + HKDF) | ~300-400 microseconds |

A single core handles approximately 2,500-3,000 hybrid handshakes per second. On 4 cores, that scales to over 10,000 handshakes per second. With Cloudflare's CIRCL library (AVX2 optimized), performance improves to approximately 15,000+ handshakes per second. The bottleneck will always be network I/O, not cryptography.

---

## Go 1.24: ML-KEM in the Standard Library

Go 1.24 (released February 2025) added the `crypto/mlkem` package with ML-KEM-768 and ML-KEM-1024 implementations. This is significant for several reasons:

**FIPS 140-3 validated.** The Go cryptographic module received CAVP certificate A6650. This means the implementation has been independently verified against NIST's test vectors and requirements.

**Audited by Trail of Bits.** In 2025, Trail of Bits conducted a comprehensive security audit of Go's cryptographic libraries - three engineers, one month, covering ECDH, ML-KEM, ECDSA, RSA, Ed25519, AES-GCM, SHA-1/2/3, HKDF, HMAC, and assembly implementations. The result: one low-severity finding in a legacy CGO module that nobody uses. The standard library itself received a clean bill of health.

**Pure Go, no CGO.** The implementation is written entirely in Go with no C dependencies. This means clean cross-compilation, no linking issues, and the full benefit of Go's memory safety guarantees (bounds checking, garbage collection, race detection).

**Maintained by Filippo Valsorda.** Go's cryptography lead is one of the most respected applied cryptographers in the field. He also created age (21,000+ GitHub stars), maintains the Go TLS implementation, and designed the X-Wing hybrid KEM.

### Usage Example

```go
import "crypto/mlkem"

// Server generates a key pair
decapsKey, encapsKey := mlkem.GenerateKey768()

// Client encapsulates (creates shared secret + ciphertext)
ciphertext, sharedSecret := encapsKey.Encapsulate()

// Server decapsulates (recovers shared secret from ciphertext)
sharedSecret2 := decapsKey.Decapsulate(ciphertext)

// sharedSecret == sharedSecret2 (32 bytes)
```

---

## Alternative Libraries

### Cloudflare CIRCL

`github.com/cloudflare/circl` v1.6.3 provides AVX2-optimized implementations that are approximately 5x faster than `crypto/mlkem` (12 microseconds vs 61 microseconds for ML-KEM-768 encapsulation) with zero heap allocations. BSD-3 licensed.

Use CIRCL only if handshake throughput becomes a measured bottleneck. For GoRelay's expected workload (hundreds to thousands of connections, not millions), the standard library's audit and FIPS status outweigh CIRCL's raw speed advantage.

### X-Wing

X-Wing (`filippo.io/mlkem768/xwing`) is a concrete hybrid KEM combining X25519 + ML-KEM-768 + SHA3-256 with a formal security proof. It is IND-CCA secure if either component is secure - meaning it remains safe even if ML-KEM is somehow broken, as long as X25519 holds (and vice versa).

X-Wing is an IETF draft by Filippo Valsorda and produces a 32-byte shared secret from 1,216-byte keys and 1,120-byte ciphertexts. It may become GoRelay's preferred hybrid construction once it reaches RFC status.

### katzenpost/hpqc

The Katzenpost project provides a hybrid post-quantum cryptography library with XWING, Kyber1024, and other PQ primitives. AGPL-3.0 licensed. Their Noise Protocol fork (`katzenpost/noise`) implements Hybrid Forward Secrecy directly in the handshake pattern.

---

## Hybrid Key Exchange: Why Both Classical and PQC

GoRelay uses hybrid key exchange - both X25519 (classical) and ML-KEM-768 (post-quantum) combined. This is not redundancy for its own sake. It is a defense-in-depth strategy:

**If ML-KEM is broken** (new mathematical attack, implementation flaw, NIST parameter concerns), the X25519 component still provides full classical security. The session keys remain safe against any non-quantum adversary.

**If X25519 is broken** (quantum computer), the ML-KEM component provides full quantum resistance. The session keys remain safe against any adversary including one with a quantum computer.

**Both must be broken simultaneously** for the hybrid to fail. This is strictly stronger than either component alone.

The combination is performed via HKDF:

```go
combined := append(mlkemSharedSecret, x25519SharedSecret...)
hkdfReader := hkdf.New(sha256.New, combined, nil, []byte("GRP/1"))
sessionKey := make([]byte, 32)
io.ReadFull(hkdfReader, sessionKey)
```

The ML-KEM secret is placed first for FIPS ordering compliance (SP 800-56C Rev. 2).

---

## The Competitive Landscape

### Signal: PQXDH and SPQR

Signal is the only major messenger with deployed post-quantum protection. They introduced PQXDH (Post-Quantum Extended Diffie-Hellman) in September 2023, adding a Kyber-1024 key encapsulation to the initial key exchange. In October 2025, they announced SPQR ("Triple Ratchet"), which integrates post-quantum key exchange into the ongoing ratchet process - not just the initial handshake.

However, Signal's PQC is end-to-end (client-to-client). The Signal server itself uses standard TLS without post-quantum protection. An attacker recording server traffic today could potentially decrypt it with a future quantum computer to extract message metadata (who contacted whom, when).

### SimpleX: Optional, Not Mandatory

SimpleX added CRYSTALS-Kyber support with a `has_kem=true/false` flag. This makes PQC optional and negotiated - clients without KEM support fall back to classical-only exchange. Optional security features protect only users who actively enable them, which in practice is a small minority.

### Matrix: No PQC

Matrix/Element has no post-quantum cryptography implementation or announced timeline as of early 2026.

### GoRelay: Mandatory from Handshake One

GRP makes post-quantum key exchange mandatory at the transport layer. There is no flag, no negotiation, no fallback. The first protocol byte identifies the version, and version 1 requires PQC. If the ML-KEM component fails or is missing, the handshake aborts.

This means GoRelay provides quantum resistance at both the transport layer (Noise + PQC) and the end-to-end layer (Double Ratchet with PQC key exchange). No other relay server provides both.

---

## GRP Fixed Cipher Suite

GRP version 1 uses the following non-negotiable cipher suite:

```
GRP/1 cipher suite:
  Key Exchange:    X25519 + ML-KEM-768 hybrid
  KDF:             HKDF-SHA-256
  Signatures:      Ed25519 (upgrade path to ML-DSA-65 in GRP/2)
  AEAD:            ChaCha20-Poly1305
  Hash:            BLAKE2s
  Noise Pattern:   IK (primary), XX (fallback)
```

There is no version negotiation. The first byte of a GRP connection identifies the protocol version. Version 1 requires all components listed above. Future versions will introduce new fixed suites without backward negotiation - the same approach WireGuard uses.

Fixed message sizes for the hybrid handshake (1,184-byte encapsulation key, 1,088-byte ciphertext) are validated exactly. Any deviation is rejected as a protocol error.

---

## Looking Forward: ML-DSA for Signatures

GRP version 1 uses Ed25519 for digital signatures (queue authorization, message authentication). Ed25519 is not quantum-resistant. The upgrade path to ML-DSA-65 (FIPS 204) is planned for GRP version 2.

The reason for not including ML-DSA in version 1 is practical: ML-DSA signatures are significantly larger (2,420 bytes for ML-DSA-44 vs 64 bytes for Ed25519) and Go's standard library does not yet include ML-DSA. Once `crypto/mldsa` is available and audited, GRP version 2 will make quantum-resistant signatures mandatory alongside quantum-resistant key exchange.

In the interim, the hybrid key exchange provides quantum resistance for session establishment, and the per-message symmetric encryption (ChaCha20-Poly1305 with HKDF-derived keys) is inherently quantum-resistant. The signature vulnerability is limited to the authentication of queue operations, not the confidentiality of message content.

---

*GoRelay - IT and More Systems, Recklinghausen*
