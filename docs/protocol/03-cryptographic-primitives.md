---
title: "Cryptographic Primitives"
sidebar_position: 3
---

# GRP Protocol Specification: Cryptographic Primitives

*Complete specification of all cryptographic algorithms used in GRP/1, with selection rationale and rejection justifications for each alternative.*

**Version:** GRP/1 (Draft)
**Status:** In development
**Date:** 2026-03-09

---

## Fixed Cipher Suite

GRP/1 uses exactly one cipher suite. There is no negotiation, no fallback, and no configuration. The suite is defined at protocol design time and is immutable for the lifetime of this protocol version.

```
GRP/1 Cipher Suite:
  Key Agreement (classical):   X25519 (RFC 7748)
  Key Agreement (post-quantum): ML-KEM-768 (FIPS 203)
  Hybrid KDF:                  HKDF-SHA-256 (RFC 5869)
  Noise Pattern:               IK (primary), XX (fallback)
  Noise DH:                    Curve25519
  Noise Cipher:                ChaCha20-Poly1305 (RFC 8439)
  Noise Hash:                  BLAKE2s (RFC 7693)
  Digital Signatures:          Ed25519 (RFC 8032)
  Message Authentication:      Poly1305 (via AEAD)
  Key Derivation:              HKDF-SHA-256
  Random Number Generation:    OS CSPRNG (crypto/rand)
```

---

## X25519 - Classical Key Agreement

### What It Does

X25519 is an elliptic curve Diffie-Hellman function on Curve25519. Two parties each generate an ephemeral keypair, exchange public keys, and compute a shared secret. The shared secret is identical for both parties but cannot be derived by an observer who sees only the public keys.

### Why X25519

| Property | X25519 | ECDH (P-256) | DH (finite field) |
|---|---|---|---|
| Key size | 32 bytes | 32 bytes | 256+ bytes |
| Performance | ~120 microseconds | ~200 microseconds | ~2 ms |
| Constant-time | By design | Requires care | Difficult |
| Patent status | Unencumbered | Unencumbered | Unencumbered |
| Side-channel resistance | Inherent (Montgomery ladder) | Implementation-dependent | Implementation-dependent |

X25519 was designed by Daniel J. Bernstein specifically for safe, fast, and misuse-resistant key agreement. The Montgomery ladder scalar multiplication is inherently constant-time, eliminating an entire class of timing side-channel attacks that plague other curves. Every major security protocol designed in the last decade uses X25519: TLS 1.3, Signal, WireGuard, Noise, age, and SSH.

### Go Implementation

```go
import "crypto/ecdh"

curve := ecdh.X25519()
privateKey, err := curve.GenerateKey(rand.Reader)
publicKey := privateKey.PublicKey()
sharedSecret, err := privateKey.ECDH(remotePublicKey)
```

Go's `crypto/ecdh` implementation is part of the FIPS 140-3 validated module and was covered by the Trail of Bits audit.

### Rejected Alternative: X448

X448 (Curve448) provides 224-bit security versus X25519's 128-bit security. Rejected because the security margin is unnecessary when combined with ML-KEM-768 (192-bit post-quantum security), and X448 is approximately 3x slower than X25519 with 56-byte keys instead of 32 bytes.

---

## ML-KEM-768 - Post-Quantum Key Encapsulation

### What It Does

ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism) is a post-quantum key exchange standardized as FIPS 203. It is based on the hardness of the Module Learning With Errors (MLWE) problem, which is believed to be resistant to both classical and quantum attacks.

Unlike Diffie-Hellman (which is interactive - both parties contribute), KEM is asymmetric: one party generates a keypair, the other party encapsulates a shared secret using the public key, and the first party decapsulates it using the private key.

### Why ML-KEM-768

| Parameter | ML-KEM-512 | ML-KEM-768 | ML-KEM-1024 |
|---|---|---|---|
| Security level | NIST Level 1 (AES-128) | NIST Level 3 (AES-192) | NIST Level 5 (AES-256) |
| Encapsulation key | 800 bytes | 1,184 bytes | 1,568 bytes |
| Ciphertext | 768 bytes | 1,088 bytes | 1,568 bytes |
| Shared secret | 32 bytes | 32 bytes | 32 bytes |
| Encapsulation time | ~40 us | ~60 us | ~90 us |
| Decapsulation time | ~50 us | ~80 us | ~120 us |

ML-KEM-768 provides NIST Security Level 3, offering a comfortable margin above the minimum while keeping handshake overhead manageable. The total PQC overhead in the handshake is approximately 2,272 bytes (1,184 encapsulation key + 1,088 ciphertext) - negligible for a one-time connection setup.

### Go Implementation

```go
import "crypto/mlkem"

// Server generates decapsulation key and encapsulation key
decapsKey, encapsKey := mlkem.GenerateKey768()

// Client encapsulates: creates shared secret + ciphertext
ciphertext, sharedSecret := encapsKey.Encapsulate()

// Server decapsulates: recovers shared secret
sharedSecret2 := decapsKey.Decapsulate(ciphertext)
```

Go 1.24's `crypto/mlkem` is FIPS 203 compliant, CAVP validated (certificate A6650), and covered by the Trail of Bits audit.

### Rejected Alternatives

**ML-KEM-512:** NIST Level 1 provides only 128-bit post-quantum security. Given that GRP connections may be recorded today and attacked decades from now, a higher security margin is warranted.

**ML-KEM-1024:** NIST Level 5 is overkill for messaging. The additional 600 bytes of overhead per handshake provides no practical benefit when 768 already exceeds foreseeable attack capabilities.

**HQC (Hamming Quasi-Cyclic):** Selected by NIST in March 2025 as a backup KEM based on code-based cryptography (algorithmic diversity from lattices). Not yet standardized as a FIPS. GoRelay may adopt HQC as an additional option in GRP/2 once the standard is finalized.

**Classic McEliece:** Extremely large public keys (261 KB for Level 3) make it impractical for interactive protocols. Better suited for long-term key storage.

**SIKE/SIDH:** Broken in 2022 by Castryck-Decru attack. Completely eliminated.

---

## Hybrid Key Exchange Construction

### Why Hybrid

The hybrid approach combines classical (X25519) and post-quantum (ML-KEM-768) key exchanges so that the session key is secure if EITHER component is secure:

- If ML-KEM-768 is broken (new lattice attack, parameter weakness), X25519 still provides full classical security
- If X25519 is broken (quantum computer), ML-KEM-768 still provides full post-quantum security
- Both must be broken simultaneously to compromise the hybrid

This is the recommended approach by NIST (SP 800-56C Rev. 2), BSI, ANSSI, and every major cryptographic authority.

### Construction

```
x25519_secret = X25519(client_ephemeral_private, server_static_public)
mlkem_secret = ML-KEM-768.Decapsulate(decaps_key, ciphertext)

// ML-KEM secret first (FIPS ordering per SP 800-56C Rev. 2)
combined = mlkem_secret || x25519_secret
session_key = HKDF-SHA-256(
    ikm: combined,
    salt: nil,
    info: "GRP/1 hybrid key exchange",
    length: 32
)
```

The combined secret is 64 bytes (32 from each component), fed into HKDF-SHA-256 to produce a 32-byte session key. The info string binds the derivation to the GRP/1 protocol, preventing cross-protocol attacks.

### Rejected Alternative: X-Wing

X-Wing (`filippo.io/mlkem768/xwing`) is a formally specified hybrid KEM combining X25519 + ML-KEM-768 + SHA3-256 with a concrete security proof. It is an excellent construction and may replace GRP's custom hybrid in GRP/2 once X-Wing reaches RFC status. For GRP/1, we use a standard HKDF combination that follows NIST SP 800-56C guidance directly.

---

## ChaCha20-Poly1305 - Authenticated Encryption

### What It Does

ChaCha20-Poly1305 is an Authenticated Encryption with Associated Data (AEAD) cipher. It encrypts data for confidentiality (ChaCha20 stream cipher) and authenticates both the ciphertext and optional associated data (Poly1305 MAC). Any modification to the ciphertext or associated data causes authentication failure.

### Why ChaCha20-Poly1305

| Property | ChaCha20-Poly1305 | AES-256-GCM |
|---|---|---|
| Performance (no hardware AES) | Faster | Slower |
| Performance (with AES-NI) | Comparable | Comparable |
| Constant-time guarantee | By design (ARX) | Requires AES-NI hardware |
| Nonce size | 96 bits | 96 bits |
| Key size | 256 bits | 256 bits |
| Patent status | Unencumbered | Unencumbered |
| Side-channel on software-only | Immune (no table lookups) | Vulnerable without AES-NI |

ChaCha20-Poly1305 is the safer default because it is constant-time on ALL hardware, including ARM boards and IoT devices without AES hardware acceleration. AES-GCM is only safe when AES-NI instructions are available - on software-only implementations, AES uses lookup tables that are vulnerable to cache-timing attacks.

Since GoRelay targets everything from VPS servers (with AES-NI) to Raspberry Pi and ESP32 devices (without AES-NI), ChaCha20-Poly1305 provides consistent security across all deployment targets.

### Go Implementation

```go
import "golang.org/x/crypto/chacha20poly1305"

aead, err := chacha20poly1305.New(key)  // 32-byte key
nonce := make([]byte, aead.NonceSize()) // 12 bytes
ciphertext := aead.Seal(nil, nonce, plaintext, associatedData)
plaintext, err := aead.Open(nil, nonce, ciphertext, associatedData)
```

### Nonce Management

GRP uses a 64-bit counter as the nonce, encoded as the last 8 bytes of the 12-byte nonce (first 4 bytes zero). The counter increments with each message and MUST NOT be reused with the same key. Nonce reuse with ChaCha20-Poly1305 catastrophically leaks the XOR of two plaintexts AND the authentication key.

The Noise Protocol's CipherState handles nonce management automatically, incrementing after each encryption operation and rejecting any attempt to encrypt more than 2^64 messages with the same key.

---

## BLAKE2s - Hash Function

### What It Does

BLAKE2s is a cryptographic hash function optimized for 8-to-32-bit platforms. It produces a 256-bit (32-byte) digest and is used within the Noise Protocol for handshake hashing and key derivation.

### Why BLAKE2s

| Property | BLAKE2s | SHA-256 | SHA-3 (Keccak) |
|---|---|---|---|
| Speed (software) | Fastest | Medium | Slowest |
| Digest size | 32 bytes | 32 bytes | 32 bytes |
| Design | HAIFA/ChaCha-based | Merkle-Damgard | Sponge |
| Standardization | RFC 7693 | FIPS 180-4 | FIPS 202 |

BLAKE2s is the standard hash function for Noise Protocol implementations (matching WireGuard's choice). It is faster than SHA-256 in software and based on the same ChaCha core as our AEAD cipher, reducing the number of distinct cryptographic building blocks in the implementation.

### Scope

BLAKE2s is used ONLY within the Noise handshake. All other key derivation in GRP uses HKDF-SHA-256 (FIPS compliant). This separation ensures that the FIPS-validated code path is used for all key material outside of the Noise transport.

---

## HKDF-SHA-256 - Key Derivation

### What It Does

HKDF (HMAC-based Key Derivation Function) extracts and expands key material from a shared secret into one or more cryptographically strong keys. It operates in two phases: Extract (compress variable-length input into a fixed-length pseudorandom key) and Expand (generate arbitrary-length output from the pseudorandom key).

### Why HKDF-SHA-256

HKDF-SHA-256 is the most widely deployed KDF in security protocols (TLS 1.3, Signal, Noise, WireGuard). It is FIPS compliant (SP 800-56C), formally analyzed, and available in Go's standard library via `crypto/hkdf` (which is backed by the FIPS-validated HMAC-SHA-256 implementation).

### Usage in GRP

| Context | Salt | Info |
|---|---|---|
| Hybrid key combination | nil | "GRP/1 hybrid key exchange" |
| Per-message key derivation | chain key | "GRP/1 message key" |
| Queue authorization key | queue secret | "GRP/1 queue auth" |
| Cover traffic key | session key | "GRP/1 cover traffic" |

The info strings are distinct for each usage context, ensuring domain separation - keys derived for one purpose cannot be used for another even if the input key material is the same.

---

## Ed25519 - Digital Signatures

### What It Does

Ed25519 is an Edwards-curve Digital Signature Algorithm providing 128-bit security. It is used in GRP for queue authorization (proving ownership of a queue) and handshake authentication (proving possession of a static key in certain Noise patterns).

### Why Ed25519

| Property | Ed25519 | ECDSA (P-256) | RSA-2048 |
|---|---|---|---|
| Signature size | 64 bytes | 64 bytes | 256 bytes |
| Public key size | 32 bytes | 33 bytes | 256 bytes |
| Sign time | ~70 us | ~100 us | ~1 ms |
| Verify time | ~200 us | ~200 us | ~50 us |
| Deterministic | Yes | Optional (RFC 6979) | N/A |
| Misuse resistance | High | Low (nonce reuse = key leak) | Medium |

Ed25519 is deterministic - the same message and key always produce the same signature. This eliminates the catastrophic nonce-reuse vulnerability that has caused real-world ECDSA key leaks (PlayStation 3 hack, Bitcoin wallet exploits). The signature is computed from a hash of the private key and message, not from a random nonce.

### Quantum Vulnerability

Ed25519 is NOT quantum-resistant. Shor's algorithm can compute discrete logarithms on elliptic curves, breaking Ed25519 with a sufficiently large quantum computer.

In GRP/1, this means an adversary with a quantum computer could forge queue authorization commands (creating, deleting, or subscribing to queues). However, they could NOT read message content because message confidentiality relies on symmetric encryption derived from the hybrid (quantum-resistant) key exchange.

GRP/2 will replace Ed25519 with ML-DSA-65 (FIPS 204) once Go's standard library includes an audited implementation. The upgrade path is planned and documented.

### Go Implementation

```go
import "crypto/ed25519"

publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
signature := ed25519.Sign(privateKey, message)
valid := ed25519.Verify(publicKey, message, signature)
```

---

## Random Number Generation

### Requirements

GRP requires cryptographically secure random numbers for:

- Ephemeral key generation (X25519, ML-KEM-768)
- Queue ID generation (24 bytes)
- Nonce generation (where not counter-based)
- Cover traffic timing (Poisson intervals)
- Queue rotation jitter

### Implementation

Go's `crypto/rand` reads directly from the operating system entropy source:

- **Linux:** `getrandom(2)` syscall (kernel CSPRNG seeded from hardware entropy)
- **macOS:** `getentropy(2)` or `/dev/urandom`
- **Windows:** `CryptGenRandom` (BCryptGenRandom)

The FIPS 140-3 module includes DRBG (Deterministic Random Bit Generator) validation per SP 800-90A.

### Entropy Health

GoRelay logs a warning at startup if the system entropy pool reports low availability. On Linux, this is checked via `/proc/sys/kernel/random/entropy_avail`. Systems with fewer than 256 bits of available entropy should not be used for key generation.

---

## Algorithm Agility Strategy

GRP intentionally avoids algorithm agility (runtime negotiation of cryptographic algorithms). History shows that algorithm agility creates downgrade attacks (POODLE, FREAK, Logjam) and implementation complexity.

Instead, GRP uses version-based algorithm evolution:

```
GRP/1: X25519 + ML-KEM-768, ChaCha20-Poly1305, BLAKE2s, Ed25519
GRP/2: X25519 + ML-KEM-768, ChaCha20-Poly1305, BLAKE2s, ML-DSA-65
GRP/3: (future, if algorithm breaks require changes)
```

Each version is a complete, fixed cipher suite. The version byte in the first message identifies which suite is in use. There is no negotiation within a version. If a client and server support different versions, the connection fails with a clear error message telling both sides to upgrade.

---

*GoRelay Protocol Specification - IT and More Systems, Recklinghausen*
