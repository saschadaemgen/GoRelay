---
title: "Handshake"
sidebar_position: 4
---

# GRP Protocol Specification: Noise Handshake and PQC

*Complete specification of the GRP/1 connection handshake using the Noise Protocol Framework with hybrid post-quantum key exchange.*

**Version:** GRP/1 (Draft)
**Status:** In development
**Date:** 2026-03-09

---

## Overview

The GRP handshake establishes an authenticated, encrypted channel between a client and a GoRelay server. It uses the Noise Protocol Framework with a hybrid post-quantum extension that combines classical X25519 with ML-KEM-768.

The handshake accomplishes four things simultaneously:

1. **Mutual authentication:** The client verifies the server's identity (static public key). In the XX pattern, the server also learns the client's identity.
2. **Key agreement:** Both parties derive identical session keys for encrypting all subsequent communication.
3. **Post-quantum protection:** The hybrid key exchange ensures quantum resistance from the first message.
4. **Identity hiding:** The initiator's static key is encrypted during the handshake, hidden from passive observers.

---

## Handshake Patterns

### Primary: Noise IK

The IK pattern is used when the client already knows the server's static public key (the common case - the key is embedded in the `grp://` server URI).

```
IK:
  <- s                         (server's static key is pre-known)
  -> e, es, s, ss              (client message 1)
  <- e, ee, se                 (server message 2)
```

**Message 1 (client to server):**
- `e`: Client generates and sends an ephemeral Curve25519 public key
- `es`: Client performs DH between its ephemeral key and the server's static key
- `s`: Client sends its static public key (encrypted by the current handshake state)
- `ss`: Client performs DH between its static key and the server's static key

**Message 2 (server to client):**
- `e`: Server generates and sends an ephemeral Curve25519 public key
- `ee`: Both parties perform DH between their ephemeral keys (forward secrecy)
- `se`: Server performs DH between its static key and the client's ephemeral key

After message 2, both parties derive identical CipherState objects for encrypting transport messages.

**Properties:**
- 1 round trip (2 messages)
- Client identity encrypted (hidden from passive observers)
- Server identity verified against pre-known key
- Forward secrecy via ephemeral-ephemeral DH

### Fallback: Noise XX

The XX pattern is used for first-contact scenarios where the client does not yet have the server's static key.

```
XX:
  -> e                         (client message 1)
  <- e, ee, s, es              (server message 2)
  -> s, se                     (client message 3)
```

**Message 1 (client to server):**
- `e`: Client generates and sends an ephemeral Curve25519 public key

**Message 2 (server to client):**
- `e`: Server generates and sends an ephemeral Curve25519 public key
- `ee`: Both parties perform ephemeral-ephemeral DH
- `s`: Server sends its static public key (encrypted)
- `es`: DH between client's ephemeral and server's static

**Message 3 (client to server):**
- `s`: Client sends its static public key (encrypted)
- `se`: DH between server's static and client's ephemeral

**Properties:**
- 1.5 round trips (3 messages)
- Both identities encrypted (strongest identity hiding)
- No pre-shared knowledge required
- Forward secrecy via ephemeral-ephemeral DH

After an XX handshake, the client caches the server's static key for future IK handshakes.

---

## Prologue

The Noise prologue binds the handshake to a specific protocol version. Both parties must agree on the prologue or the handshake fails:

```
prologue = "GRP/1"
```

The prologue is mixed into the handshake hash before any messages are sent. If a client expecting GRP/1 connects to a server running GRP/2, the handshake hashes diverge and authentication fails. This provides version binding without version negotiation.

---

## Hybrid Post-Quantum Extension

### Integration with Noise

The standard Noise handshake uses only X25519 for key agreement. GRP extends this with an ML-KEM-768 encapsulation that runs alongside the Noise handshake:

```
GRP Hybrid IK Handshake:

  Pre-message:
    <- s                       (server static Curve25519 key, pre-known)

  Message 1 (client -> server):
    noise_e                    (Noise ephemeral key, 32 bytes)
    noise_es                   (DH: client ephemeral x server static)
    noise_s                    (Noise static key, encrypted, 32+16 bytes)
    noise_ss                   (DH: client static x server static)
    mlkem_ciphertext           (ML-KEM-768 ciphertext, 1088 bytes)

  Message 2 (server -> client):
    noise_e                    (Noise ephemeral key, 32 bytes)
    noise_ee                   (DH: ephemeral x ephemeral)
    noise_se                   (DH: server static x client ephemeral)
    confirmation               (encrypted confirmation, variable)

  Post-handshake key mixing:
    final_key = HKDF-SHA-256(
      ikm: mlkem_shared_secret || noise_handshake_hash,
      salt: nil,
      info: "GRP/1 hybrid session"
    )
```

### ML-KEM Flow

1. Before the handshake, the server publishes its ML-KEM-768 encapsulation key alongside its Noise static key in the server URI or through a key discovery mechanism.

2. In Message 1, the client encapsulates a shared secret using the server's ML-KEM encapsulation key and includes the 1,088-byte ciphertext.

3. The server decapsulates to recover the 32-byte ML-KEM shared secret.

4. After the Noise handshake completes, both parties mix the ML-KEM shared secret into the final session key using HKDF. This ensures that the session key depends on BOTH the Noise DH outputs AND the ML-KEM shared secret.

### Why Post-Handshake Mixing

The ML-KEM secret is mixed in after the Noise handshake rather than during it because:

- The Noise framework has a well-defined, formally analyzed state machine. Inserting additional key material mid-handshake would require a custom Noise modification that loses the formal analysis.
- Post-handshake mixing via HKDF is a standard, well-understood construction (used by TLS 1.3, QUIC, and others).
- The security property is identical: the final session key is compromised only if both the Noise DH AND the ML-KEM are broken.

### Encapsulation Key Distribution

The server's ML-KEM-768 encapsulation key (1,184 bytes) is distributed alongside the server's Noise static key:

**In the server URI:**
```
grp://<noise-static-key-b64>:<mlkem-encaps-key-b64>@host:port
```

**Via key discovery (for XX handshakes):**
The server includes its ML-KEM encapsulation key in Message 2 of the XX handshake, encrypted under the ephemeral-ephemeral DH key established in the first exchange.

### Key Rotation

The server's ML-KEM keypair is rotated independently of the Noise static key:

- **Noise static key:** Long-lived, rotated only when the server identity needs to change
- **ML-KEM keypair:** Rotated every 24 hours. Old decapsulation keys are retained for 48 hours to handle in-flight handshakes, then securely destroyed.

This limits the window of exposure if an ML-KEM private key is somehow compromised.

---

## Handshake Message Sizes

### Noise IK + ML-KEM Hybrid

| Message | Components | Size |
|---|---|---|
| Message 1 (client) | ephemeral (32) + encrypted static (48) + ML-KEM ciphertext (1088) + MAC (16) | 1,184 bytes |
| Message 2 (server) | ephemeral (32) + confirmation + MAC (16) | ~64 bytes |
| **Total handshake** | | **~1,248 bytes** |

### Noise XX + ML-KEM Hybrid

| Message | Components | Size |
|---|---|---|
| Message 1 (client) | ephemeral (32) | 32 bytes |
| Message 2 (server) | ephemeral (32) + encrypted static (48) + ML-KEM encaps key (1184) + MAC (16) | ~1,280 bytes |
| Message 3 (client) | encrypted static (48) + ML-KEM ciphertext (1088) + MAC (16) | ~1,152 bytes |
| **Total handshake** | | **~2,464 bytes** |

For comparison, a TLS 1.3 handshake is typically 2,000-4,000 bytes. GRP's IK handshake is smaller than TLS despite including post-quantum key material.

---

## Handshake Padding

To prevent an observer from distinguishing IK handshakes from XX handshakes based on message count or size, all handshake messages are padded to fixed sizes:

| Message | Padded Size |
|---|---|
| Client Message 1 | 2,500 bytes |
| Server Message 1/2 | 2,500 bytes |
| Client Message 2 (XX only) | 2,500 bytes |

For IK handshakes (2 messages), the client sends a single 2,500-byte padded message and receives a single 2,500-byte padded response. For XX handshakes (3 messages), an additional 2,500-byte padded message is sent. The padding consists of random bytes appended after the MAC.

An observer sees either 2 or 3 messages of 2,500 bytes each. The size difference between 2 and 3 messages reveals whether IK or XX was used, but does not reveal any key material or identity information.

---

## Handshake Timeout

The complete handshake must finish within 30 seconds. If any handshake message is not received within this window, the connection is closed without error message (to prevent information leakage about the failure reason).

This prevents slowloris-style attacks where an attacker opens many connections and sends handshake messages very slowly to exhaust server resources.

---

## Session Key Derivation

After the handshake completes, the Noise CipherState provides two encryption keys (one per direction). GRP mixes in the ML-KEM shared secret to produce the final session keys:

```
// Noise provides handshake_hash (32 bytes) and two CipherStates
// ML-KEM provides mlkem_shared_secret (32 bytes)

combined = mlkem_shared_secret || handshake_hash

client_to_server_key = HKDF-SHA-256(
    ikm: combined,
    salt: nil,
    info: "GRP/1 c2s",
    length: 32
)

server_to_client_key = HKDF-SHA-256(
    ikm: combined,
    salt: nil,
    info: "GRP/1 s2c",
    length: 32
)
```

The directional info strings ("c2s" and "s2c") ensure that the two keys are distinct even though they are derived from the same input material. Using the same key for both directions would be catastrophic with counter-based nonces (both sides would reuse nonce values).

---

## Rekeying

GRP implements periodic rekeying to provide continuous forward secrecy during long-lived connections:

**Time-based:** Every 2 minutes, both parties perform a Noise rekey operation that derives new encryption keys from the current key and a counter. The old keys are securely zeroed.

**Message-based:** After every 1,000 messages in either direction, a rekey is triggered regardless of elapsed time.

**Explicit rekey:** Either party can initiate a full DH rekeying by sending a new ephemeral public key and performing a fresh DH exchange. This provides post-compromise security (recovery from key compromise) whereas counter-based rekeying only provides forward secrecy.

The rekey schedule ensures that even a long-running connection (hours or days) maintains forward secrecy. An adversary who compromises a session key can decrypt at most 2 minutes or 1,000 messages of traffic before the key changes.

---

## Implementation Notes

### flynn/noise Configuration

```go
cs := noise.NewCipherSuite(
    noise.DH25519,
    noise.CipherChaChaPoly,
    noise.HashBLAKE2s,
)

serverHS, err := noise.NewHandshakeState(noise.Config{
    CipherSuite:           cs,
    Pattern:               noise.HandshakeIK,
    Initiator:             false,
    StaticKeypair:         serverNoiseKey,
    Prologue:              []byte("GRP/1"),
    PresharedKey:          nil,
    PresharedKeyPlacement: 0,
})
```

### Handshake State Machine

```
Client                              Server
  |                                    |
  |--- Version byte (0x01) ---------->|  (identifies GRP/1)
  |--- Padded Message 1 (2500B) ----->|  (Noise e,es,s,ss + ML-KEM ct)
  |                                    |  Server: Noise process + ML-KEM decaps
  |<-- Padded Message 2 (2500B) ------|  (Noise e,ee,se + confirmation)
  |                                    |
  |  Both: derive final session keys   |
  |  Both: switch to transport mode    |
  |                                    |
  |=== Encrypted 16KB blocks ========>|
  |<== Encrypted 16KB blocks =========|
```

The first byte sent by the client is the version byte (0x01 for GRP/1). This allows the server to identify the protocol version before any handshake processing occurs. If the version is unsupported, the server closes the connection immediately.

---

*GoRelay Protocol Specification - IT and More Systems, Recklinghausen*
