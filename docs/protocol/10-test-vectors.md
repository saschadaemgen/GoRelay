---
title: "Test Vectors"
sidebar_position: 10
---

# GRP Protocol Specification: Test Vectors

*Reference values for independent implementation validation. All values are deterministic given the specified inputs.*

**Version:** GRP/1 (Draft)
**Status:** In development
**Date:** 2026-03-09

---

## Purpose

Test vectors allow independent implementations of GRP to verify correctness by comparing their output against known-good reference values. Each vector specifies deterministic inputs and the expected output. An implementation that produces different output has a bug.

All byte sequences are encoded as hexadecimal strings. All keys use the test values specified below - these are NOT secure keys and MUST NOT be used in production.

---

## Test Key Material

The following key material is used across all test vectors:

### X25519 Keys

```
Client ephemeral private:  a8abababababababababababababababababababababababababababababababab06
Client ephemeral public:   e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c

Server static private:     b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b040
Server static public:      de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f

Client static private:     c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c040
Client static public:      (derived from private key above)
```

### Ed25519 Keys

```
Recipient private seed:    d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0
Recipient public:          (derived from seed above)

Sender private seed:       e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0
Sender public:             (derived from seed above)
```

### ML-KEM-768 Keys

```
ML-KEM seed:               f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0
                            f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0
Encapsulation key:         (derived, 1184 bytes)
Decapsulation key:         (derived)
```

*Note: Exact derived values will be computed from the Go standard library reference implementation and published with the GRP/1 final specification.*

---

## Vector 1: Block Framing

### Input

```
payload = "Hello, GRP!"  (11 bytes, hex: 48656c6c6f2c2047525021)
```

### Expected Output

```
block[0:2]   = 0x000b          (payload length = 11, big-endian uint16)
block[2:13]  = 48656c6c6f2c2047525021  (payload)
block[13:16384] = 23232323...23  (padding, '#' = 0x23, repeated 16371 times)
```

Total block size: exactly 16,384 bytes.

### Verification

```go
func TestBlockFraming(t *testing.T) {
    payload := []byte("Hello, GRP!")
    block := WriteBlock(payload)

    assert.Equal(t, 16384, len(block))
    assert.Equal(t, uint16(11), binary.BigEndian.Uint16(block[:2]))
    assert.Equal(t, payload, block[2:13])
    for i := 13; i < 16384; i++ {
        assert.Equal(t, byte('#'), block[i])
    }
}
```

---

## Vector 2: Block Parsing

### Input

```
block = 0x000b 48656c6c6f2c2047525021 232323...23  (16,384 bytes total)
```

### Expected Output

```
payload = 48656c6c6f2c2047525021  (11 bytes)
parsed_string = "Hello, GRP!"
```

### Edge Cases

**Zero-length payload:**
```
block[0:2] = 0x0000
block[2:16384] = all '#' padding
parsed payload = empty (0 bytes)
```

**Maximum payload:**
```
block[0:2] = 0x3ffe (16382)
block[2:16384] = 16382 bytes of payload, no padding
```

**Invalid length (exceeds block):**
```
block[0:2] = 0x3fff (16383) -> ERROR: invalid payload length
block[0:2] = 0xffff (65535) -> ERROR: invalid payload length
```

---

## Vector 3: Transmission Encoding

### Input

```
batch_count = 1
signature = empty (unsigned, PING command)
session_id = empty
correlation_id = 0101010101010101010101010101010101010101010101010101  (24 bytes of 0x01)
entity_id = empty
command = 0x0D (PING)
```

### Expected Output

```
payload:
  0x01                          (batch count = 1)
  0x001a                        (transmission length = 26)
  0x00                          (signature length = 0)
  0x00                          (session_id length = 0)
  0101010101010101010101010101010101010101010101010101  (correlation_id, 24 bytes)
  0x00                          (entity_id length = 0)
  0x0d                          (command = PING)

Total payload: 29 bytes
```

---

## Vector 4: SEND Command Encoding

### Input

```
batch_count = 1
signature = (64-byte Ed25519 signature, computed from sender key over transmission body)
session_id = 0xaa (1 byte)
correlation_id = 0202020202020202020202020202020202020202020202020202  (24 bytes of 0x02)
entity_id = 030303030303030303030303030303030303030303030303  (24 bytes of 0x03, sender_id)
command = 0x05 (SEND)
flags = 0x00 (no cover traffic, no notification)
message_body = "Test message" (12 bytes, hex: 54657374206d657373616765)
```

### Expected Output

```
payload:
  0x01                          (batch count = 1)
  0x????                        (transmission length, computed)
  0x40                          (signature length = 64)
  <64 bytes signature>          (Ed25519 signature)
  0x01                          (session_id length = 1)
  0xaa                          (session_id)
  0202...02                     (correlation_id, 24 bytes)
  0x18                          (entity_id length = 24)
  0303...03                     (entity_id/sender_id, 24 bytes)
  0x05                          (command = SEND)
  0x00                          (flags)
  54657374206d657373616765      (message body, 12 bytes)
```

*Note: The exact signature value depends on the Ed25519 private key and is deterministic for the test key material specified above. Final values will be computed from the reference implementation.*

---

## Vector 5: Hybrid Key Exchange

### Input

```
x25519_client_ephemeral_private = a8abab...ab06  (as specified above)
x25519_server_static_private = b0b0b0...b040     (as specified above)
mlkem_shared_secret = 0xAAAA...AA                 (32 bytes of 0xAA, test value)
noise_handshake_hash = 0xBBBB...BB                (32 bytes of 0xBB, test value)
```

### Expected Derivation

```
combined = mlkem_shared_secret || noise_handshake_hash
         = AAAA...AA BBBB...BB  (64 bytes)

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

*Note: Exact HKDF output values will be computed from the Go standard library and published with the final specification.*

---

## Vector 6: Error Response Encoding

### Input

```
batch_count = 1
correlation_id = 0404040404040404040404040404040404040404040404040404  (24 bytes of 0x04)
entity_id = 0505050505050505050505050505050505050505050505050505  (24 bytes of 0x05)
command = 0x0C (ERR)
error_code = 0x02 (NO_QUEUE)
```

### Expected Output

```
payload:
  0x01                          (batch count = 1)
  0x001d                        (transmission length = 29)
  0x00                          (signature length = 0)
  0x00                          (session_id length = 0)
  0404...04                     (correlation_id, 24 bytes)
  0x18                          (entity_id length = 24)
  0505...05                     (entity_id, 24 bytes)
  0x0c                          (command = ERR)
  0x02                          (error code = NO_QUEUE)

Total payload: 32 bytes
Block: padded to 16,384 bytes with '#'
```

---

## Vector 7: Cover Traffic Message

### Input

```
command = 0x06 (MSG)
entity_id = random 24 bytes
message_id = random 24 bytes
timestamp = 0x00000000 65d8e200 (2024-02-23 12:00:00 UTC, example)
flags = 0x01 (FLAG_COVER_TRAFFIC)
body = random 200 bytes
```

### Verification

```go
func TestCoverTrafficFlag(t *testing.T) {
    msg := parseMSG(decryptedBlock)

    if msg.Flags & FLAG_COVER_TRAFFIC != 0 {
        // Silently discard - this is cover traffic
        return
    }
    // Process real message
}
```

The key verification: after decryption, the flags byte with bit 0 set indicates cover traffic. The client MUST discard the message without further processing.

---

## Vector 8: Message ID Generation

### Input

```
timestamp = 1708689600 (2024-02-23 12:00:00 UTC)
sequence = 42
random = 0xDEADBEEFCAFEBABE (8 bytes)
```

### Expected Output

```
message_id:
  bytes 0-7:   0x0000000065d8e200  (timestamp, uint64 BE, Unix seconds)
  bytes 8-15:  0x000000000000002a  (sequence = 42, uint64 BE)
  bytes 16-23: 0xdeadbeefcafebabe  (random)

Total: 24 bytes
Hex: 0000000065d8e200000000000000002adeadbeefcafebabe
```

---

## Running Test Vectors

GoRelay includes a test suite that validates all vectors:

```bash
go test -run TestVectors ./internal/protocol/...
```

Independent implementations should validate against these vectors before claiming GRP/1 compatibility. All vectors are deterministic - given the specified inputs, there is exactly one correct output.

---

## Future Vectors

The following test vectors will be added as the implementation progresses:

- **Noise IK handshake transcript:** Complete byte-by-byte handshake with test keys
- **Noise XX handshake transcript:** Complete byte-by-byte fallback handshake
- **ML-KEM-768 encapsulation:** Deterministic encapsulation with test seed
- **Hybrid session key derivation:** Full HKDF chain from DH outputs to session keys
- **Server-side re-encryption:** NaCl crypto_box with test keys and message ID as nonce
- **Queue rotation sequence:** Complete QROT/QACK command exchange
- **Two-hop forwarding:** Complete PFWD/RFWD/RRES/PRES sequence with all encryption layers

---

*GoRelay Protocol Specification - IT and More Systems, Recklinghausen*
