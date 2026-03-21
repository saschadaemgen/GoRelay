---
title: "Message Format"
sidebar_position: 5
---

# GRP Protocol Specification: Message Format

*Byte-level specification of GRP/1 frame format, block structure, transmission encoding, and padding rules.*

**Version:** GRP/1 (Draft)
**Status:** In development
**Date:** 2026-03-09

---

## Design Principles

GRP's message format follows three rules:

1. **Fixed size:** Every block on the wire is exactly 16,384 bytes. No exceptions.
2. **Indistinguishable:** Real messages, keep-alive pings, error responses, and cover traffic dummies all produce identical 16 KB blocks after encryption.
3. **Parseable:** The format can be parsed with a single pass, no backtracking, no lookahead.

---

## Block Format

### Wire Format

Every GRP frame transmitted over the Noise channel is exactly 16,384 bytes:

```
+------------------------------------------------------------------+
| Encrypted Block (16,384 bytes)                                   |
|                                                                  |
| After Noise decryption:                                          |
| +--------------------------------------------------------------+ |
| | payload_length (2 bytes, uint16 big-endian)                   | |
| +--------------------------------------------------------------+ |
| | payload (payload_length bytes)                                | |
| +--------------------------------------------------------------+ |
| | padding ('#' repeated to fill 16,384 - 2 - payload_length)   | |
| +--------------------------------------------------------------+ |
+------------------------------------------------------------------+
```

**payload_length:** The first 2 bytes encode the actual payload length as a big-endian unsigned 16-bit integer. Maximum value: 16,382 (16,384 minus 2 bytes for the length field itself).

**payload:** The actual protocol data, consisting of one or more transmissions.

**padding:** The '#' character (0x23) repeated to fill the block to exactly 16,384 bytes. The padding character is fixed (not random) because the block is encrypted before transmission - random padding would provide no additional security benefit.

### Maximum Payload Size

```
max_payload = 16,384 - 2 = 16,382 bytes
```

Any payload exceeding 16,382 bytes MUST be rejected as a protocol error. GRP does not support message fragmentation across multiple blocks - if a message does not fit in a single block, it is too large for the protocol.

### Reading Blocks

Implementations MUST use exact-read operations (equivalent to Go's `io.ReadFull`) to read blocks. TCP can deliver partial data at any time - a standard `read()` call might return 8,192 bytes of a 16,384-byte block. Partial reads corrupt frame boundaries and can cause cascading parse failures.

```go
var block [16384]byte
_, err := io.ReadFull(noiseReader, block[:])
if err != nil {
    return err  // connection broken or closed
}
payloadLen := binary.BigEndian.Uint16(block[:2])
if payloadLen > 16382 {
    return ErrInvalidPayloadLength
}
payload := block[2 : 2+payloadLen]
```

### Writing Blocks

```go
var block [16384]byte
binary.BigEndian.PutUint16(block[:2], uint16(len(payload)))
copy(block[2:], payload)
for i := 2 + len(payload); i < 16384; i++ {
    block[i] = '#'
}
_, err := noiseWriter.Write(block[:])
```

---

## Transmission Format

### Single Transmission

Within a payload, each transmission has the following structure:

```
transmission:
  +------------------------------------------------------+
  | signature_length (1 byte)                             |
  +------------------------------------------------------+
  | signature (signature_length bytes, Ed25519 or empty)  |
  +------------------------------------------------------+
  | session_id_length (1 byte)                            |
  +------------------------------------------------------+
  | session_id (session_id_length bytes)                  |
  +------------------------------------------------------+
  | correlation_id (24 bytes, fixed)                      |
  +------------------------------------------------------+
  | entity_id_length (1 byte)                             |
  +------------------------------------------------------+
  | entity_id (entity_id_length bytes, queue ID)          |
  +------------------------------------------------------+
  | command (remaining bytes)                             |
  +------------------------------------------------------+
```

**signature:** Ed25519 signature over the transmission body (session_id through command). Empty (length 0) for unsigned commands (PING, PONG).

**session_id:** Binds the transmission to the current session. Prevents replay of transmissions from a different session.

**correlation_id:** 24-byte identifier linking a response to its request. The client generates a random correlation_id for each command; the server echoes it in the response.

**entity_id:** The queue identifier (recipient_id or sender_id depending on the command). Empty for connection-level commands (PING, PONG).

**command:** The actual protocol command and its parameters.

### Batched Transmissions

Multiple transmissions can be batched into a single block to reduce round trips:

```
payload:
  +------------------------------------------------------+
  | batch_count (1 byte, 1-255)                          |
  +------------------------------------------------------+
  | transmission_1_length (2 bytes, uint16 BE)           |
  +------------------------------------------------------+
  | transmission_1 (transmission_1_length bytes)         |
  +------------------------------------------------------+
  | transmission_2_length (2 bytes, uint16 BE)           |
  +------------------------------------------------------+
  | transmission_2 (transmission_2_length bytes)         |
  +------------------------------------------------------+
  | ... (up to batch_count transmissions)                |
  +------------------------------------------------------+
```

**batch_count:** The number of transmissions in this block. A value of 1 indicates a single (non-batched) transmission. Maximum 255.

Each transmission is prefixed with its own 2-byte length, allowing the parser to advance through the batch without knowing the internal structure of each transmission.

### Batch Rules

- All transmissions in a batch MUST be for the same connection (same session_id)
- The total size of all transmissions plus batch overhead MUST fit in 16,382 bytes
- The server processes batched transmissions in order and returns batched responses
- If any transmission in a batch fails, the error response is included in the response batch at the corresponding position

---

## Command Encoding

### Command Byte

Each command is identified by a single-byte command code:

| Code | Command | Direction | Parameters |
|---|---|---|---|
| 0x01 | NEW | Client to Server | recipient_key, dh_key |
| 0x02 | IDS | Server to Client | recipient_id, sender_id, server_dh_key |
| 0x03 | SUB | Client to Server | (none) |
| 0x04 | KEY | Client to Server | sender_key |
| 0x05 | SEND | Client to Server | flags, message_body |
| 0x06 | MSG | Server to Client | msg_id, timestamp, flags, message_body |
| 0x07 | ACK | Client to Server | msg_id |
| 0x08 | OFF | Client to Server | (none) |
| 0x09 | DEL | Client to Server | (none) |
| 0x0A | GET | Client to Server | (none) |
| 0x0B | OK | Server to Client | (none) |
| 0x0C | ERR | Server to Client | error_code |
| 0x0D | PING | Client to Server | (none) |
| 0x0E | PONG | Server to Client | (none) |
| 0x0F | END | Server to Client | (none) |
| 0x10 | PFWD | Client to Server | destination, encrypted_payload |
| 0x11 | RFWD | Server to Server | encrypted_payload |
| 0x12 | RRES | Server to Server | encrypted_response |
| 0x13 | PRES | Server to Client | encrypted_response |
| 0x14 | QROT | Client to Server | new_queue_info |
| 0x15 | QACK | Server to Client | rotation_confirmation |

### String Encoding

All variable-length strings and byte arrays use a length-prefixed format:

**Short string (max 255 bytes):**
```
short_string:
  length (1 byte, uint8) + data (length bytes)
```

**Medium string (max 65535 bytes):**
```
medium_string:
  length (2 bytes, uint16 BE) + data (length bytes)
```

Queue IDs (entity_id, recipient_id, sender_id) are always 24 bytes and use the short_string format with length = 24.

### Flags Byte

The SEND and MSG commands include a flags byte:

```
flags:
  bit 0: cover_traffic  (1 = this is a dummy message, discard after decryption)
  bit 1: notification   (1 = trigger push notification on delivery)
  bit 2: priority       (1 = high priority, skip cover traffic queue)
  bits 3-7: reserved (must be 0)
```

The cover_traffic flag is critical for traffic analysis resistance. When set, the recipient client silently discards the message content without processing or displaying it. The flag is inside the encrypted payload, invisible to network observers.

---

## Error Codes

The ERR command includes a single-byte error code:

| Code | Meaning | Description |
|---|---|---|
| 0x01 | AUTH | Authentication failure (invalid signature) |
| 0x02 | NO_QUEUE | Queue does not exist |
| 0x03 | NO_MSG | No message available (response to GET) |
| 0x04 | DUPLICATE | Queue already exists (duplicate NEW) |
| 0x05 | QUOTA | Queue or message quota exceeded |
| 0x06 | LARGE | Message too large for block |
| 0x07 | INTERNAL | Server internal error |
| 0x08 | BLOCKED | Rate limit exceeded |
| 0x09 | NO_KEY | Sender key not set (SEND before KEY) |
| 0x0A | DISABLED | Queue is disabled (OFF was called) |
| 0x0B | VERSION | Protocol version mismatch |
| 0x0C | TIMEOUT | Operation timed out |

Error responses are padded to the same 16 KB block size as successful responses. An observer cannot determine whether an operation succeeded or failed by watching block sizes or timing.

---

## Message ID Format

Message IDs (msg_id) are 24 bytes, generated by the server when a message is stored:

```
msg_id:
  timestamp (8 bytes, uint64 BE, Unix nanoseconds)
  sequence  (8 bytes, uint64 BE, per-queue monotonic counter)
  random    (8 bytes, random)
```

The timestamp enables TTL enforcement without a separate index. The sequence provides per-queue ordering. The random component prevents prediction of future message IDs.

Message IDs are used as nonces for server-side re-encryption (NaCl crypto_box), so they MUST be unique across the lifetime of a queue. The combination of nanosecond timestamp + sequence counter + random bytes provides sufficient uniqueness.

---

## Cover Traffic Messages

Cover traffic (dummy) messages are structurally identical to real messages:

```
cover_message:
  command = SEND (0x05) or MSG (0x06)
  flags = 0x01 (cover_traffic bit set)
  message_body = random bytes (variable length, matching typical message distribution)
```

The message body is filled with random bytes rather than a fixed pattern. The length of the random body is drawn from a distribution matching typical real message lengths to prevent statistical distinguishing based on message size within the encrypted block.

After encryption and padding to 16,384 bytes, the cover message is indistinguishable from a real message on the wire.

---

## Timestamp Format

All timestamps in GRP use Unix time in seconds as a 64-bit unsigned big-endian integer:

```
timestamp = uint64 BE, seconds since 1970-01-01T00:00:00Z
```

Timestamps are used in MSG delivery (message creation time) and message ID generation. The 64-bit range covers approximately 584 billion years, eliminating any Y2K-style overflow concerns.

Implementations SHOULD NOT rely on timestamp precision finer than 1 second. Clock skew of up to 60 seconds between client and server is tolerated.

---

## Wire Example

A PING command in a 16,384-byte block:

```
Byte 0-1:   0x00 0x1D          (payload length = 29 bytes)
Byte 2:     0x01               (batch count = 1)
Byte 3-4:   0x00 0x1A          (transmission length = 26 bytes)
Byte 5:     0x00               (signature length = 0, unsigned)
Byte 6:     0x00               (session_id length = 0)
Byte 7-30:  <24 random bytes>  (correlation_id)
Byte 31:    0x00               (entity_id length = 0, no queue)
Byte 32:    0x0D               (command = PING)
Byte 33-16383: 0x23 repeated   (padding, '#')
```

After Noise encryption, the entire 16,384-byte block is ciphertext. An observer sees 16,384 bytes of encrypted data - indistinguishable from any other message type.

---

*GoRelay Protocol Specification - IT and More Systems, Recklinghausen*
