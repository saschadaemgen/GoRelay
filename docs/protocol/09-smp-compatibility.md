---
title: "SMP Compatibility"
sidebar_position: 9
---

# GRP Protocol Specification: SMP Compatibility

*How GoRelay maintains full backward compatibility with the SimpleX Messaging Protocol, enabling seamless interoperability between GRP-native clients and the SimpleX ecosystem.*

**Version:** GRP/1 (Draft)
**Status:** In development
**Date:** 2026-03-09

---

## Design Principle

GoRelay is not a fork of SimpleX. It is a dual-protocol server that speaks both SMP and GRP natively. The two protocols share a common internal queue store, enabling messages to flow between SMP clients and GRP clients transparently.

The goal is additive, not competitive: GoRelay gives every SimpleX user a better relay option without requiring them to change their client software.

---

## Dual-Port Architecture

GoRelay listens on two ports simultaneously:

```
Port 5223: SMP (TLS 1.3, ALPN "smp/1")
  - Full SimpleX Messaging Protocol v7+ compatibility
  - Standard SMP client commands (NEW, SUB, SEND, MSG, ACK, DEL, etc.)
  - TLS certificate chain with offline CA (standard SMP identity model)

Port 7443: GRP (Noise IK/XX, hybrid PQC)
  - GoRelay Protocol with enhanced security
  - All SMP commands plus PFWD, RFWD, QROT, etc.
  - Static Curve25519 key identity model
```

Both ports accept connections concurrently. The server maintains a single `QueueStore` and `SubscriptionHub` that both protocols share.

---

## Shared Queue Store

### Queue Structure

Queues are protocol-agnostic at the storage layer. A queue created via SMP is accessible via GRP and vice versa:

```go
type Queue struct {
    RecipientID     [24]byte
    SenderID        [24]byte
    RecipientKey    ed25519.PublicKey
    SenderKey       ed25519.PublicKey  // set via KEY command
    ServerDHPublic  *ecdh.PublicKey
    ServerDHPrivate *ecdh.PrivateKey
    Status          QueueStatus       // ACTIVE, DISABLED, DELETED
    CreatedAt       time.Time
    CreatedVia      Protocol          // SMP or GRP (informational only)
}
```

The `CreatedVia` field records which protocol created the queue but does not restrict access. A queue created via SMP can be subscribed to via GRP and vice versa.

### Message Storage

Messages are stored in BadgerDB with a uniform format regardless of which protocol delivered them:

```
Key:   q:<recipientID>:msg:<sequence>:data
Value: encrypted message blob

Key:   q:<recipientID>:msg:<sequence>:key
Value: 32-byte per-message symmetric key

Key:   q:<recipientID>:msg:<sequence>:meta
Value: timestamp (8 bytes) + flags (1 byte) + source_protocol (1 byte)
```

The `source_protocol` byte indicates whether the message arrived via SMP (0x01) or GRP (0x02). This is used only for metrics and logging - it does not affect delivery behavior.

---

## Cross-Protocol Message Flow

### SMP Sender to GRP Recipient

```
SimpleX App --- SMP SEND ---> [GoRelay Port 5223]
                                     |
                              Queue Store (write)
                                     |
SimpleGo Device <--- GRP MSG --- [GoRelay Port 7443]
```

1. SimpleX app connects via TLS to port 5223
2. SimpleX app sends SEND command with encrypted message
3. Server stores message in shared queue store
4. SimpleGo device is subscribed to the same queue via GRP on port 7443
5. Server delivers message via GRP MSG command

The message content is end-to-end encrypted between the SimpleX app and the SimpleGo device using Double Ratchet. The server cannot read it regardless of which transport protocol is used.

### GRP Sender to SMP Recipient

```
SimpleGo Device --- GRP SEND ---> [GoRelay Port 7443]
                                        |
                                  Queue Store (write)
                                        |
SimpleX App <--- SMP MSG --- [GoRelay Port 5223]
```

Same flow in reverse. The GRP client sends to a queue that an SMP client is subscribed to. The message is delivered via SMP.

### GRP Sender to GRP Recipient (with Relay Routing)

```
SimpleGo A --- GRP PFWD ---> [Relay A Port 7443]
                                     |
                              RFWD (forwarding)
                                     |
                              [Relay B Port 7443]
                                     |
                              Queue Store (write)
                                     |
SimpleGo B <--- GRP MSG --- [Relay B Port 7443]
```

When both parties use GRP, two-hop relay routing provides the full enhanced security properties.

---

## Subscription Sharing

### One Subscriber Rule

The one-subscriber-per-queue rule applies across protocols. If an SMP client subscribes to a queue while a GRP client is already subscribed, the GRP client receives END and the SMP client takes over the subscription.

```go
func (h *SubscriptionHub) Subscribe(queueID [24]byte, client *Client) *Client {
    // Client can be SMP or GRP - doesn't matter
    old, _ := h.subscribers.Swap(queueID, client)
    if old != nil {
        old.SendEND(queueID)  // uses the old client's protocol
        return old
    }
    return nil
}
```

The END notification is sent using whatever protocol the displaced client connected with. If the displaced client used SMP, END is sent via TLS. If it used GRP, END is sent via Noise.

### Subscription Persistence

Subscriptions are bound to connections, not to protocols. When a connection drops (SMP or GRP), all subscriptions on that connection are released. The next SUB command from any protocol re-establishes the subscription.

---

## Server-Side Re-Encryption

SMP defines server-side re-encryption: the server re-encrypts messages using a DH-derived shared secret with the message ID as nonce. This prevents ciphertext correlation between the send and receive sides.

GoRelay implements re-encryption identically for both protocols:

```go
func (s *Server) reEncryptMessage(queue *Queue, msgID [24]byte, body []byte) []byte {
    // DH shared secret from queue creation
    sharedSecret := s.computeDHSecret(queue.ServerDHPrivate, queue.RecipientDHPublic)

    // NaCl crypto_box seal with msgID as nonce
    var nonce [24]byte
    copy(nonce[:], msgID[:])

    return box.Seal(nil, body, &nonce, queue.RecipientDHPublic, queue.ServerDHPrivate)
}
```

The same re-encryption is applied regardless of whether the message arrived via SMP or GRP. The recipient decrypts using the server's DH public key (received during queue creation) and the message ID.

---

## SMP Protocol Version Compatibility

GoRelay implements SMP protocol version 7 and above. The SMP version handshake works as follows:

1. Server sends its supported version range: `minVersion=7, maxVersion=8`
2. Client sends its supported version range
3. Both sides agree on the highest mutually supported version

GoRelay tracks SMP protocol evolution and updates its implementation to maintain compatibility with the latest SimpleX Chat client releases.

### SMP Features Supported

| Feature | SMP Version | GoRelay Support |
|---|---|---|
| Basic queue operations | v1+ | Yes |
| Batched transmissions | v4+ | Yes |
| Server-side re-encryption | v5+ | Yes |
| Private Message Routing (PMR) | v7+ | Yes |
| SEND with flags | v7+ | Yes |
| Queue rotation commands | v8+ | Yes |

### SMP Features NOT Supported

| Feature | Reason |
|---|---|
| XFTP (file transfer protocol) | Separate protocol, not part of SMP relay |
| Push notifications (APNS/FCM) | Requires integration with Apple/Google services |
| Agent-level protocol | Client-side protocol, not relay concern |

---

## Server URI Formats

GoRelay publishes two server URIs - one for each protocol:

**SMP URI (for SimpleX Chat compatibility):**
```
smp://<tls-certificate-fingerprint>@<host>:5223
```

**GRP URI (for GRP-native clients):**
```
grp://<noise-static-key-b64>:<mlkem-encaps-key-b64>@<host>:7443
```

A SimpleGo device stores both URIs for its configured server. When communicating with a SimpleX Chat user, it creates queues via SMP. When communicating with another SimpleGo device, it uses GRP.

The client determines which protocol to use based on the URI scheme provided by the contact.

---

## SMP Command Translation

GRP commands are a superset of SMP commands. The shared queue store means no translation is needed for core operations:

| Operation | SMP Command | GRP Command | Queue Store Operation |
|---|---|---|---|
| Create queue | NEW | NEW | Identical |
| Subscribe | SUB | SUB | Identical |
| Set sender key | KEY | KEY | Identical |
| Send message | SEND | SEND | Identical |
| Deliver message | MSG | MSG | Identical |
| Acknowledge | ACK | ACK | Identical |
| Disable queue | OFF | OFF | Identical |
| Delete queue | DEL | DEL | Identical |
| Keep-alive | PING/PONG | PING/PONG | Identical |
| Forward message | N/A (PMR) | PFWD/RFWD | GRP extension |
| Queue rotation | N/A | QROT/QACK | GRP extension |

SMP's PMR (Private Message Routing) commands (PFWD, RFWD, PRES, RRES) are functionally equivalent to GRP's relay routing commands. GoRelay implements both command sets, mapping them to the same internal forwarding logic.

---

## Testing Interoperability

GoRelay maintains an integration test suite that verifies cross-protocol operation:

```
test_smp_create_grp_subscribe:
  1. SMP client creates queue via NEW
  2. GRP client subscribes via SUB
  3. SMP client sends message via SEND
  4. Verify GRP client receives MSG
  5. GRP client sends ACK
  6. Verify message deleted

test_grp_create_smp_subscribe:
  1. GRP client creates queue via NEW
  2. SMP client subscribes via SUB
  3. GRP client sends message via SEND
  4. Verify SMP client receives MSG

test_cross_protocol_subscription_takeover:
  1. SMP client subscribes to queue
  2. GRP client subscribes to same queue
  3. Verify SMP client receives END
  4. Verify GRP client receives subsequent messages

test_smp_pmr_through_grp_relay:
  1. SMP client sends PFWD to GoRelay
  2. GoRelay forwards via RFWD to second GoRelay
  3. Verify delivery to recipient
```

These tests run against every GoRelay build to ensure that SMP compatibility is never accidentally broken by GRP development.

---

## Limitations

**No GRP benefits for SMP clients.** SimpleX Chat apps connecting via SMP do not receive GRP's enhanced security properties (mandatory PQC, cover traffic, automatic queue rotation). They receive standard SMP security, which is already strong.

**Server-side cover traffic helps SMP recipients.** When an SMP client is subscribed and connected, the server CAN generate cover traffic for the SMP delivery path. The SMP client will receive and discard blocks that do not parse as valid SMP transmissions.

**No cross-protocol relay routing.** Two-hop routing works within GRP (GRP client to GRP relay to GRP relay) and within SMP's PMR (SMP client to SMP relay to SMP relay). Cross-protocol routing (SMP client forwarding through a GRP relay path) is not currently specified.

**Queue creation protocol matters for identity model.** A queue created via SMP uses the TLS certificate fingerprint as server identity. A queue created via GRP uses the Noise static key. Both queues function identically at the storage layer, but clients must use the correct identity verification for their protocol.

---

*GoRelay Protocol Specification - IT and More Systems, Recklinghausen*
