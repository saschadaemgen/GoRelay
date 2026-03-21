---
title: "Queue Store"
sidebar_position: 3
---

# BadgerDB Queue Store

*How GoRelay persists queues and messages using BadgerDB with native TTL, cryptographic deletion, and zero external dependencies.*

**Status:** In development
**Date:** 2026-03-09 (Session 001)

---

## Why BadgerDB

GoRelay needs an embedded key-value store that satisfies four requirements:

1. **Zero external dependencies:** No PostgreSQL, no Redis, no separate process. The database is embedded in the binary.
2. **Native TTL:** Automatic expiry of messages without custom cleanup logic.
3. **LSM-tree architecture:** Keys in memory for fast lookups, values on disk for large message blobs.
4. **Pure Go:** No CGO, clean cross-compilation, full benefit of Go's tooling.

BadgerDB v4 (`github.com/dgraph-io/badger/v4`) satisfies all four. It is used in production by Dgraph (distributed graph database), Minio, and numerous Go projects.

### Rejected Alternatives

| Database | Rejection Reason |
|---|---|
| BoltDB/bbolt | No native TTL, values in memory (bad for large blobs) |
| SQLite (via CGO) | Requires CGO, breaks cross-compilation |
| Pebble | No native TTL |
| LevelDB | CGO wrapper, no native TTL |
| PostgreSQL | External dependency, massive operational overhead |
| Redis | External dependency, primarily in-memory |

---

## Key Schema

All keys follow a hierarchical pattern using `:` as separator:

### Queue Keys

```
q:<recipientID>:meta           -> Queue metadata (protobuf or gob encoded)
q:<recipientID>:sender         -> SenderID mapping (24 bytes)
q:<recipientID>:rkey           -> Recipient Ed25519 public key (32 bytes)
q:<recipientID>:skey           -> Sender Ed25519 public key (32 bytes)
q:<recipientID>:dh:pub         -> Server DH public key (32 bytes)
q:<recipientID>:dh:priv        -> Server DH private key (32 bytes)
q:<recipientID>:status         -> Queue status byte (ACTIVE/DISABLED/DELETED)
```

### Sender-to-Recipient Index

```
s:<senderID>                   -> RecipientID (24 bytes, reverse lookup)
```

This index enables O(1) lookup when a SEND command arrives with a senderID. Without it, finding the queue would require scanning all queues.

### Message Keys

```
q:<recipientID>:msg:<seq>:data -> Encrypted message blob (variable, up to ~16 KB)
q:<recipientID>:msg:<seq>:key  -> Per-message symmetric key (32 bytes)
q:<recipientID>:msg:<seq>:meta -> Timestamp (8 bytes) + flags (1 byte) + protocol (1 byte)
```

The `<seq>` is a zero-padded 16-digit sequence number (e.g., `0000000000000042`) that ensures lexicographic ordering matches insertion order. This allows BadgerDB's prefix iteration to return messages in delivery order.

### Sequence Counter

```
q:<recipientID>:seq            -> Current sequence number (uint64, big-endian)
```

Atomically incremented for each new message. Ensures monotonic ordering even under concurrent SEND commands.

---

## Operations

### CreateQueue

```go
func (s *BadgerStore) CreateQueue(recipientKey ed25519.PublicKey, dhKey *ecdh.PublicKey) (*Queue, error) {
    recipientID := generateRandomID()  // 24 bytes
    senderID := generateRandomID()     // 24 bytes

    serverDH, _ := ecdh.X25519().GenerateKey(rand.Reader)

    return s.db.Update(func(txn *badger.Txn) error {
        // Check for ID collision (astronomically unlikely with 24 random bytes)
        if _, err := txn.Get(queueKey(recipientID, "meta")); err == nil {
            return ErrDuplicateID  // regenerate and retry
        }

        txn.Set(queueKey(recipientID, "rkey"), recipientKey)
        txn.Set(queueKey(recipientID, "dh:pub"), serverDH.PublicKey().Bytes())
        txn.Set(queueKey(recipientID, "dh:priv"), serverDH.Bytes())
        txn.Set(queueKey(recipientID, "status"), []byte{StatusActive})
        txn.Set(senderKey(senderID), recipientID[:])
        txn.Set(queueKey(recipientID, "sender"), senderID[:])
        txn.Set(queueKey(recipientID, "seq"), uint64ToBytes(0))

        return nil
    })
}
```

All operations within a single BadgerDB transaction - either everything succeeds or nothing does.

### PushMessage

```go
func (s *BadgerStore) PushMessage(senderID [24]byte, flags byte, body []byte) (*MessageID, error) {
    // Look up recipient ID from sender ID
    recipientID, err := s.getRecipientID(senderID)
    if err != nil {
        return nil, ErrNoQueue
    }

    return s.db.Update(func(txn *badger.Txn) error {
        // Increment sequence counter
        seq, err := s.incrementSequence(txn, recipientID)
        if err != nil {
            return err
        }

        // Generate message ID
        msgID := generateMessageID(seq)

        // Generate per-message encryption key
        msgKey := make([]byte, 32)
        rand.Read(msgKey)

        // Encrypt message body with per-message key
        encrypted := encryptMessage(msgKey, body)

        // Store with TTL
        ttl := s.config.DefaultTTL  // 48 hours
        if ttl > 7*24*time.Hour {
            ttl = 7 * 24 * time.Hour  // hard cap
        }

        txn.SetEntry(badger.NewEntry(
            msgDataKey(recipientID, seq), encrypted,
        ).WithTTL(ttl))

        txn.SetEntry(badger.NewEntry(
            msgKeyKey(recipientID, seq), msgKey,
        ).WithTTL(ttl))

        txn.SetEntry(badger.NewEntry(
            msgMetaKey(recipientID, seq), encodeMeta(msgID, flags),
        ).WithTTL(ttl))

        return nil
    })
}
```

### AckMessage (with Cryptographic Deletion)

```go
func (s *BadgerStore) AckMessage(recipientID [24]byte, msgID [24]byte) error {
    return s.db.Update(func(txn *badger.Txn) error {
        seq := msgIDToSequence(msgID)

        // Read and zero the per-message key FIRST
        keyItem, err := txn.Get(msgKeyKey(recipientID, seq))
        if err != nil {
            return nil  // already ACKed (idempotent)
        }
        keyItem.Value(func(val []byte) error {
            // Securely zero the key in memory
            for i := range val {
                val[i] = 0
            }
            return nil
        })

        // Delete all message entries
        txn.Delete(msgDataKey(recipientID, seq))
        txn.Delete(msgKeyKey(recipientID, seq))
        txn.Delete(msgMetaKey(recipientID, seq))

        return nil
    })
}
```

The per-message key is zeroed before deletion. Even if the encrypted blob persists temporarily in BadgerDB's value log before garbage collection, it is unreadable without the key.

### PopMessage (Delivery)

```go
func (s *BadgerStore) PopMessage(recipientID [24]byte) (*Message, error) {
    var msg *Message

    err := s.db.View(func(txn *badger.Txn) error {
        // Prefix scan for oldest message
        prefix := []byte(fmt.Sprintf("q:%x:msg:", recipientID))
        opts := badger.DefaultIteratorOptions
        opts.PrefetchSize = 1

        it := txn.NewIterator(opts)
        defer it.Close()

        it.Seek(prefix)
        if !it.ValidForPrefix(prefix) {
            return ErrNoMessage
        }

        // Read message data, key, and meta
        // Decrypt message body using per-message key
        // Construct Message struct
        return nil
    })

    return msg, err
}
```

Pop does NOT delete the message - it reads it for delivery. Deletion happens only on ACK. This ensures reliable delivery even if the connection drops between MSG and ACK.

---

## Garbage Collection

### TTL-Based Expiry

BadgerDB automatically marks expired entries as deleted during compaction. A background goroutine accelerates cleanup:

```go
func (s *BadgerStore) gcLoop(ctx context.Context) {
    ticker := time.NewTicker(5 * time.Minute)
    defer ticker.Stop()

    for {
        select {
        case <-ctx.Done():
            return
        case <-ticker.C:
            for {
                err := s.db.RunValueLogGC(0.5)
                if err == badger.ErrNoRewrite {
                    break  // no more garbage to collect
                }
            }
        }
    }
}
```

The `0.5` threshold means: if a value log file has more than 50% dead entries, rewrite it. This balances disk space reclamation against write amplification.

### Disk Space

For a server with 100 active users, 10 messages/hour average, 48-hour TTL:

```
Messages at any time: 100 users * 10 msg/hr * 48 hr = 48,000 messages
Average message size: 2 KB (encrypted, padded)
Total data: 48,000 * 2 KB = ~96 MB
BadgerDB overhead (2-3x): ~200-300 MB
```

A modest VPS with 20 GB of storage has plenty of headroom.

---

## Backup and Recovery

### Backup

BadgerDB supports online backup via `db.Backup()`:

```go
func (s *BadgerStore) Backup(w io.Writer) error {
    _, err := s.db.Backup(w, 0)  // 0 = full backup
    return err
}
```

The backup is a consistent snapshot that can be taken while the server is running.

### Recovery

On startup, BadgerDB replays its write-ahead log (WAL) to recover from crashes. No manual recovery is needed - the database is crash-consistent by design.

### Master Key Rotation

Every 24 hours, the server generates a new master storage key and re-encrypts the BadgerDB encryption key:

```go
func (s *BadgerStore) rotateMasterKey(ctx context.Context) {
    ticker := time.NewTicker(24 * time.Hour)
    for {
        select {
        case <-ctx.Done():
            return
        case <-ticker.C:
            newKey := generateMasterKey()
            s.reEncryptWithNewKey(newKey)
            secureZero(s.currentMasterKey)
            s.currentMasterKey = newKey
        }
    }
}
```

Old master keys are securely zeroed. An adversary who obtains a disk snapshot can only access data encrypted with the current master key.

---

## Configuration

```yaml
store:
  path: "/var/lib/gorelay/data"    # BadgerDB data directory
  encryption_key: ""                # auto-generated on first run
  default_ttl: "48h"               # message TTL
  max_ttl: "168h"                  # 7 days hard maximum
  gc_interval: "5m"                # garbage collection frequency
  gc_threshold: 0.5                # dead entry threshold for GC
  max_message_size: 16382          # bytes (matching block payload max)
  backup_interval: "6h"            # automatic backup frequency
  backup_path: "/var/lib/gorelay/backups"
```

---

*GoRelay - IT and More Systems, Recklinghausen*
