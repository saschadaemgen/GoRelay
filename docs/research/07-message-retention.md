---
title: "Message Retention and Legal Analysis"
sidebar_position: 7
---

# Message Retention and Legal Analysis

*How GoRelay's aggressive message deletion strategy aligns with GDPR, German telecommunications law, and the legal precedents set by Signal and other encrypted messaging services.*

**Research date:** 2026-03-09 (Session 001)

---

## GoRelay's Retention Policy

GoRelay follows a simple principle: if data does not need to exist, it must not exist. The retention policy has three tiers:

**Immediate deletion on ACK.** When a recipient acknowledges a message, the server deletes it permanently. This is the primary deletion path - most messages exist on the server for seconds or minutes.

**48-hour default TTL.** If a recipient does not come online to collect a message within 48 hours, the server deletes it automatically. This gives offline users a full weekend to reconnect while limiting the window of exposure.

**7-day hard maximum.** No message can exist on the server for more than 7 days under any circumstances. This is a server-enforced limit that cannot be overridden by configuration. After 7 days, the message is gone regardless of recipient status.

**Zero metadata logging.** GoRelay does not log IP addresses, connection timestamps, queue-to-IP mappings, or any other metadata to persistent storage. When a connection closes, all connection-related information exists only in volatile memory and disappears with the next garbage collection cycle.

---

## How Other Systems Handle Retention

### Signal

Signal's servers store messages only until they are delivered, with a maximum retention of 30 days for undelivered messages. Signal's legal response to subpoenas has become the gold standard for privacy-preserving services. When served with a grand jury subpoena in 2016, Signal could only provide two data points per account: the date the account was created and the date of last connection. No message content, no contact lists, no group memberships, no metadata.

This legal precedent demonstrates that "we have nothing to provide" is a viable and legally defensible position. GoRelay aims to have even less than Signal - no account creation date (GoRelay has no accounts) and no last connection date (GoRelay does not log connections).

### SimpleX

SimpleX servers retain messages until delivery or until a configurable expiry period (default 21 days). The server stores no user identities by design - only queue records with cryptographic keys. Self-hosted SimpleX servers can configure shorter retention periods.

### Matrix

Matrix takes a fundamentally different approach. Synapse (the reference homeserver) retains message history indefinitely by default. Server administrators can configure retention policies per-room with minimums of 1 day and maximums of 1 year. The Matrix protocol itself is designed around persistent, synchronized history - deletion is an afterthought rather than a default.

This makes Matrix poorly suited for high-privacy use cases despite supporting end-to-end encryption. The server retains encrypted message blobs, room membership, timestamps, and extensive metadata.

---

## GDPR Alignment

The General Data Protection Regulation provides strong legal support for GoRelay's approach.

### Article 5(1)(c) - Data Minimization

Personal data must be "adequate, relevant and limited to what is necessary in relation to the purposes for which they are processed." A relay server's purpose is message delivery, not message storage. Retaining messages beyond the point of delivery serves no legitimate purpose. Immediate deletion on ACK is the most GDPR-aligned approach possible.

### Article 5(1)(e) - Storage Limitation

Personal data must be "kept in a form which permits identification of data subjects for no longer than is necessary for the purposes for which the personal data are processed." Since GoRelay does not identify data subjects at all (no accounts, no user IDs, no IP logging), and message content is encrypted (the server cannot read it), the storage limitation principle is satisfied by design.

### IP Addresses as Personal Data

The Court of Justice of the European Union ruled in Breyer v Germany (2016) that dynamic IP addresses constitute personal data when the operator has the legal means to identify the user (which ISPs do). By not logging IP addresses at all, GoRelay eliminates an entire category of GDPR compliance obligations. There is no data subject access request to fulfill, no data breach to notify about, and no processing purpose to justify - because the data was never collected.

### Data Protection Impact Assessment

Under Article 35, a DPIA is required for processing that is "likely to result in a high risk to the rights and freedoms of natural persons." A relay server that processes encrypted blobs without the ability to read them, does not identify users, and deletes everything on delivery arguably does not meet the threshold for "high risk" - but conducting a DPIA voluntarily demonstrates good faith and can be published as a transparency measure.

---

## German Telecommunications Law

### Vorratsdatenspeicherung (Data Retention)

Germany's telecommunications data retention law (Section 175 TKG) required telecommunications providers to retain connection data (who communicated with whom, when, from where) for 4-10 weeks. This law was suspended by the Federal Network Agency (BNetzA) in June 2017 and has not been enforced since.

The Court of Justice of the European Union delivered the decisive blow on September 20, 2022 in the SpaceNet/Telekom Deutschland ruling, finding that Germany's blanket data retention provisions violate EU law. Germany has since pursued a "quick-freeze" model instead of blanket retention - authorities can order the preservation of specific data for specific suspects, but there is no obligation to retain data speculatively.

### Quick-Freeze Implications

Under quick-freeze, a GoRelay operator could theoretically receive an order to preserve data related to a specific queue or connection going forward. However, if the server does not log metadata and deletes messages on delivery, there is nothing to freeze. The quick-freeze model only works if the data exists in the first place.

This is not legal evasion - it is the natural consequence of building a system designed around the data minimization principle. GoRelay does not avoid legal obligations; it simply has no data to provide when asked.

### TKG Classification

Whether GoRelay qualifies as a "telecommunications service" under the TKG depends on whether it provides "signal transmission" as a service to the public. A self-hosted relay server used by a small group likely falls below the threshold. A publicly offered relay service may qualify, in which case TKG obligations around network security and emergency services apply - but data retention (the most burdensome obligation) remains suspended.

---

## ePrivacy Directive

Article 6 of the ePrivacy Directive (2002/58/EC) requires that "traffic data relating to subscribers and users processed and stored by the provider of a public communications network or publicly available electronic communications service must be erased or made anonymous when it is no longer needed for the purpose of the transmission of a communication."

GoRelay's approach of not generating traffic data in the first place is the strongest possible compliance posture. You cannot fail to erase data that was never created.

---

## BadgerDB TTL for Automatic Expiry

GoRelay uses BadgerDB's native TTL (Time-To-Live) feature for automatic message expiry:

```go
entry := badger.NewEntry(key, encryptedMessage).WithTTL(48 * time.Hour)
err := db.Update(func(txn *badger.Txn) error {
    return txn.SetEntry(entry)
})
```

After the TTL elapses, the key returns `ErrKeyNotFound` on read and becomes eligible for garbage collection. A background goroutine calls `db.RunValueLogGC(0.5)` every 5 minutes to reclaim disk space from expired entries.

The 7-day hard maximum is enforced independently of BadgerDB's TTL as a defense-in-depth measure:

```go
func (s *Store) PushMessage(queueID string, msg []byte) error {
    ttl := s.config.DefaultTTL  // 48 hours
    if ttl > 7 * 24 * time.Hour {
        ttl = 7 * 24 * time.Hour  // hard cap
    }
    // ...
}
```

---

## Cryptographic Deletion

Beyond TTL-based expiry, GoRelay implements cryptographic deletion for defense-in-depth:

Each stored message is encrypted with a per-message random symmetric key. The encrypted message blob and the key are stored in separate BadgerDB entries:

```
q:<queueID>:msg:<seq>:data  -> encrypted message blob
q:<queueID>:msg:<seq>:key   -> 32-byte symmetric key
```

On delivery ACK, the key entry is securely zeroed and deleted. Even if the encrypted blob persists temporarily before garbage collection, it is unreadable without the key. This provides forward secrecy at the storage layer - a disk forensics analysis after message delivery finds only encrypted blobs with no corresponding keys.

Periodic rotation of a master storage key provides additional protection. Every 24 hours, GoRelay generates a new master key and re-encrypts any remaining messages. Old master keys are securely destroyed. An adversary who obtains a disk snapshot can only access messages encrypted with the current master key, not historical ones.

---

## Subpoena Response

When (not if) GoRelay receives a legal request for data, the response is:

**Message content:** Not available. Messages are end-to-end encrypted and deleted on delivery. The server cannot read message content at any point during processing.

**Metadata (who communicated with whom):** Not available. The server does not log connection-to-queue mappings. Queue IDs are random 24-byte values with no linkage to user identities.

**IP addresses:** Not available. The server does not log IP addresses.

**Connection history:** Not available. Connection events are not logged to persistent storage.

**Account information:** Not applicable. GoRelay has no user accounts, no registration, no identifiers.

**Queue contents (undelivered messages):** Encrypted blobs may exist for messages not yet delivered (up to 7 days). These are end-to-end encrypted and the server does not possess the decryption keys. The blobs can be provided but are useless without the recipient's private key.

This is a stronger position than Signal (which can provide account creation date and last connection date) and equivalent to the strongest possible legal position for a communications intermediary.

---

## Operational Security Recommendations

For GoRelay server operators who want to maximize legal protection:

**Run servers in privacy-friendly jurisdictions.** Germany, Switzerland, Iceland, and the Netherlands have strong data protection frameworks. Avoid jurisdictions with mandatory decryption laws (Australia, UK's IPA).

**Use full-disk encryption.** Encrypt the server's storage volume so that physical seizure of the server yields only encrypted data. LUKS on Linux with a strong passphrase.

**Enable automatic key destruction.** Configure the server to securely wipe its TLS/Noise private keys and BadgerDB encryption keys on any unauthorized shutdown or tampering detection.

**Separate logging from relay.** Run the relay process with no write access to syslog, journald, or any persistent logging facility. Use a minimal systemd unit with `StandardOutput=null` and `StandardError=null`.

**Document the architecture.** Publish the server's privacy architecture so that law enforcement understands the technical limitations before serving requests. This saves time for everyone and prevents contempt-of-court situations where an operator is ordered to produce data they genuinely cannot produce.

---

*GoRelay - IT and More Systems, Recklinghausen*
