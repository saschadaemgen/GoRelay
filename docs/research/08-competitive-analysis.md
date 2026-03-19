---
title: "Competitive Landscape Analysis"
sidebar_position: 8
---

# Competitive Landscape Analysis

*How GoRelay compares to every major encrypted relay and messaging server, and why the combination of Go + zero-knowledge + mandatory PQC + single binary is currently unoccupied.*

**Research date:** 2026-03-09 (Session 001)

---

## The Encrypted Relay Landscape

The market for encrypted messaging infrastructure divides into four categories, each with significant limitations that GoRelay addresses. No existing server combines zero-knowledge architecture, Go's deployment simplicity, mandatory post-quantum cryptography, and active traffic analysis resistance in a single binary.

---

## SimpleX SMP Server

**Language:** Haskell
**License:** AGPL-3.0
**Protocol:** SMP (SimpleX Messaging Protocol)
**Repository:** github.com/simplex-chat/simplexmq

### Strengths

SimpleX provides the best metadata protection of any messaging system. No user identifiers of any kind - no phone numbers, no usernames, no public keys as identity. Unidirectional simplex queues with separate sender and recipient IDs that cannot be correlated without server access. Server-side re-encryption prevents ciphertext correlation across hops. Fixed 16 KB block framing prevents size-based traffic analysis.

The protocol design is genuinely innovative. The separation of sender and recipient identifiers, the implicit subscription model, and the zero-identity architecture represent real advances in private messaging protocol design.

### Limitations

**Haskell ecosystem.** The GHC runtime adds deployment complexity. Cross-compilation is extremely difficult - Docker images support amd64 only. Build times of 10-30 minutes for clean builds. The developer pool is approximately 2% of professional developers, limiting community contributions.

**No post-quantum cryptography.** CRYSTALS-Kyber support exists as an optional flag (`has_kem=true/false`) but is not mandatory. Optional security features protect only users who actively enable them.

**No active cover traffic.** Fixed-size blocks prevent size-based analysis, but timing-based analysis remains possible. No dummy message generation.

**Unaudited crypto libraries.** The Haskell cryptographic libraries (cryptonite/crypton, hs-tls) have never received an independent security audit. Trail of Bits audited the SimpleX application but found a medium-severity X3DH implementation error that Haskell's type system did not catch.

**Private Message Routing is optional.** Two-hop relay routing exists since v5.8 but is not enabled by default in all configurations.

### GoRelay's Advantage

GoRelay maintains full SMP compatibility while adding GRP with mandatory PQC, mandatory two-hop routing, active cover traffic, and deploying as a single static binary with audited cryptography.

---

## Matrix Synapse and Dendrite

**Language:** Python (Synapse), Go (Dendrite)
**License:** Apache 2.0
**Protocol:** Matrix
**Repositories:** github.com/matrix-org/synapse, github.com/matrix-org/dendrite

### Strengths

Matrix is the most feature-rich federated messaging protocol. Room-based architecture supports groups, spaces, threads, and rich media. Federation allows independent servers to communicate. The ecosystem includes bridges to Signal, Telegram, WhatsApp, Slack, IRC, and dozens of other platforms. Element (the primary client) is polished and widely used. The French government, German military (BwMessenger), and NATO have adopted Matrix for official communications.

Dendrite (the Go implementation) compiles to a single binary and is significantly easier to deploy than Synapse.

### Limitations

**Extensive metadata exposure.** Matrix servers see user IDs (@user:server.org), room memberships, message timestamps, device information, typing indicators, read receipts, and presence status. Even with E2E encryption enabled, the server has a complete social graph of who is in which room and when they are active.

**E2E encryption is optional.** Rooms can be created without encryption. Even in encrypted rooms, the Megolm group ratchet provides weaker forward secrecy than pairwise Double Ratchet - a compromised session key exposes all messages in that ratchet epoch.

**No post-quantum cryptography.** No PQC implementation or announced timeline as of early 2026.

**Complex deployment.** Synapse requires PostgreSQL or SQLite, significant memory (4+ GB for moderate deployments), and careful tuning. Dendrite is simpler but still requires a database.

**Persistent message history.** Messages are retained indefinitely by default. Server administrators can configure retention policies, but the protocol is designed around synchronized persistent history.

### GoRelay's Advantage

GoRelay provides zero metadata exposure where Matrix exposes everything. No user identities, no room memberships, no timestamps, no social graph. The trade-off is feature richness - GoRelay is a relay, not a collaboration platform.

---

## Signal Server

**Language:** Java/Rust
**License:** AGPL-3.0
**Protocol:** Signal Protocol (X3DH + Double Ratchet)
**Repository:** github.com/signalapp/Signal-Server

### Strengths

Signal has the strongest end-to-end encryption of any mainstream messenger. The Signal Protocol (X3DH key agreement + Double Ratchet) is the gold standard, formally verified, and adopted by WhatsApp, Facebook Messenger, and Google Messages. Signal introduced PQXDH (post-quantum key exchange) in 2023 and SPQR ("Triple Ratchet" with ongoing PQ ratcheting) in 2025.

Signal's legal track record is impeccable. When subpoenaed, they provide only account creation date and last connection date - nothing else.

### Limitations

**Impossible to self-host.** The Signal server requires FoundationDB, PostgreSQL, Redis, DynamoDB (or compatible), S3 storage, and proprietary anti-spam/anti-abuse modules. Multiple independent attempts to self-host Signal have been abandoned due to complexity. Signal explicitly discourages federation and third-party servers.

**Centralized infrastructure.** All Signal traffic flows through Signal Foundation servers in the United States. Users cannot choose their relay server or jurisdiction.

**Phone number requirement.** Signal requires a phone number for registration, creating a persistent identifier linked to real-world identity. Signal is working on usernames but phone numbers remain the primary identifier.

**Server code transparency issues.** Signal went months without updating their public server repository (April to December 2021), raising questions about whether the deployed code matches the published code.

**No cover traffic.** Signal does not generate dummy messages for traffic analysis resistance.

### GoRelay's Advantage

GoRelay is trivially self-hostable (single binary, zero dependencies). No phone numbers, no accounts, no centralized infrastructure. Users choose their own relay servers in their preferred jurisdictions.

---

## Cwtch

**Language:** Go
**License:** MIT
**Protocol:** Custom (Tor-based)
**Repository:** git.openprivacy.ca/cwtch.im/cwtch

### Strengths

Cwtch is the closest existing project to GoRelay's philosophy. Written in Go, designed for privacy-preserving messaging with untrusted relay servers. No user registration required. Metadata-resistant design where servers cannot learn who is communicating with whom.

The Cwtch protocol routes all traffic through Tor, providing strong network-level anonymity. Relay servers are Tor onion services, hiding their network location.

### Limitations

**Requires Tor.** Every connection must traverse the Tor network, adding 100-300ms latency per hop and requiring Tor to be running. This limits deployment scenarios - corporate networks, IoT devices, and many mobile networks block or throttle Tor traffic.

**Small ecosystem.** Limited client support, small user base, minimal third-party development.

**No post-quantum cryptography.** No PQC implementation.

**Performance constraints.** Tor's bandwidth limitations restrict the volume and speed of message delivery.

### GoRelay's Advantage

GoRelay provides metadata protection through two-hop relay routing and cover traffic without requiring Tor. This enables deployment on any network, any device, with predictable low latency. Tor can be used as an additional layer if desired, but is not required.

---

## XMPP Servers (ejabberd, Prosody)

**Language:** Erlang (ejabberd), Lua (Prosody)
**License:** GPL-2.0 (ejabberd), MIT (Prosody)
**Protocol:** XMPP

### Strengths

XMPP is the most mature open federated messaging protocol, with 25+ years of development. Extensive XEP (XMPP Extension Protocol) ecosystem covers nearly every messaging feature imaginable. Strong federation support with millions of federated servers. OMEMO (based on Signal Protocol) provides E2E encryption.

### Limitations

**Metadata-rich by design.** XMPP uses JIDs (user@server.org) as permanent identifiers. Servers see full contact lists (roster), presence information, and message metadata. Federation requires exposing user identifiers across server boundaries.

**E2E encryption is an afterthought.** OMEMO was bolted onto XMPP years after the protocol was designed. Many features (group chat, file transfer, message search) do not work with E2E encryption enabled.

**Complex deployment.** ejabberd requires Erlang runtime. Prosody requires Lua. Both need external databases for any non-trivial deployment.

**No post-quantum cryptography.** No PQC in any XMPP implementation.

### GoRelay's Advantage

GoRelay starts from a zero-identity foundation rather than trying to add privacy to an identity-centric protocol.

---

## Briar

**Language:** Java/Kotlin
**License:** GPL-3.0
**Protocol:** Bramble

### Strengths

Briar is designed for extreme conditions - it works without internet infrastructure using Bluetooth, WiFi direct, and SD card exchange. All data is stored on-device only, never on servers. Strong threat model focused on activists and journalists in hostile environments.

### Limitations

**Android only.** No iOS, no desktop client (a desktop version is in development but incomplete).

**No relay servers.** Briar is purely peer-to-peer, meaning both parties must be online simultaneously for direct messaging (or use Tor-based mailboxes with significant latency).

**No post-quantum cryptography.** No PQC implementation.

### GoRelay's Advantage

GoRelay provides asynchronous message delivery (recipients can be offline) with server infrastructure while maintaining comparable privacy properties.

---

## Comparison Matrix

| Property | GoRelay | SimpleX SMP | Matrix | Signal | Cwtch | XMPP |
|---|---|---|---|---|---|---|
| Language | Go | Haskell | Python/Go | Java/Rust | Go | Erlang/Lua |
| User identifiers | None | None | @user:server | Phone number | None | user@server |
| E2E encryption | Mandatory | Mandatory | Optional | Mandatory | Mandatory | Optional |
| Post-quantum | Mandatory | Optional | None | Yes (PQXDH) | None | None |
| Cover traffic | Yes (Poisson) | Padding only | None | None | Via Tor | None |
| Two-hop routing | Mandatory | Optional (PMR) | N/A (federation) | No | Via Tor | N/A |
| Self-hostable | Single binary | Yes (complex) | Yes (complex) | Practically no | Yes (needs Tor) | Yes (complex) |
| Docker image size | 5-15 MB | 15-100 MB | 500+ MB (Synapse) | N/A | ~50 MB | 50-200 MB |
| Cross-compilation | Trivial | Very difficult | N/A | N/A | Possible | Difficult |
| Crypto audit | Yes (Go stdlib) | App only | Partial | Yes | No | Partial |
| Groups | Via SMP clients | Via clients | Native | Native | Yes | Native |
| Federation | Multi-server | Multi-server | Full federation | No | Tor network | Full federation |
| Metadata on server | None | Minimal | Extensive | Minimal | None | Extensive |

---

## The Unoccupied Niche

GoRelay sits at the intersection of five properties that no other server combines:

1. **Go language** - mainstream ecosystem, easy contributions, single binary, trivial cross-compilation
2. **Zero-knowledge architecture** - no identifiers, no metadata logging, nothing to subpoena
3. **Mandatory post-quantum** - not optional, not negotiated, from handshake one
4. **Active traffic analysis resistance** - cover traffic + queue rotation + two-hop routing
5. **Minimal deployment** - single static binary under 20 MB with zero dependencies

Each property exists in isolation in other systems. No system combines all five.

---

## Market Context

The encrypted messaging market was valued at approximately $357 million in 2025 with an 11.4% compound annual growth rate projected through 2033. Decentralized and privacy-focused messaging (SimpleX, Session, Briar, Cwtch) is gaining users, with prominent advocates including Vitalik Buterin publicly endorsing metadata-private messaging.

Regulatory pressure creates contradictory forces: GDPR and NIS2 drive encryption adoption while proposed regulations like the EU's Chat Control aim to mandate client-side scanning. Systems that store no metadata and provide no backdoors are simultaneously more legally compliant (GDPR data minimization) and more resistant to surveillance mandates.

GoRelay's "nothing to provide" architecture positions it on the right side of both regulatory trends: fully GDPR-compliant through data minimization, and technically resistant to metadata collection mandates.

---

*GoRelay - IT and More Systems, Recklinghausen*
