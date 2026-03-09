---
title: "GoRelay Documentation"
sidebar_position: 1
slug: /intro
---

# GoRelay Documentation

Welcome to the GoRelay documentation. GoRelay is a lightweight, zero-knowledge encrypted relay server for the SimpleGo ecosystem, written in Go.

## What is GoRelay?

GoRelay is a dual-protocol relay server that implements both the SimpleX Messaging Protocol (SMP) for backward compatibility and the GoRelay Protocol (GRP) - an enhanced protocol designed from the ground up with stronger security properties.

The server acts as a message relay: clients push encrypted messages into queues, and recipients collect them. GoRelay never decrypts content, never logs metadata, and deletes messages immediately upon delivery confirmation. When served with a court order, there is nothing to provide.

## Core Design Principles

**1:1 messaging only.** No group chats, no broadcast channels. Every message uses full Double Ratchet with Perfect Forward Secrecy. No compromises like Sender Keys or Megolm.

**Zero-knowledge by design.** The server is a dumb pipe. It stores encrypted blobs, delivers them, and forgets them. No user accounts, no identities, no metadata.

**Post-quantum from day one.** GRP mandates hybrid X25519 + ML-KEM-768 key exchange. Not optional, not configurable, not "coming soon."

**Single binary deployment.** One static Go binary under 20 MB. No runtime dependencies, no external databases, no container orchestration required.

## Documentation Structure

**Research** contains the technical analysis that informed GoRelay's design - existing system analysis, protocol comparisons, and the security landscape review.

**GRP Protocol Specification** is the formal protocol definition with byte-level formats, state machines, cryptographic primitive justifications, and test vectors.

**Server Architecture** covers GoRelay's internals: connection lifecycle, queue storage, subscription management, and the dual-protocol design.

**Deployment** provides practical guides for running GoRelay in production: Docker, systemd, configuration, and TLS certificate management.

**Development** contains contributor guidelines, code style conventions, and testing strategy.

**Session Log** is the complete development history - every session documented with technical decisions, code changes, and lessons learned.

## Project Links

- **GoRelay Repository:** [github.com/saschadaemgen/GoRelay](https://github.com/saschadaemgen/GoRelay)
- **SimpleGo Client:** [github.com/saschadaemgen/SimpleGo](https://github.com/saschadaemgen/SimpleGo)
- **SimpleGo Website:** [simplego.dev](https://simplego.dev)

---

*GoRelay - IT and More Systems, Recklinghausen*
*Zero-knowledge relay infrastructure for the SimpleGo platform*
