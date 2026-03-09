---
title: "Haskell vs Go for Relay Servers"
sidebar_position: 10
---

# Haskell vs Go for Encrypted Relay Servers

*Why SimpleX chose Haskell, why its creator would rewrite in Rust, and why Go is the right choice for GoRelay.*

**Research date:** 2026-03-09 (Session 001)

---

## SimpleX Started in Go - Then Abandoned It

The SimpleX SMP server was originally prototyped in Go in early 2020 by Evgeny Poberezkin. The archived repository `simplex-server-go` (7 commits, 8 stars) remains on GitHub as evidence. Evgeny abandoned Go after months of frustration and switched to Haskell, a language he had never used before. He rebuilt the server in approximately one week.

His stated reasons for choosing Haskell: green threads for massive concurrency, composable STM (Software Transactional Memory) for race-condition-free concurrent code, a strong parsing ecosystem for custom binary protocols, and dependent types (simulated via singletons) for encoding protocol invariants at the type level.

However, Evgeny has been transparent about Haskell's limitations. In a Serokell interview, he stated that all programming languages are equally terrible and that Haskell is no exception. He added that if the team had more funding, they would probably rewrite everything in Rust. The growing Haskell codebase (shared across server, agent, and mobile clients) creates path dependency that makes rewriting impractical.

---

## Performance Comparison

### Garbage Collection - The Critical Difference

Go's concurrent mark-and-sweep GC delivers sub-millisecond stop-the-world pauses consistently. Haskell's GHC runtime produces pauses proportional to live working set size:

| Metric | Haskell (GHC) | Go |
|---|---|---|
| GC pause (typical) | 20us - 200ms (varies by GC mode) | <1ms |
| GC worst case (production) | 150 - 800ms+ | 7 - 19ms |
| Thread initial stack | ~1 KB | 2 KB |
| Startup time | ~1.4ms | ~0.4ms |

Pusher (pub/sub message bus) migrated from Haskell to Go specifically because of GC pauses exceeding 50ms with a ~200MB working set. Cachix reported GC pauses up to 800ms. NoRedInk achieved 13ms p99 latency only after extensive RTS tuning.

For SMP relay servers specifically, the working set is small (messages deleted after delivery), which mitigates Haskell's worst GC behavior. But Go's GC simply does not have this problem at any scale.

### Concurrency Models

Both languages excel at concurrency through different mechanisms. Haskell uses green threads with STM for composable atomic transactions. Go uses goroutines with channels for message passing. Both use M:N scheduling with epoll/kqueue internally. Both handle millions of lightweight threads.

The practical difference is complexity. Starting a concurrent handler in Go: `go handleConnection(conn)`. In Haskell: understanding monads, STM semantics, async exceptions, and the runtime scheduler.

---

## Deployment - Where Go Wins Decisively

| Dimension | Haskell | Go | Difference |
|---|---|---|---|
| Clean build time | 10 - 30 min | 0.5 - 2 min | 10 - 15x slower |
| Binary size (static) | 20 - 100 MB | 5 - 20 MB | 3 - 5x larger |
| Docker image (minimal) | 15 - 100 MB | 3 - 15 MB | 3 - 10x larger |
| Cross-compilation | Days of configuration | One environment variable | Incomparable |
| Build toolchain install | 20+ min (ghcup + system deps) | <1 min (single binary) | 20x slower |
| Developer pool | ~2% of professionals | ~13.5% of professionals | ~7x smaller |

SimpleX Docker images support amd64 only. A Go equivalent trivially produces binaries for linux/amd64, linux/arm64, darwin/amd64, darwin/arm64, and windows/amd64.

The simplexmq build requires GHC 9.6.3, Cabal 3.10.x, and approximately 10 system-level C library dependencies (libgmp, zlib, OpenSSL, libnuma, etc.). Go requires downloading a single binary.

---

## Cryptographic Library Audits - The Security Gap

This is the most critical comparison for a security-focused project.

**Haskell (cryptonite/crypton, hs-tls):** No independent security audit has ever been conducted on these libraries. Trail of Bits' 2022 audit of SimpleX found a medium-severity X3DH key exchange implementation error that Haskell's type system did not catch - the KDF was not applied correctly to the DH output concatenation. The types were compatible (both bytestring-like), so the compiler accepted incorrect code.

**Go (crypto/*):** Trail of Bits conducted a comprehensive audit in 2025 - three engineers, one month, covering ECDH, ML-KEM, ECDSA, RSA, Ed25519, AES-GCM, SHA-1/2/3, HKDF, HMAC, and assembly implementations. Result: one low-severity finding in a legacy CGO module that nobody uses. Go's crypto module is also pursuing FIPS 140-3 certification (CAVP certificate A6650).

For a project whose entire value proposition is security, using audited cryptographic libraries is not optional.

---

## AI-Assisted Development

Go is significantly better suited for AI-assisted development (Claude Code, GitHub Copilot):

- Go's syntax is simpler - fewer ways to write incorrect code
- No lifetime/borrow checker errors (vs. Rust)
- No monad/type class complexity (vs. Haskell)
- Faster compilation means faster feedback loops for AI agents
- Go's explicit error handling is easier for AI to generate correctly than Haskell's exception-based model

Evgeny Poberezkin himself uses Claude Code extensively and wrote the entire XFTP browser implementation with AI assistance - but in TypeScript, not Haskell.

---

## Where Haskell Genuinely Wins

To be fair, Haskell has real advantages that Go cannot replicate:

**Type-level protocol safety.** Parameterized command types distinguish server commands from client commands at compile time. Separate newtypes for RecipientPrivateKey, SenderPublicKey, RecipientId, and SenderId make key confusion structurally impossible.

**STM composability.** Atomic transactions that automatically retry on conflict, with no possibility of deadlock. The STM monad prevents I/O inside transactions, guaranteeing no side effects during retries.

**Purity as documentation.** Pure functions cannot have side effects - the type signature tells you everything about what the function can do.

These are genuine engineering advantages. But they do not compensate for unaudited crypto libraries, impossible cross-compilation, and a developer pool one-seventh the size.

---

## Conclusion

Haskell was the right choice for SimpleX given its specific history - a solo founder who learned Haskell, a codebase too large to rewrite, and a colleague who made mobile cross-compilation possible. For a greenfield encrypted relay server in 2026, Go is the pragmatically stronger choice: easier to deploy, easier to audit, easier to recruit for, and backed by a battle-tested security ecosystem.

The WireGuard precedent is instructive: the world's most trusted VPN protocol has a Go implementation (wireguard-go) used in production by Tailscale at 10 Gbps throughput. If Go is secure enough for WireGuard, it is secure enough for GoRelay.

---

*GoRelay - IT and More Systems, Recklinghausen*
