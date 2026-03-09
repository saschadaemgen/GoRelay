---
title: "Rust vs Go for Relay Servers"
sidebar_position: 11
---

# Rust vs Go for Encrypted Relay Servers

*Why Rust is overkill for a messaging relay, and why Go's tradeoffs are the right ones.*

**Research date:** 2026-03-09 (Session 001)

---

## The Core Question

Rust provides memory safety without a garbage collector through its ownership and borrowing system. For systems programming (kernels, browsers, databases), this is transformative. For a messaging relay server that handles text messages in 16 KB blocks on a VPS, the question is whether Rust's complexity budget pays for itself.

The answer is no.

---

## Performance Comparison

| Property | Go | Rust | Relevance for Relay |
|---|---|---|---|
| GC pauses | <1ms | None | Irrelevant (messaging tolerates seconds) |
| Raw throughput | ~95% of Rust | 100% baseline | Negligible for 16 KB text blocks |
| Memory usage | Higher (GC overhead) | Lower (no GC) | VPS has gigabytes, we use megabytes |
| Startup time | ~0.4ms | ~0.2ms | Server starts once |
| Tail latency (p99) | Low single-digit ms | Sub-ms | Both invisible to end users |

The 5% throughput difference between Go and Rust disappears into noise for a relay server. We are not processing video frames or running ML inference. We are receiving 16 KB encrypted blobs and forwarding them. A Raspberry Pi could handle this workload.

---

## Development Speed

| Factor | Go | Rust |
|---|---|---|
| Clean build (medium project) | 30 - 90 seconds | 5 - 15 minutes |
| Incremental build | <5 seconds | 10 - 60 seconds |
| Learning curve | One weekend | Months (borrow checker) |
| async networking | `go func()` - done | tokio + Pin + Send + Sync |
| Error handling | `if err != nil` (verbose but simple) | `Result<T, E>` + `?` (elegant but complex) |
| AI code generation quality | Very good | Good, but more lifetime errors |

The async story in Rust is particularly painful for server development. Choosing between tokio, async-std, and smol is just the beginning. Pinning futures, satisfying Send+Sync bounds on async trait methods, and debugging opaque type errors in async code remain significant friction points. In Go, you write `go handleConnection(conn)` and move on with your life.

---

## Cross-Compilation

Go: `GOOS=linux GOARCH=arm64 go build` - one command, static binary, done.

Rust: Install the target triple, configure a cross-linker, handle OpenSSL linkage (or use rustls), potentially use `cross` docker tool for foreign architectures. Better than Haskell, worse than Go.

---

## Ecosystem for Security Infrastructure

Go powers the security infrastructure of the internet: WireGuard (wireguard-go), Tailscale, HashiCorp Vault, age encryption, Sigstore, Docker, Kubernetes. These are not toy projects - they handle real security at scale.

Rust has strong security projects too: rustls, ring, the Linux kernel modules. But the Go ecosystem for server-side security tooling is larger and more mature.

---

## When Rust IS the Right Choice

Rust would be the better choice if GoRelay needed to:
- Handle millions of concurrent connections on a single machine
- Achieve microsecond-level tail latencies
- Run in memory-constrained environments (embedded, WASM)
- Provide deterministic latency with zero GC pauses

None of these apply to a messaging relay server handling hundreds to thousands of connections on a standard VPS, delivering text messages where seconds of latency are acceptable.

---

## Conclusion

Rust is a better language than Go in many dimensions. It is more expressive, more memory-efficient, and provably safe at compile time. But for a messaging relay server, these advantages solve problems we do not have, while imposing a development speed cost we cannot afford.

The SimpleX founder himself wants to rewrite in Rust - but he also acknowledges he cannot afford to. We are starting fresh with no legacy code. We choose the tool that gets us to a working, tested, deployable server fastest: Go.

---

*GoRelay - IT and More Systems, Recklinghausen*
