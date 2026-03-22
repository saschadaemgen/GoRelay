---
title: "References"
sidebar_position: 6
---

# References

All sources consulted during GoRelay research and development, organized by topic.

---

## SMP Protocol and SimpleX

- SimpleX Messaging Protocol specification: https://github.com/simplex-chat/simplexmq/blob/stable/protocol/simplex-messaging.md
- SimpleX Protocol overview: https://github.com/simplex-chat/simplexmq/blob/stable/protocol/overview-tjr.md
- SimpleX Agent protocol: https://github.com/simplex-chat/simplexmq/blob/stable/protocol/agent-protocol.md
- simplexmq Haskell server source: https://github.com/simplex-chat/simplexmq
- Server.hs (main server logic): https://hackage-content.haskell.org/package/simplexmq-0.5.2/src/src/Simplex/Messaging/Server.hs
- SimpleX Chat Protocol: https://simplex.chat/docs/protocol/simplex-chat.html
- SimpleX Private Message Routing: https://simplex.chat/blog/20240604-simplex-chat-v5.8-private-message-routing-chat-themes.html
- Self-hosting SMP server: https://simplex.chat/docs/server.html
- SimpleX Privacy Policy: https://simplex.chat/privacy/

## Noise Protocol Framework

- Official specification: https://noiseprotocol.org/noise.html
- Noise Protocol PDF: https://noiseprotocol.org/noise.pdf
- Duo Security introduction: https://duo.com/labs/tech-notes/noise-protocol-framework-intro
- Wikipedia overview: https://en.wikipedia.org/wiki/Noise_Protocol_Framework
- Formal analysis (Ruhr University Bochum): https://casa.rub.de/fileadmin/img/Publikationen_PDFs/2020_Flexible_Authenticated_and_Confidential_Channel_Establishment__fACCE__Analyzing_the_Noise_Protocol_Framework_Publication_ClusterofExcellence_CASA_Bochum.pdf
- Netmaker glossary entry: https://www.netmaker.io/glossary/noise-protocol-framework
- flynn/noise Go library: https://github.com/flynn/noise
- katzenpost/noise (PQ extension): https://katzenpost.network/blog/2024/04/12/hpqc-hybrid-post-quantum-cryptography-library/

## WireGuard and Noise in Practice

- WireGuard exploration (Purdue): https://docs.lib.purdue.edu/cgi/viewcontent.cgi?article=1000&context=ceriastr

## Post-Quantum Cryptography

- NIST PQC standardization: https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization
- NIST finalizes first 3 PQC standards: https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards
- FIPS 203 (ML-KEM) overview: https://www.encryptionconsulting.com/overview-of-fips-203/
- Go crypto/mlkem package: https://pkg.go.dev/crypto/mlkem
- Go FIPS 140-3 module: https://go.dev/blog/fips140
- Go crypto security audit (Trail of Bits): https://go.dev/blog/tob-crypto-audit
- ML-KEM benchmark (Go vs CIRCL): https://medium.com/@moeghifar/post-quantum-key-encapsulation-ml-kem-performance-benchmark-between-go-library-and-cloudflare-006df9f759e1
- Cloudflare CIRCL library: https://github.com/cloudflare/circl
- FiloSottile mlkem768: https://github.com/FiloSottile/mlkem768
- Cloudflare PQ status 2025: https://blog.cloudflare.com/pq-2025/
- PQC status quo and action: https://www.intelligentcio.com/me/2025/12/15/post-quantum-cryptography-the-status-quo-and-need-for-action/
- 2026 encrypted communications trends: https://www.advasecurity.com/en/newsroom/blog/20260114-top-three-trends-shaping-the-security-of-encrypted-communications-in-2026

## Signal Protocol and Server

- Signal Protocol documentation: https://signal.org/docs/
- Signal PQXDH: https://signal.org/blog/pqxdh/
- Signal SPQR (Post-Quantum Ratchets): https://signal.org/blog/spqr/
- Signal Server source: https://github.com/signalapp/Signal-Server
- Signal server public code updates: https://www.xda-developers.com/signal-updates-public-server-code/
- Signal GDPR compliance: https://support.signal.org/hc/en-us/articles/360007059412-Signal-and-the-General-Data-Protection-Regulation-GDPR
- Signal Privacy Policy: https://signal.org/legal/
- Can you self-host Signal?: https://softwaremill.com/can-you-self-host-the-signal-server/

## Matrix and Dendrite

- Matrix Dendrite (Go homeserver): https://github.com/matrix-org/dendrite
- Dendrite component design: https://github.com/matrix-org/dendrite/wiki/Component-Design
- Dendrite DeepWiki analysis: https://deepwiki.com/matrix-org/dendrite
- Matrix protocol mapping study (Springer): https://link.springer.com/article/10.1186/s13677-025-00829-7
- Matrix overview (LWN): https://lwn.net/Articles/835880/
- Matrix message retention policies: https://github.com/matrix-org/synapse/blob/develop/docs/message_retention_policies.md

## Go Server Architecture

- Go networking internals: https://goperf.dev/02-networking/networking-internals/
- Go epoll handling under load: https://volito.digital/how-gos-standard-net-package-handles-thousands-of-connections-under-high-load-using-non-blocking-i-o-via-epoll-on-linux-or-kqueue-on-bsd-macos/
- 1M Go TCP server benchmarks: https://github.com/smallnest/1m-go-tcp-server
- Go crypto/tls package: https://pkg.go.dev/crypto/tls
- Go sync package: https://pkg.go.dev/sync
- Go io package (ReadFull): https://pkg.go.dev/io
- NATS server client.go: https://github.com/nats-io/nats-server/blob/main/server/client.go
- hashicorp/yamux multiplexing: https://github.com/hashicorp/yamux
- fatih/pool connection pooling: https://github.com/fatih/pool
- cmux protocol multiplexing: https://pkg.go.dev/github.com/adodon2go/cmux
- Go Docker multi-stage builds: https://oneuptime.com/blog/post/2026-01-07-go-docker-multi-stage/view

## Persistence and Storage

- BadgerDB: https://pkg.go.dev/github.com/dgraph-io/badger
- BadgerDB quickstart: https://docs.hypermode.com/badger/quickstart
- Pebble database: https://dbdb.io/db/pebble
- Embedded database comparison: https://gist.github.com/mjpitz/875a1a951812068b112d4a8779841839

## Configuration and Logging

- koanf configuration library: https://github.com/knadh/koanf
- Go slog benchmarks: https://dwarvesf.hashnode.dev/go-1-21-release-slog-with-benchmarks-zerolog-and-zap
- Prometheus Go instrumentation: https://prometheus.io/docs/guides/go-application/
- golang.org/x/time/rate: https://pkg.go.dev/golang.org/x/time/rate
- Rate limiting HTTP requests in Go: https://www.alexedwards.net/blog/how-to-rate-limit-http-requests
- autocert (Let's Encrypt): https://pkg.go.dev/golang.org/x/crypto/acme/autocert

## Cover Traffic and Traffic Analysis

- Loopix: strong anonymity analysis (IACR): https://eprint.iacr.org/2017/954.pdf
- Anonymity trilemma (PoPETs 2020): https://petsymposium.org/popets/2020/popets-2020-0056.pdf
- Sender cover traffic analysis: https://csc.csudh.edu/btang/papers/sender_cover_sda.pdf
- Receiver-bound cover analysis (ACM): https://dl.acm.org/doi/abs/10.1016/j.cose.2011.08.011
- Optimal Tor path length (PETS 2010): https://petsymposium.org/2010/papers/hotpets10-Bauer.pdf
- ShorTor multi-hop routing (arXiv): https://arxiv.org/pdf/2204.04489

## Legal and Compliance

- GDPR Article 5 (principles): https://gdpr-info.eu/art-5-gdpr/
- Data minimization and storage limitation: https://www.metomic.io/resource-centre/data-minimization-and-storage-limitation
- Germany data retention abolishment: https://tuta.com/blog/data-retention-germany
- BfDI on data retention: https://www.bfdi.bund.de/EN/Fachthemen/Inhalte/Telefon-Internet/Positionen/Vorratsdatenspeicherung.html
- EU ePrivacy and encrypted messaging: https://edri.org/our-work/its-official-your-private-communications-can-and-will-be-spied-on/

## Market and Industry

- Encrypted messaging apps market report: https://www.datainsightsmarket.com/reports/encrypted-messaging-apps-525357
- Future of secure messaging: https://www.cryptobreaking.com/the-future-of-secure-messaging/
- Forward secrecy and zero knowledge guide: https://gofoss.net/encrypted-messages/
- Cryptographic erasure: https://jetico.com/blog/cryptographic-erasure-crypto-erase-is-it-a-secure-option-for-data-sanitization/
- Cryptography test vectors: https://cryptography.io/en/latest/development/test-vectors/

---

*GoRelay - IT and More Systems, Recklinghausen*
