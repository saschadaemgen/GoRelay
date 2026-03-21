---
title: "Contributing"
sidebar_position: 1
---

# Contributing to GoRelay

*How to contribute to GoRelay - from bug reports to protocol extensions.*

**Status:** In development
**Date:** 2026-03-09 (Session 001)

---

## Welcome

GoRelay is an open-source project under AGPL-3.0. Contributions are welcome from anyone who shares the goal of building secure, privacy-preserving relay infrastructure.

---

## Ways to Contribute

### Bug Reports

Found a bug? Open a GitHub issue with:
- GoRelay version (`gorelay version`)
- Operating system and architecture
- Steps to reproduce
- Expected vs actual behavior
- Relevant log output (sanitized - no real queue IDs or connection data)

### Security Vulnerabilities

**Do NOT open a public issue for security vulnerabilities.** Instead, email security@simplego.dev with:
- Description of the vulnerability
- Steps to reproduce or proof of concept
- Suggested fix (if you have one)

We will acknowledge within 48 hours and aim to release a fix within 7 days for critical issues.

### Code Contributions

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Write code following the [Code Style](code-style) guide
4. Write tests following the [Testing](testing) guide
5. Commit using Conventional Commits: `feat(core): add encryption`
6. Open a pull request against `main`

### Documentation

Documentation improvements are always welcome. The docs live in `/docs/` and are rendered by Docusaurus. Fix typos, improve explanations, add examples - every improvement helps.

### Protocol Review

If you have cryptographic expertise, reviewing the GRP protocol specification is extremely valuable. We want independent eyes on every design decision.

---

## Development Setup

### Prerequisites

- Go 1.24 or later
- Git
- A text editor or IDE with Go support

### Clone and Build

```bash
git clone https://github.com/saschadaemgen/GoRelay.git
cd GoRelay
go build -o gorelay ./cmd/gorelay
```

### Run Tests

```bash
go test -race ./...
```

### Run Locally

```bash
./gorelay init --config ./dev-config.yaml --data ./dev-data
./gorelay start --config ./dev-config.yaml
```

---

## Branch Strategy

- `main` - stable, deployable code. Never commit directly.
- `feature/*` - feature branches. One feature per branch.
- Pull requests are squash-merged into `main`.

### Commit Messages

GoRelay uses Conventional Commits strictly:

```
type(scope): description

Types: feat, fix, docs, test, refactor, ci, chore
Scopes: core, smp, grp, store, relay, config, ci, wiki
```

Examples:
```
feat(grp): implement Noise IK handshake
fix(store): handle BadgerDB compaction race condition
docs(protocol): add test vectors for block framing
test(smp): add integration test for cross-protocol delivery
refactor(core): extract subscription hub into separate package
ci(docker): add arm64 build target
```

---

## Pull Request Requirements

Before a PR can be merged:

1. **All tests pass:** `go test -race ./...` must be green
2. **No linting errors:** `golangci-lint run` must pass
3. **Conventional Commit messages:** Every commit follows the format
4. **Documentation updated:** If behavior changes, docs must reflect it
5. **No version changes:** Never modify version numbers without explicit permission
6. **No em dashes:** Use regular hyphens or rewrite the sentence

---

## Architecture Decision Records

Significant design decisions are documented in the Session Log. If your contribution involves an architectural change, document the decision:

- What was decided
- What alternatives were considered
- Why this option was chosen
- What trade-offs were accepted

---

## Code of Conduct

Be respectful, be constructive, be honest. We value technical accuracy over politeness, but there is no reason you cannot have both. Personal attacks, harassment, and discrimination are not tolerated.

---

## License

By contributing to GoRelay, you agree that your contributions will be licensed under the AGPL-3.0 license. This means derivative works must also be open-source and share their source code.

---

*GoRelay - IT and More Systems, Recklinghausen*
