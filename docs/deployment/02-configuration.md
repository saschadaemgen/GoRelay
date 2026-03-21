---
title: "Configuration"
sidebar_position: 2
---

# Configuration Reference

*Complete reference for all GoRelay configuration options.*

**Status:** In development
**Date:** 2026-03-09 (Session 001)

---

## Configuration File

GoRelay uses YAML configuration loaded by koanf. Default path: `/etc/gorelay/gorelay.yaml`

```yaml
# ============================================================
# GoRelay Configuration
# ============================================================

# --- Server Identity ---
server:
  hostname: "relay.example.com"       # public hostname
  data_dir: "/var/lib/gorelay"        # persistent data directory

# --- SMP Listener (SimpleX Compatibility) ---
smp:
  enabled: true
  address: ":5223"                    # listen address
  tls:
    cert: "/var/lib/gorelay/tls/cert.pem"
    key: "/var/lib/gorelay/tls/key.pem"
    ca_cert: "/var/lib/gorelay/tls/ca.pem"  # offline CA cert
    min_version: "1.3"                # TLS 1.3 only
    alpn: "smp/1"

# --- GRP Listener (Enhanced Protocol) ---
grp:
  enabled: true
  address: ":7443"                    # listen address
  noise:
    static_key: "/var/lib/gorelay/noise_static.key"
    pattern: "IK"                     # primary handshake pattern
    fallback_pattern: "XX"            # for first-contact
  mlkem:
    key_rotation_interval: "24h"      # ML-KEM keypair rotation

# --- Queue Store ---
store:
  path: "/var/lib/gorelay/data"       # BadgerDB directory
  default_ttl: "48h"                  # message time-to-live
  max_ttl: "168h"                     # 7-day hard maximum (cannot exceed)
  gc_interval: "5m"                   # garbage collection frequency
  gc_threshold: 0.5                   # dead entry ratio for GC trigger
  backup_interval: "6h"              # automatic backup interval
  backup_path: "/var/lib/gorelay/backups"
  backup_retention: 3                 # number of backups to keep

# --- Connection Limits ---
limits:
  max_connections: 10000              # total concurrent connections
  max_connections_per_ip: 20          # per IP address
  new_connections_per_minute: 20      # per IP rate limit
  commands_per_second: 50             # per connection
  commands_burst: 100                 # burst allowance
  queues_per_connection: 1000         # max queues managed per connection
  handshake_timeout: "30s"
  read_timeout: "5m"
  write_timeout: "10s"

# --- Cover Traffic ---
cover_traffic:
  enabled: true
  rate: 0.2                           # messages per second per client
  min_rate: 0.05                      # minimum (even if adaptive lowers it)
  max_rate: 2.0                       # maximum
  adaptive: true                      # adjust based on real traffic

# --- Relay Routing ---
relay:
  enabled: true                       # enable relay-to-relay forwarding
  peers: []                           # populated below
  pool_size: 4                        # connections per peer
  idle_timeout: "15m"                 # close idle peer connections
  rekey_interval: "1h"                # rekey peer sessions
  rekey_messages: 10000               # rekey after N messages

# relay.peers example:
# - address: "relay2.simplego.dev:7443"
#   public_key: "base64-encoded-noise-static-key"
# - address: "relay3.example.com:7443"
#   public_key: "base64-encoded-noise-static-key"

# --- Metrics ---
metrics:
  enabled: true
  address: "127.0.0.1:9090"          # Prometheus metrics endpoint
  path: "/metrics"                    # metrics HTTP path

# --- Logging ---
logging:
  level: "info"                       # debug, info, warn, error
  format: "json"                      # json or text
  output: "stdout"                    # stdout, stderr, or file path
  # SECURITY: GoRelay NEVER logs IP addresses, queue IDs,
  # or any metadata that could identify users.
```

---

## Environment Variable Overrides

Every configuration option can be overridden via environment variables using the prefix `GORELAY_` and underscores for nesting:

```bash
export GORELAY_SMP_ADDRESS=":5224"
export GORELAY_STORE_DEFAULT_TTL="24h"
export GORELAY_LIMITS_MAX_CONNECTIONS=5000
export GORELAY_COVER_TRAFFIC_RATE=0.5
export GORELAY_LOGGING_LEVEL="debug"
```

Environment variables take precedence over the configuration file.

---

## Configuration Validation

GoRelay validates the entire configuration at startup and refuses to start with invalid settings:

- `store.default_ttl` must not exceed `store.max_ttl`
- `store.max_ttl` cannot exceed 168 hours (7 days, hard-coded limit)
- `limits.max_connections` must be positive
- `cover_traffic.rate` must be between `min_rate` and `max_rate`
- TLS certificate and key files must exist and be readable
- Noise static key file must exist and be readable
- Relay peer public keys must be valid base64-encoded Curve25519 keys
- Data directory must be writable
- Metrics address must not conflict with SMP or GRP listener addresses

---

## Default Values

If no configuration file is provided, GoRelay uses sensible defaults:

| Option | Default | Notes |
|---|---|---|
| smp.address | :5223 | Standard SMP port |
| grp.address | :7443 | GoRelay GRP port |
| store.default_ttl | 48h | Two days |
| store.max_ttl | 168h | Seven days (hard cap) |
| limits.max_connections | 10000 | |
| limits.commands_per_second | 50 | Per connection |
| cover_traffic.rate | 0.2 | One dummy every 5 seconds |
| metrics.address | 127.0.0.1:9090 | Localhost only |
| logging.level | info | |

---

## Reloading Configuration

GoRelay supports configuration reload via SIGHUP:

```bash
kill -HUP $(pidof gorelay)
```

Reloadable options (no restart required): logging level, cover traffic rate, rate limit parameters, metrics settings.

Non-reloadable options (require restart): listen addresses, TLS certificates, Noise keys, store path, relay peers.

---

*GoRelay - IT and More Systems, Recklinghausen*
