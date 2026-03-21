---
title: "Docker"
sidebar_position: 3
---

# Docker Deployment

*Running GoRelay in Docker with minimal image size, persistent storage, and secure defaults.*

**Status:** In development
**Date:** 2026-03-09 (Session 001)

---

## Docker Image

GoRelay's Docker image uses a multi-stage build producing a minimal distroless image:

```dockerfile
# Build stage
FROM golang:1.24-alpine AS builder
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-w -s -X main.version=$(git describe --tags)" \
    -o gorelay ./cmd/gorelay

# Runtime stage
FROM gcr.io/distroless/static:nonroot
COPY --from=builder /build/gorelay /gorelay
EXPOSE 5223 7443 9090
ENTRYPOINT ["/gorelay"]
CMD ["start", "--config", "/etc/gorelay/gorelay.yaml"]
```

**Image size:** 5-15 MB (binary + distroless base)
**Attack surface:** No shell, no package manager, no libc, no users except nonroot
**User:** Runs as non-root by default (UID 65534)

---

## Docker Compose

```yaml
version: '3.8'

services:
  gorelay:
    image: ghcr.io/saschadaemgen/gorelay:latest
    container_name: gorelay
    restart: unless-stopped
    ports:
      - "5223:5223"   # SMP
      - "7443:7443"   # GRP
    volumes:
      - gorelay-config:/etc/gorelay
      - gorelay-data:/var/lib/gorelay
    environment:
      - GORELAY_LOGGING_LEVEL=info
    read_only: true
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    tmpfs:
      - /tmp:noexec,nosuid,size=64m

volumes:
  gorelay-config:
  gorelay-data:
```

### Security Hardening

- `read_only: true` - filesystem is read-only except mounted volumes
- `no-new-privileges` - prevents privilege escalation
- `cap_drop: ALL` - drops all Linux capabilities
- `tmpfs` for /tmp - ephemeral, not written to disk
- No shell in distroless image - cannot exec into container

---

## First Run

```bash
# Initialize configuration and keys
docker compose run --rm gorelay init --config /etc/gorelay/gorelay.yaml --data /var/lib/gorelay

# Start the server
docker compose up -d

# Check logs
docker compose logs -f gorelay

# Verify
docker compose exec gorelay /gorelay version
```

---

## Persistent Storage

**Configuration volume (`gorelay-config`):** Contains `gorelay.yaml`, TLS certificates, and Noise keys. Back this up carefully - losing the Noise static key changes the server's GRP identity.

**Data volume (`gorelay-data`):** Contains BadgerDB data and automatic backups. This can be rebuilt (empty queues) but should be backed up for continuity.

### Backup

```bash
# Stop the server briefly for consistent backup
docker compose stop gorelay
tar czf gorelay-backup-$(date +%Y%m%d).tar.gz \
    /var/lib/docker/volumes/gorelay-config \
    /var/lib/docker/volumes/gorelay-data
docker compose start gorelay
```

Or use BadgerDB's online backup (no downtime required) via the admin API if enabled.

---

## Multi-Architecture

GoRelay Docker images are published for both amd64 and arm64:

```bash
# Automatically pulls the correct architecture
docker pull ghcr.io/saschadaemgen/gorelay:latest

# Or specify explicitly
docker pull ghcr.io/saschadaemgen/gorelay:latest --platform linux/arm64
```

This means the same docker-compose.yml works on x86 VPS servers, ARM cloud instances (Oracle, AWS Graviton), and Raspberry Pi 4/5.

---

## Resource Limits

Recommended Docker resource limits:

```yaml
services:
  gorelay:
    deploy:
      resources:
        limits:
          cpus: '2.0'
          memory: 512M
        reservations:
          cpus: '0.5'
          memory: 128M
```

For 100 concurrent users, GoRelay uses approximately 50-100 MB of memory and minimal CPU. The limits above provide generous headroom.

---

## Monitoring with Prometheus

The metrics port (9090) should NOT be exposed publicly. If running Prometheus in the same Docker network:

```yaml
services:
  gorelay:
    # ... (as above, but WITHOUT exposing 9090)
    networks:
      - internal

  prometheus:
    image: prom/prometheus
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
    networks:
      - internal

networks:
  internal:
    driver: bridge
```

Prometheus config:

```yaml
scrape_configs:
  - job_name: 'gorelay'
    static_configs:
      - targets: ['gorelay:9090']
    scrape_interval: 15s
```

---

*GoRelay - IT and More Systems, Recklinghausen*
