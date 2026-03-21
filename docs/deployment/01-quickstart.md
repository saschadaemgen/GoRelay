---
title: "Quick Start"
sidebar_position: 1
---

# Quick Start Guide

*Get a GoRelay server running in under 5 minutes.*

**Prerequisites:** A Linux server (VPS, bare metal, or Raspberry Pi) with a public IP address and ports 5223 and 7443 open.

---

## Step 1: Download

Download the latest GoRelay binary for your platform:

```bash
# Linux amd64 (most VPS providers)
curl -LO https://github.com/saschadaemgen/GoRelay/releases/latest/download/gorelay-linux-amd64
chmod +x gorelay-linux-amd64
sudo mv gorelay-linux-amd64 /usr/local/bin/gorelay

# Linux arm64 (Raspberry Pi 4/5, Oracle Cloud ARM)
curl -LO https://github.com/saschadaemgen/GoRelay/releases/latest/download/gorelay-linux-arm64
chmod +x gorelay-linux-arm64
sudo mv gorelay-linux-arm64 /usr/local/bin/gorelay
```

Verify the binary:

```bash
gorelay version
# GoRelay v0.1.0 (GRP/1) - built with go1.24
```

---

## Step 2: Initialize

Generate keys and default configuration:

```bash
sudo mkdir -p /etc/gorelay /var/lib/gorelay
sudo gorelay init --config /etc/gorelay/gorelay.yaml --data /var/lib/gorelay
```

This creates:
- `/etc/gorelay/gorelay.yaml` - configuration file
- `/var/lib/gorelay/noise_static.key` - Noise static keypair (GRP identity)
- `/var/lib/gorelay/tls/` - self-signed TLS certificate (SMP identity)
- `/var/lib/gorelay/data/` - BadgerDB data directory

The command outputs your server URIs:

```
SMP URI: smp://abc123def456@your-server.example.com:5223
GRP URI: grp://xyz789ghi012:mlkemkey@your-server.example.com:7443
```

Save these URIs - clients need them to connect.

---

## Step 3: Start

```bash
sudo gorelay start --config /etc/gorelay/gorelay.yaml
```

That is it. GoRelay is running. SMP clients can connect on port 5223, GRP clients on port 7443.

---

## Step 4: Verify

Test that both ports are reachable:

```bash
# From another machine:
openssl s_client -connect your-server.example.com:5223 -alpn smp/1
# Should show TLS 1.3 handshake with ALPN "smp/1"

# Check GRP port is open:
nc -zv your-server.example.com 7443
# Should show "Connection succeeded"
```

---

## Step 5: Connect a Client

### SimpleX Chat (SMP)

In the SimpleX Chat app: Settings > Network and Servers > Add Server. Enter your SMP URI:

```
smp://abc123def456@your-server.example.com:5223
```

### SimpleGo Device (GRP)

Configure the SimpleGo device with your GRP URI:

```
grp://xyz789ghi012:mlkemkey@your-server.example.com:7443
```

---

## Production Recommendations

The quick start gets you running. For production use:

1. **Use proper TLS certificates** - see [TLS Certificates](tls-certificates) for Let's Encrypt setup
2. **Run as a systemd service** - see [Systemd](systemd) for automatic start and restart
3. **Configure firewall** - allow only ports 5223, 7443, and your SSH port
4. **Set up monitoring** - see [Configuration](configuration) for Prometheus metrics
5. **Use Docker** for isolated deployment - see [Docker](docker)
6. **Deploy a second relay** for two-hop routing
7. **Enable full-disk encryption** on the server

---

## Firewall Configuration

### UFW (Ubuntu/Debian)

```bash
sudo ufw allow 5223/tcp comment "GoRelay SMP"
sudo ufw allow 7443/tcp comment "GoRelay GRP"
sudo ufw enable
```

### iptables

```bash
sudo iptables -A INPUT -p tcp --dport 5223 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 7443 -j ACCEPT
```

---

## Troubleshooting

**Port already in use:** Another service is using port 5223 or 7443. Check with `ss -tlnp | grep -E '5223|7443'`.

**Permission denied:** GoRelay needs root or CAP_NET_BIND_SERVICE for ports below 1024. Ports 5223 and 7443 do not require root.

**Connection refused from outside:** Check your cloud provider's firewall/security group. Many providers block all ports by default.

**Binary not found:** Ensure `/usr/local/bin` is in your PATH, or use the full path `/usr/local/bin/gorelay`.

---

*GoRelay - IT and More Systems, Recklinghausen*
