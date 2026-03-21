---
title: "Systemd Service"
sidebar_position: 4
---

# Systemd Service

*Running GoRelay as a systemd service with automatic restart, security hardening, and log management.*

**Status:** In development
**Date:** 2026-03-09 (Session 001)

---

## Service Unit File

Create `/etc/systemd/system/gorelay.service`:

```ini
[Unit]
Description=GoRelay Encrypted Relay Server
Documentation=https://wiki.gorelay.dev
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=gorelay
Group=gorelay
ExecStart=/usr/local/bin/gorelay start --config /etc/gorelay/gorelay.yaml
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=5
TimeoutStopSec=30

# Logging - stdout only, no syslog metadata leakage
StandardOutput=journal
StandardError=journal
SyslogIdentifier=gorelay

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
MemoryDenyWriteExecute=true
LockPersonality=true
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources

# File access
ReadWritePaths=/var/lib/gorelay
ReadOnlyPaths=/etc/gorelay

# Resource limits
LimitNOFILE=65536
LimitNPROC=4096

[Install]
WantedBy=multi-user.target
```

---

## Setup

### Create Service User

```bash
sudo useradd --system --shell /usr/sbin/nologin --home-dir /var/lib/gorelay gorelay
sudo mkdir -p /var/lib/gorelay /etc/gorelay
sudo chown -R gorelay:gorelay /var/lib/gorelay /etc/gorelay
```

### Initialize

```bash
sudo -u gorelay gorelay init --config /etc/gorelay/gorelay.yaml --data /var/lib/gorelay
```

### Enable and Start

```bash
sudo systemctl daemon-reload
sudo systemctl enable gorelay
sudo systemctl start gorelay
sudo systemctl status gorelay
```

---

## Management Commands

```bash
# Check status
sudo systemctl status gorelay

# View logs
sudo journalctl -u gorelay -f

# View recent logs
sudo journalctl -u gorelay --since "1 hour ago"

# Reload configuration (no restart)
sudo systemctl reload gorelay

# Restart
sudo systemctl restart gorelay

# Stop
sudo systemctl stop gorelay
```

---

## Security Hardening Explained

The unit file includes extensive systemd security directives:

| Directive | Purpose |
|---|---|
| NoNewPrivileges | Cannot gain privileges via setuid/setgid |
| ProtectSystem=strict | Entire filesystem is read-only except explicitly allowed paths |
| ProtectHome | /home, /root, /run/user are inaccessible |
| PrivateTmp | Private /tmp directory, invisible to other processes |
| PrivateDevices | No access to /dev except /dev/null, /dev/zero, /dev/urandom |
| MemoryDenyWriteExecute | Cannot create executable memory (prevents code injection) |
| RestrictAddressFamilies | Only IPv4 and IPv6 networking (no Unix, Netlink, etc.) |
| SystemCallFilter | Whitelist of allowed system calls |
| ReadWritePaths | Only /var/lib/gorelay is writable |
| ReadOnlyPaths | /etc/gorelay is readable but not writable |

These directives create a sandbox that limits damage even if the GoRelay binary is compromised.

### Verify Security

```bash
sudo systemd-analyze security gorelay
# Target: score below 2.0 (well-secured)
```

---

## Log Rotation

Journald handles log rotation automatically. To configure retention:

```bash
# /etc/systemd/journald.conf
[Journal]
SystemMaxUse=100M
MaxRetentionSec=7d
```

GoRelay logs contain NO IP addresses, NO queue identifiers, and NO message metadata. Typical log entries:

```json
{"time":"2026-03-09T14:30:00Z","level":"INFO","msg":"client connected","protocol":"grp","connections":42}
{"time":"2026-03-09T14:30:05Z","level":"INFO","msg":"client disconnected","protocol":"smp","duration":"5m30s","commands":127}
{"time":"2026-03-09T14:35:00Z","level":"INFO","msg":"store gc completed","freed_mb":12,"duration":"340ms"}
```

---

## Automatic Updates

For automatic binary updates (optional):

```bash
# Create update script at /usr/local/bin/gorelay-update.sh
#!/bin/bash
LATEST=$(curl -s https://api.github.com/repos/saschadaemgen/GoRelay/releases/latest | grep tag_name | cut -d'"' -f4)
CURRENT=$(gorelay version | awk '{print $2}')

if [ "$LATEST" != "$CURRENT" ]; then
    curl -LO "https://github.com/saschadaemgen/GoRelay/releases/download/${LATEST}/gorelay-linux-amd64"
    chmod +x gorelay-linux-amd64
    sudo mv gorelay-linux-amd64 /usr/local/bin/gorelay
    sudo systemctl restart gorelay
fi
```

```bash
# Add to crontab (check daily at 3 AM)
0 3 * * * /usr/local/bin/gorelay-update.sh
```

---

*GoRelay - IT and More Systems, Recklinghausen*
