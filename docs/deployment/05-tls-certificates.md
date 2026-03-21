---
title: "TLS Certificates"
sidebar_position: 5
---

# TLS Certificate Management

*How to set up TLS certificates for GoRelay's SMP listener, including the offline CA model required by the SimpleX protocol.*

**Status:** In development
**Date:** 2026-03-09 (Session 001)

---

## SMP Certificate Model

SMP uses a two-certificate chain that differs from standard web TLS:

```
Offline CA Certificate (self-signed, long-lived)
  |
  +-- fingerprint appears in server URI: smp://<fingerprint>@host
  |
  +-- signs -->  Online TLS Certificate (shorter-lived, rotatable)
                   |
                   +-- presented during TLS handshake
```

**Offline CA cert:** Generated once, stored securely offline. Its SHA-256 fingerprint is the server's identity in SMP URIs. Clients verify the server by checking that the online cert is signed by the CA whose fingerprint they have.

**Online TLS cert:** Used for the actual TLS handshake. Can be rotated (reissued and re-signed by the CA) without changing the server's identity.

This allows certificate rotation without requiring clients to update their server URIs.

---

## Generating Certificates

### Step 1: Create Offline CA

```bash
# Generate CA private key
openssl genpkey -algorithm Ed25519 -out ca.key

# Generate self-signed CA certificate (10 years)
openssl req -new -x509 -key ca.key -out ca.pem -days 3650 \
    -subj "/CN=GoRelay CA"

# Get the fingerprint (this goes in your SMP URI)
openssl x509 -in ca.pem -fingerprint -sha256 -noout
# SHA256 Fingerprint=AB:CD:12:34:...
```

**Store ca.key securely offline.** This key only needs to be available when issuing or rotating the TLS certificate. It should not be on the server during normal operation.

### Step 2: Create Online TLS Certificate

```bash
# Generate server private key
openssl genpkey -algorithm Ed25519 -out server.key

# Generate certificate signing request
openssl req -new -key server.key -out server.csr \
    -subj "/CN=relay.example.com"

# Sign with CA (1 year)
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key \
    -CAcreateserial -out server.pem -days 365 \
    -extfile <(printf "subjectAltName=DNS:relay.example.com")

# Verify the chain
openssl verify -CAfile ca.pem server.pem
# server.pem: OK
```

### Step 3: Install

```bash
sudo mkdir -p /var/lib/gorelay/tls
sudo cp ca.pem /var/lib/gorelay/tls/ca.pem
sudo cp server.pem /var/lib/gorelay/tls/cert.pem
sudo cp server.key /var/lib/gorelay/tls/key.pem
sudo chown -R gorelay:gorelay /var/lib/gorelay/tls
sudo chmod 600 /var/lib/gorelay/tls/key.pem
```

### Step 4: Configure

```yaml
smp:
  tls:
    cert: "/var/lib/gorelay/tls/cert.pem"
    key: "/var/lib/gorelay/tls/key.pem"
    ca_cert: "/var/lib/gorelay/tls/ca.pem"
```

---

## Certificate Rotation

When the online certificate approaches expiry, rotate it without changing the server identity:

```bash
# On the machine with the CA key:
openssl genpkey -algorithm Ed25519 -out server-new.key
openssl req -new -key server-new.key -out server-new.csr \
    -subj "/CN=relay.example.com"
openssl x509 -req -in server-new.csr -CA ca.pem -CAkey ca.key \
    -CAcreateserial -out server-new.pem -days 365 \
    -extfile <(printf "subjectAltName=DNS:relay.example.com")

# Copy to server and replace
sudo cp server-new.pem /var/lib/gorelay/tls/cert.pem
sudo cp server-new.key /var/lib/gorelay/tls/key.pem
sudo chown gorelay:gorelay /var/lib/gorelay/tls/cert.pem /var/lib/gorelay/tls/key.pem
sudo chmod 600 /var/lib/gorelay/tls/key.pem

# Restart to load new certificate
sudo systemctl restart gorelay
```

Clients do not need to update anything - the SMP URI contains the CA fingerprint, not the TLS certificate fingerprint. As long as the new cert is signed by the same CA, existing clients will accept it.

---

## Automatic Renewal with Let's Encrypt

For operators who prefer automated certificate management, Let's Encrypt can be used for the online TLS certificate. However, this changes the trust model:

**Standard SMP model:** Client trusts a specific CA fingerprint (self-signed, operator-controlled).

**Let's Encrypt model:** Client trusts the Let's Encrypt CA chain (third-party CA).

If using Let's Encrypt:

```bash
# Install certbot
sudo apt install certbot

# Obtain certificate
sudo certbot certonly --standalone -d relay.example.com \
    --preferred-challenges http

# Certificates are at:
# /etc/letsencrypt/live/relay.example.com/fullchain.pem
# /etc/letsencrypt/live/relay.example.com/privkey.pem
```

Configure GoRelay to use Let's Encrypt certs:

```yaml
smp:
  tls:
    cert: "/etc/letsencrypt/live/relay.example.com/fullchain.pem"
    key: "/etc/letsencrypt/live/relay.example.com/privkey.pem"
    ca_cert: ""  # not needed for Let's Encrypt
```

**Note:** When using Let's Encrypt, the SMP URI fingerprint must match the Let's Encrypt certificate. Clients will need updated URIs if you switch between self-signed CA and Let's Encrypt.

---

## GRP Does Not Use TLS

The GRP listener (port 7443) uses the Noise Protocol Framework, not TLS. GRP identity is based on a static Curve25519 public key, not a certificate.

GRP key management:
- The Noise static keypair is generated during `gorelay init`
- The keypair is stored at `/var/lib/gorelay/noise_static.key`
- The public key appears in the GRP URI: `grp://<public-key>@host:7443`
- There is no expiry, no rotation, no CA chain
- Changing the key changes the server's GRP identity (clients need updated URIs)

---

## Security Recommendations

1. **Use Ed25519 keys** for both CA and TLS certificates. Ed25519 is faster and more secure than RSA.
2. **Store the CA key offline** - on a USB drive in a safe, not on the server.
3. **Set short lifetimes** for online certificates (90-365 days). Rotate regularly.
4. **Verify the chain** after every rotation: `openssl verify -CAfile ca.pem server.pem`
5. **Restrict key file permissions** to 600 (owner read/write only).
6. **Back up the CA key** securely. Losing it means generating a new CA and updating all client URIs.

---

*GoRelay - IT and More Systems, Recklinghausen*
