package server

import (
"crypto/ecdsa"
"crypto/elliptic"
"crypto/rand"
"crypto/tls"
"crypto/x509"
"math/big"
"time"
)

// generateDevCert creates a self-signed TLS certificate for development.
// DO NOT use in production - generate real certificates with gorelay init.
func generateDevCert() (tls.Certificate, error) {
key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
if err != nil {
return tls.Certificate{}, err
}

template := &x509.Certificate{
SerialNumber: big.NewInt(1),
NotBefore:    time.Now(),
NotAfter:     time.Now().Add(24 * time.Hour),
KeyUsage:     x509.KeyUsageDigitalSignature,
ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
}

certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
if err != nil {
return tls.Certificate{}, err
}

return tls.Certificate{
Certificate: [][]byte{certDER},
PrivateKey:  key,
}, nil
}
