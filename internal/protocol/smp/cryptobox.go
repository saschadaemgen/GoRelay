package smp

import (
	"encoding/binary"
	"encoding/hex"
	"log/slog"

	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/salsa20/salsa"
)

// MaxMessageLength is the maximum rcvMsgBody length for MSG delivery.
// Haskell: maxRcvMessageLength = 16104
const MaxMessageLength = 16104

// paddedSize is the total size of the padded plaintext: 2 (length prefix) + MaxMessageLength = 16106.
const paddedSize = 2 + MaxMessageLength

// EncryptMsgBody encrypts a message body for delivery to the recipient.
//
// Wire format per SMP spec:
//
//	encryptedRcvMsgBody = simplexCryptoBox(padded(rcvMsgBody))
//	rcvMsgBody = timestamp(8 bytes Int64 BE) + sentBody(raw, unchanged)
//	sentBody already contains: flagsASCII + SP(0x20) + smpEncMessage
//	padded(data, maxLen) = originalLength(2 bytes BE) + data + '#'-fill to maxLen
//	maxLen = MaxMessageLength + 2 = 16106
//
// The nonce is the 24-byte msgId. The key is the raw X25519 DH shared secret.
// Uses SimpleX custom XSalsa20 nonce splitting (cryptonite library convention).
//
// Returns: authTag(16) + ciphertext(16106) = 16122 bytes total.
func EncryptMsgBody(dhSharedKey [32]byte, msgId [24]byte, timestamp uint64, sentBody []byte) []byte {
	// Build rcvMsgBody: timestamp(8) + sentBody(raw)
	// sentBody is passed through unchanged - it already contains flags + SP + smpEncMessage
	rcvMsgBody := make([]byte, 0, 8+len(sentBody))
	ts := make([]byte, 8)
	binary.BigEndian.PutUint64(ts, timestamp)
	rcvMsgBody = append(rcvMsgBody, ts...)
	rcvMsgBody = append(rcvMsgBody, sentBody...)

	slog.Info("DIAG: EncryptMsgBody rcvMsgBody",
		"rcvMsgBody_len", len(rcvMsgBody),
	)

	// Build padded: uint16BE(len(rcvMsgBody)) + rcvMsgBody + '#'-fill to paddedSize
	padded := make([]byte, paddedSize)
	binary.BigEndian.PutUint16(padded[0:2], uint16(len(rcvMsgBody)))
	copy(padded[2:], rcvMsgBody)
	// Fill remaining bytes with '#' (0x23) per Haskell: B.replicate padLen '#'
	for i := 2 + len(rcvMsgBody); i < paddedSize; i++ {
		padded[i] = '#'
	}

	n := len(padded)
	if n > 32 {
		n = 32
	}
	slog.Info("DIAG: EncryptMsgBody padded plaintext",
		"padded_first32_hex", hex.EncodeToString(padded[:n]),
		"padded_len", len(padded),
	)

	// Encrypt with SimpleX custom XSalsa20 variant
	out := simplexCryptoBox(dhSharedKey, msgId, padded)

	return out
}

// simplexCryptoBox encrypts plaintext using NaCl crypto_box_afternm.
//
// This is equivalent to Haskell's cbEncrypt:
//
//	Step 1: HSalsa20(rawDHKey, zeros[16]) -> beforenmKey  (crypto_box_beforenm)
//	Step 2: secretbox.Seal(beforenmKey, nonce, plaintext)  (crypto_box_afternm)
//
// Output: poly1305Tag(16) + ciphertext(len(plaintext))
func simplexCryptoBox(key [32]byte, nonce [24]byte, plaintext []byte) []byte {
	// Step 1: crypto_box_beforenm = HSalsa20(rawDHKey, zeros[16])
	var beforenmKey [32]byte
	var zeros16 [16]byte
	salsa.HSalsa20(&beforenmKey, &zeros16, &key, &salsa.Sigma)

	// Step 2: crypto_box_afternm = standard NaCl secretbox
	out := secretbox.Seal(nil, plaintext, &nonce, &beforenmKey)

	// Zero sensitive material
	for i := range beforenmKey {
		beforenmKey[i] = 0
	}

	return out
}

// SimplexCryptoBoxOpen decrypts ciphertext produced by simplexCryptoBox.
// Returns the plaintext and true on success, or nil and false if authentication fails.
func SimplexCryptoBoxOpen(key [32]byte, nonce [24]byte, box []byte) ([]byte, bool) {
	if len(box) < secretbox.Overhead {
		return nil, false
	}

	// Step 1: crypto_box_beforenm = HSalsa20(rawDHKey, zeros[16])
	var beforenmKey [32]byte
	var zeros16 [16]byte
	salsa.HSalsa20(&beforenmKey, &zeros16, &key, &salsa.Sigma)

	// Step 2: crypto_box_open_afternm = standard NaCl secretbox.Open
	plaintext, ok := secretbox.Open(nil, box, &nonce, &beforenmKey)

	// Zero sensitive material
	for i := range beforenmKey {
		beforenmKey[i] = 0
	}

	if !ok {
		return nil, false
	}

	return plaintext, true
}
