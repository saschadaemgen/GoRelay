package smp

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"log/slog"

	"golang.org/x/crypto/poly1305"
	"golang.org/x/crypto/salsa20"
	"golang.org/x/crypto/salsa20/salsa"
)

// MaxMessageLength is the maximum message body length for MSG delivery.
// This matches the SMP specification for padded message bodies.
const MaxMessageLength = 16064

// paddedSize is the total size of the padded plaintext: 2 (length prefix) + MaxMessageLength = 16066.
const paddedSize = 2 + MaxMessageLength

// EncryptMsgBody encrypts a message body for delivery to the recipient.
//
// Wire format per SMP spec:
//
//	encryptedRcvMsgBody = simplexCryptoBox(padded(rcvMsgBody))
//	sentBody wire format: flagsASCII + SP(0x20) + smpEncMessage
//	rcvMsgBody = timestamp(8 bytes BE) + flagsByte(1 byte) + smpEncMessage
//	flagsByte: 0x01 if flagsASCII=="T" (notification), 0x00 otherwise
//	padded(data, maxLen) = originalLength(2 bytes BE) + data + zero-fill to maxLen
//	maxLen = MaxMessageLength + 2 = 16066
//
// The nonce is the 24-byte msgId. The key is the raw X25519 DH shared secret.
// Uses SimpleX custom XSalsa20 nonce splitting (cryptonite library convention).
//
// Returns: authTag(16) + ciphertext(16066) = 16082 bytes total.
func EncryptMsgBody(dhSharedKey [32]byte, msgId [24]byte, timestamp uint64, sentBody []byte) []byte {
	// sentBody wire format: flagsASCII + SP(0x20) + smpEncMessage
	// flagsASCII is "T" (notification) or empty ""
	// rcvMsgBody format: timestamp(8) + flagsByte(1) + uint16BE(len(smpEncMessage)) + smpEncMessage
	var flagsByte byte = 'F'
	var smpEncMessage []byte
	if spIdx := bytes.IndexByte(sentBody, 0x20); spIdx >= 0 {
		flagsStr := sentBody[:spIdx]
		smpEncMessage = sentBody[spIdx+1:]
		if bytes.Equal(flagsStr, []byte("T")) {
			flagsByte = 'T' // notification flag (ASCII 0x54)
		}
	} else {
		// No SP found - treat entire sentBody as smpEncMessage
		smpEncMessage = sentBody
	}

	// Build rcvMsgBody: timestamp(12) + flagsByte(1) + uint16BE(len(smpEncMessage)) + smpEncMessage
	// timestamp = int64BE(seconds)(8) + word32BE(nanoseconds)(4) = 12 bytes (Haskell SystemTime)
	rcvMsgBody := make([]byte, 0, 12+1+2+len(smpEncMessage))
	ts := make([]byte, 12)
	binary.BigEndian.PutUint64(ts[0:8], timestamp)
	binary.BigEndian.PutUint32(ts[8:12], 0) // nanoseconds = 0
	rcvMsgBody = append(rcvMsgBody, ts...)
	rcvMsgBody = append(rcvMsgBody, flagsByte)
	var encMsgLen [2]byte
	binary.BigEndian.PutUint16(encMsgLen[:], uint16(len(smpEncMessage)))
	rcvMsgBody = append(rcvMsgBody, encMsgLen[:]...)
	rcvMsgBody = append(rcvMsgBody, smpEncMessage...)

	slog.Info("DIAG: EncryptMsgBody rcvMsgBody",
		"rcvMsgBody_len", len(rcvMsgBody),
	)

	// Build padded: uint16BE(len(rcvMsgBody)) + rcvMsgBody + zero-fill to paddedSize
	padded := make([]byte, paddedSize)
	binary.BigEndian.PutUint16(padded[0:2], uint16(len(rcvMsgBody)))
	copy(padded[2:], rcvMsgBody)
	// Remaining bytes are already zero from make()

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

// simplexCryptoBox encrypts plaintext using the SimpleX custom XSalsa20 variant.
//
// SimpleX (via Haskell cryptonite) uses three key derivation steps:
//
//	Step 1: HSalsa20(key, zeros[16])      -> subkey1   (cryptonite initialize)
//	Step 2: HSalsa20(subkey1, nonce[8:24]) -> subkey2   (cryptonite derive)
//	Step 3: Salsa20(subkey2, nonce[0:8])   -> keystream
//
// This differs from standard NaCl which skips step 1.
//
// Output: poly1305Tag(16) + ciphertext(len(plaintext))
func simplexCryptoBox(key [32]byte, nonce [24]byte, plaintext []byte) []byte {
	// Step 1: HSalsa20(key, zeros[16]) -> subkey1
	var subkey1 [32]byte
	var zeros16 [16]byte
	salsa.HSalsa20(&subkey1, &zeros16, &key, &salsa.Sigma)

	// Step 2: HSalsa20(subkey1, nonce[8:24]) -> subkey2
	var subkey2 [32]byte
	var hsInput [16]byte
	copy(hsInput[:], nonce[8:24])
	salsa.HSalsa20(&subkey2, &hsInput, &subkey1, &salsa.Sigma)

	// Zero subkey1 immediately
	for i := range subkey1 {
		subkey1[i] = 0
	}

	// Step 3: Salsa20 XOR with subkey2 and nonce[0:8]
	// Prepend 32 zero bytes for Poly1305 key extraction
	buf := make([]byte, 32+len(plaintext))
	copy(buf[32:], plaintext)

	var salsaNonce [8]byte
	copy(salsaNonce[:], nonce[0:8])
	salsa20.XORKeyStream(buf, buf, salsaNonce[:], &subkey2)

	// First 32 bytes XORed with zeros = raw keystream = Poly1305 one-time key
	var polyKey [32]byte
	copy(polyKey[:], buf[:32])
	ciphertext := buf[32:]

	// Poly1305 MAC over ciphertext
	var tag [16]byte
	poly1305.Sum(&tag, ciphertext, &polyKey)

	// Zero sensitive material
	for i := range subkey2 {
		subkey2[i] = 0
	}
	for i := range polyKey {
		polyKey[i] = 0
	}

	// Output: tag(16) + ciphertext
	result := make([]byte, 16+len(ciphertext))
	copy(result[:16], tag[:])
	copy(result[16:], ciphertext)

	return result
}

// SimplexCryptoBoxOpen decrypts ciphertext produced by simplexCryptoBox.
// Returns the plaintext and true on success, or nil and false if authentication fails.
func SimplexCryptoBoxOpen(key [32]byte, nonce [24]byte, box []byte) ([]byte, bool) {
	if len(box) < 16 {
		return nil, false
	}

	// Split tag and ciphertext
	var tag [16]byte
	copy(tag[:], box[:16])
	ciphertext := box[16:]

	// Step 1: HSalsa20(key, zeros[16]) -> subkey1
	var subkey1 [32]byte
	var zeros16 [16]byte
	salsa.HSalsa20(&subkey1, &zeros16, &key, &salsa.Sigma)

	// Step 2: HSalsa20(subkey1, nonce[8:24]) -> subkey2
	var subkey2 [32]byte
	var hsInput [16]byte
	copy(hsInput[:], nonce[8:24])
	salsa.HSalsa20(&subkey2, &hsInput, &subkey1, &salsa.Sigma)

	// Zero subkey1 immediately
	for i := range subkey1 {
		subkey1[i] = 0
	}

	// Step 3: Generate Poly1305 key by encrypting 32 zero bytes
	var salsaNonce [8]byte
	copy(salsaNonce[:], nonce[0:8])

	polyKeyBuf := make([]byte, 32)
	salsa20.XORKeyStream(polyKeyBuf, polyKeyBuf, salsaNonce[:], &subkey2)
	var polyKey [32]byte
	copy(polyKey[:], polyKeyBuf)

	// Verify Poly1305 tag
	if !poly1305.Verify(&tag, ciphertext, &polyKey) {
		for i := range subkey2 {
			subkey2[i] = 0
		}
		for i := range polyKey {
			polyKey[i] = 0
		}
		return nil, false
	}

	// Decrypt: XOR ciphertext with keystream at counter offset 1 (after 32-byte poly key block)
	// We need to XOR with the keystream starting at byte 32, so prepend 32 dummy bytes
	buf := make([]byte, 32+len(ciphertext))
	copy(buf[32:], ciphertext)
	salsa20.XORKeyStream(buf, buf, salsaNonce[:], &subkey2)
	plaintext := make([]byte, len(ciphertext))
	copy(plaintext, buf[32:])

	// Zero sensitive material
	for i := range subkey2 {
		subkey2[i] = 0
	}
	for i := range polyKey {
		polyKey[i] = 0
	}

	return plaintext, true
}
