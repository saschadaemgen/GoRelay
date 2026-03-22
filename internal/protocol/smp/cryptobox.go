package smp

import (
	"encoding/binary"

	"golang.org/x/crypto/nacl/secretbox"
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
//	encryptedRcvMsgBody = NaCl_secretbox(padded(rcvMsgBody))
//	rcvMsgBody = timestamp(8 bytes BE) + msgFlags(1 byte) + SP(0x20) + sentMsgBody
//	padded(data, maxLen) = originalLength(2 bytes BE) + data + zero-fill to maxLen
//	maxLen = MaxMessageLength + 2 = 16066
//
// The nonce is the 24-byte msgId. The key is the precomputed DH shared secret.
//
// Returns: authTag(16) + ciphertext(16066) = 16082 bytes total.
func EncryptMsgBody(dhSharedKey [32]byte, msgId [24]byte, timestamp uint64, flags byte, sentBody []byte) []byte {
	// Build rcvMsgBody: timestamp(8) + flags(1) + 0x20 + sentBody
	rcvMsgBody := make([]byte, 0, 8+1+1+len(sentBody))
	ts := make([]byte, 8)
	binary.BigEndian.PutUint64(ts, timestamp)
	rcvMsgBody = append(rcvMsgBody, ts...)
	rcvMsgBody = append(rcvMsgBody, flags)
	rcvMsgBody = append(rcvMsgBody, 0x20)
	rcvMsgBody = append(rcvMsgBody, sentBody...)

	// Build padded: uint16BE(len(rcvMsgBody)) + rcvMsgBody + zero-fill to paddedSize
	padded := make([]byte, paddedSize)
	binary.BigEndian.PutUint16(padded[0:2], uint16(len(rcvMsgBody)))
	copy(padded[2:], rcvMsgBody)
	// Remaining bytes are already zero from make()

	// Encrypt with NaCl secretbox: nonce = msgId, key = dhSharedKey
	nonce := msgId // [24]byte is directly usable as nonce
	out := secretbox.Seal(nil, padded, &nonce, &dhSharedKey)

	return out
}
