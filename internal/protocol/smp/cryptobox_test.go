package smp

import (
	"crypto/rand"
	"encoding/binary"
	"testing"
)

func TestEncryptMsgBodyOutputLength(t *testing.T) {
	var key [32]byte
	var msgId [24]byte
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(msgId[:]); err != nil {
		t.Fatal(err)
	}

	// sentBody: no flags + SP + message content
	sentBody := append([]byte(" "), []byte("hello world")...)
	out := EncryptMsgBody(key, msgId, 1234567890, sentBody)

	// 16 (auth tag) + 16066 (padded plaintext) = 16082
	expected := 16082
	if len(out) != expected {
		t.Fatalf("output length: got %d, want %d", len(out), expected)
	}
}

func TestEncryptMsgBodyDecryptRoundtrip(t *testing.T) {
	var key [32]byte
	var msgId [24]byte
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(msgId[:]); err != nil {
		t.Fatal(err)
	}

	timestamp := uint64(1711100000)
	// sentBody wire format: flagsASCII + SP + smpEncMessage
	// "T" means notification flag -> binary 0x01
	msgContent := []byte("test message content")
	sentBody := make([]byte, 0, 2+len(msgContent))
	sentBody = append(sentBody, 'T', 0x20)
	sentBody = append(sentBody, msgContent...)

	encrypted := EncryptMsgBody(key, msgId, timestamp, sentBody)

	// Decrypt with SimplexCryptoBoxOpen
	decrypted, ok := SimplexCryptoBoxOpen(key, msgId, encrypted)
	if !ok {
		t.Fatal("SimplexCryptoBoxOpen failed")
	}

	if len(decrypted) != paddedSize {
		t.Fatalf("decrypted length: got %d, want %d", len(decrypted), paddedSize)
	}

	// Verify padded plaintext starts with uint16BE(len(rcvMsgBody))
	rcvMsgBodyLen := binary.BigEndian.Uint16(decrypted[0:2])
	// rcvMsgBody = timestamp(8) + flagsByte(1) + smpEncMessage
	expectedLen := uint16(8 + 1 + len(msgContent))
	if rcvMsgBodyLen != expectedLen {
		t.Fatalf("rcvMsgBody length prefix: got %d, want %d", rcvMsgBodyLen, expectedLen)
	}

	// Verify timestamp
	gotTS := binary.BigEndian.Uint64(decrypted[2:10])
	if gotTS != timestamp {
		t.Fatalf("timestamp: got %d, want %d", gotTS, timestamp)
	}

	// Verify flagsByte is 0x01 (from "T")
	if decrypted[10] != 0x01 {
		t.Fatalf("flagsByte: got 0x%02x, want 0x01", decrypted[10])
	}

	// Verify message content starts at offset 11
	gotBody := decrypted[11 : 11+len(msgContent)]
	if string(gotBody) != string(msgContent) {
		t.Fatalf("body: got %q, want %q", gotBody, msgContent)
	}

	// Verify zero padding after rcvMsgBody
	for i := 2 + int(rcvMsgBodyLen); i < paddedSize; i++ {
		if decrypted[i] != 0x00 {
			t.Fatalf("padding byte at offset %d: got 0x%02x, want 0x00", i, decrypted[i])
		}
	}
}

func TestEncryptMsgBodyNoFlags(t *testing.T) {
	var key [32]byte
	var msgId [24]byte
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(msgId[:]); err != nil {
		t.Fatal(err)
	}

	// sentBody with empty flags: SP + smpEncMessage
	msgContent := []byte("no flags message")
	sentBody := append([]byte(" "), msgContent...)

	encrypted := EncryptMsgBody(key, msgId, 100, sentBody)

	decrypted, ok := SimplexCryptoBoxOpen(key, msgId, encrypted)
	if !ok {
		t.Fatal("SimplexCryptoBoxOpen failed")
	}

	// flagsByte should be 0x00 (empty flags string)
	if decrypted[10] != 0x00 {
		t.Fatalf("flagsByte: got 0x%02x, want 0x00", decrypted[10])
	}

	// Verify content
	rcvLen := int(binary.BigEndian.Uint16(decrypted[0:2]))
	expectedLen := 8 + 1 + len(msgContent)
	if rcvLen != expectedLen {
		t.Fatalf("rcvMsgBody length: got %d, want %d", rcvLen, expectedLen)
	}
}

func TestEncryptMsgBodyNonceUniqueness(t *testing.T) {
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatal(err)
	}

	body := append([]byte(" "), []byte("same body")...)

	var msgId1, msgId2 [24]byte
	if _, err := rand.Read(msgId1[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(msgId2[:]); err != nil {
		t.Fatal(err)
	}

	out1 := EncryptMsgBody(key, msgId1, 100, body)
	out2 := EncryptMsgBody(key, msgId2, 100, body)

	// Different nonces must produce different ciphertexts
	if len(out1) != len(out2) {
		t.Fatal("output lengths differ")
	}
	same := true
	for i := range out1 {
		if out1[i] != out2[i] {
			same = false
			break
		}
	}
	if same {
		t.Fatal("different msgIds produced identical ciphertexts")
	}
}

func TestEncryptMsgBodyEmptyBody(t *testing.T) {
	var key [32]byte
	var msgId [24]byte
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(msgId[:]); err != nil {
		t.Fatal(err)
	}

	// Empty sent body (no SP) - treated as no flags, empty smpEncMessage
	out := EncryptMsgBody(key, msgId, 0, nil)
	if len(out) != 16082 {
		t.Fatalf("output length with empty body: got %d, want 16082", len(out))
	}

	// Decrypt and verify
	decrypted, ok := SimplexCryptoBoxOpen(key, msgId, out)
	if !ok {
		t.Fatal("SimplexCryptoBoxOpen failed for empty body")
	}

	rcvMsgBodyLen := binary.BigEndian.Uint16(decrypted[0:2])
	// timestamp(8) + flagsByte(1) + empty = 9
	if rcvMsgBodyLen != 9 {
		t.Fatalf("rcvMsgBody length for empty body: got %d, want 9", rcvMsgBodyLen)
	}
}

func TestSimplexCryptoBoxOpenWrongKey(t *testing.T) {
	var key1, key2 [32]byte
	var nonce [24]byte
	if _, err := rand.Read(key1[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(key2[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}

	encrypted := simplexCryptoBox(key1, nonce, []byte("secret"))
	_, ok := SimplexCryptoBoxOpen(key2, nonce, encrypted)
	if ok {
		t.Fatal("decryption should fail with wrong key")
	}
}

func TestSimplexCryptoBoxOpenTampered(t *testing.T) {
	var key [32]byte
	var nonce [24]byte
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}

	encrypted := simplexCryptoBox(key, nonce, []byte("secret"))
	// Tamper with ciphertext
	encrypted[20] ^= 0xFF
	_, ok := SimplexCryptoBoxOpen(key, nonce, encrypted)
	if ok {
		t.Fatal("decryption should fail with tampered ciphertext")
	}
}
