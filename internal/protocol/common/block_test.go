package common

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
)

func TestWriteBlock_PadsToExactSize(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	payload := []byte("Hello, GRP!")

	go func() {
		if err := WriteBlock(server, payload); err != nil {
			t.Errorf("WriteBlock failed: %v", err)
		}
	}()

	var block [BlockSize]byte
	if _, err := client.Read(block[:]); err != nil {
		t.Fatalf("read failed: %v", err)
	}

	// Verify length prefix
	length := binary.BigEndian.Uint16(block[:2])
	if length != uint16(len(payload)) {
		t.Fatalf("expected length %d, got %d", len(payload), length)
	}

	// Verify payload
	if !bytes.Equal(block[2:2+length], payload) {
		t.Fatalf("payload mismatch")
	}

	// Verify padding
	for i := 2 + int(length); i < BlockSize; i++ {
		if block[i] != PaddingByte {
			t.Fatalf("expected padding byte at position %d, got %x", i, block[i])
		}
	}
}

func TestParsePayload_PING(t *testing.T) {
	// Build a PING transmission
	var corrID [24]byte
	for i := range corrID {
		corrID[i] = 0x01
	}

	transmission := []byte{
		0x00,       // signature length = 0
		0x00,       // session_id length = 0
	}
	transmission = append(transmission, corrID[:]...)
	transmission = append(transmission,
		0x00,       // entity_id length = 0
		CmdPING,    // command = PING
	)

	// Wrap in batch
	payload := []byte{0x01} // batch count = 1
	tLen := uint16(len(transmission))
	payload = append(payload, byte(tLen>>8), byte(tLen))
	payload = append(payload, transmission...)

	cmds, err := ParsePayload(payload)
	if err != nil {
		t.Fatalf("ParsePayload failed: %v", err)
	}

	if len(cmds) != 1 {
		t.Fatalf("expected 1 command, got %d", len(cmds))
	}

	if cmds[0].Type != CmdPING {
		t.Fatalf("expected PING (0x%02x), got 0x%02x", CmdPING, cmds[0].Type)
	}

	if cmds[0].CorrelationID != corrID {
		t.Fatalf("correlation ID mismatch")
	}
}

func TestParsePayload_EmptyPayload(t *testing.T) {
	_, err := ParsePayload([]byte{})
	if err != ErrBlockTooShort {
		t.Fatalf("expected ErrBlockTooShort, got %v", err)
	}
}
