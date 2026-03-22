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

	// Verify '#' padding per SMP spec
	for i := 2 + int(length); i < BlockSize; i++ {
		if block[i] != PaddingByte {
			t.Fatalf("expected padding byte 0x%02x ('#') at position %d, got 0x%02x", PaddingByte, i, block[i])
		}
	}
}

func TestParsePayload_PING(t *testing.T) {
	// Build a PING transmission in the new text-based wire format
	var corrID [CorrIDSize]byte
	for i := range corrID {
		corrID[i] = 0x01
	}

	// transmission = authorization + corrId + entityId + "PING"
	transmission := []byte{
		0x00, // authorization = empty (unsigned)
	}
	// corrId = 0x18 + 24 bytes
	transmission = append(transmission, CorrIDSize)
	transmission = append(transmission, corrID[:]...)
	// entityId = empty
	transmission = append(transmission, 0x00)
	// command = "PING"
	transmission = append(transmission, TagPING...)

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

func TestParsePayload_NEW(t *testing.T) {
	var corrID [CorrIDSize]byte
	for i := range corrID {
		corrID[i] = 0xAA
	}

	// Build a NEW transmission
	t2 := BuildTransmission(nil, corrID, nil, TagNEW, []byte("test-body"))
	block := WrapTransmissionBlock(t2)

	// Parse
	payloadLen := binary.BigEndian.Uint16(block[:2])
	payload := block[2 : 2+payloadLen]
	cmds, err := ParsePayload(payload)
	if err != nil {
		t.Fatalf("ParsePayload: %v", err)
	}
	if len(cmds) != 1 {
		t.Fatalf("expected 1 cmd, got %d", len(cmds))
	}
	if cmds[0].Type != CmdNEW {
		t.Fatalf("expected NEW, got 0x%02x", cmds[0].Type)
	}
	if cmds[0].CorrelationID != corrID {
		t.Fatal("corrID mismatch")
	}
	if !bytes.Equal(cmds[0].Body, []byte("test-body")) {
		t.Fatalf("body mismatch: %q", cmds[0].Body)
	}
}

func TestBlockPaddingIsHash(t *testing.T) {
	t2 := BuildTransmission(nil, [CorrIDSize]byte{}, nil, TagPING, nil)
	block := WrapTransmissionBlock(t2)

	payloadLen := binary.BigEndian.Uint16(block[:2])
	for i := 2 + int(payloadLen); i < BlockSize; i++ {
		if block[i] != PaddingByte {
			t.Fatalf("padding at offset %d: got 0x%02x, want 0x%02x ('#')", i, block[i], PaddingByte)
		}
	}
}

func TestCorrIdEcho(t *testing.T) {
	var corrID [CorrIDSize]byte
	for i := range corrID {
		corrID[i] = byte(i)
	}

	resp := Response{
		Type:          CmdPONG,
		CorrelationID: corrID,
	}

	data := resp.Serialize()
	cmds, err := ParsePayload(data)
	if err != nil {
		t.Fatalf("ParsePayload: %v", err)
	}
	if len(cmds) != 1 {
		t.Fatalf("expected 1, got %d", len(cmds))
	}
	if cmds[0].CorrelationID != corrID {
		t.Fatal("corrID not echoed correctly")
	}
}

func TestSerializeAndParsePONG(t *testing.T) {
	var corrID [CorrIDSize]byte
	for i := range corrID {
		corrID[i] = byte(i + 10)
	}

	resp := Response{
		Type:          CmdPONG,
		CorrelationID: corrID,
	}
	data := resp.Serialize()

	cmds, err := ParsePayload(data)
	if err != nil {
		t.Fatalf("ParsePayload: %v", err)
	}
	if cmds[0].Type != CmdPONG {
		t.Fatalf("expected PONG, got 0x%02x", cmds[0].Type)
	}
}

func TestSerializeAndParseERR(t *testing.T) {
	var corrID [CorrIDSize]byte
	resp := Response{
		Type:          CmdERR,
		CorrelationID: corrID,
		ErrorCode:     ErrAuth,
	}
	data := resp.Serialize()

	cmds, err := ParsePayload(data)
	if err != nil {
		t.Fatalf("ParsePayload: %v", err)
	}
	if cmds[0].Type != CmdERR {
		t.Fatalf("expected ERR, got 0x%02x", cmds[0].Type)
	}
	if string(cmds[0].Body) != "AUTH" {
		t.Fatalf("expected error text 'AUTH', got %q", string(cmds[0].Body))
	}
}
