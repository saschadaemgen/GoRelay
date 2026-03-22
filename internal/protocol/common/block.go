package common

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

const (
	// BlockSize is the fixed size of every SMP/GRP frame on the wire
	BlockSize = 16384

	// MaxPayloadSize is the maximum payload within a block
	MaxPayloadSize = BlockSize - 2

	// PaddingByte is the byte used to pad blocks to BlockSize.
	// SMP specification requires zero-byte padding.
	PaddingByte = 0x00
)

var (
	ErrInvalidPayloadLength = errors.New("invalid payload length")
	ErrBlockTooShort        = errors.New("block too short")
)

// ReadBlock reads exactly BlockSize bytes from the connection
// and extracts the payload. Uses io.ReadFull - never plain conn.Read.
func ReadBlock(conn net.Conn) ([]byte, error) {
	var block [BlockSize]byte
	_, err := io.ReadFull(conn, block[:])
	if err != nil {
		return nil, fmt.Errorf("read block: %w", err)
	}

	payloadLen := binary.BigEndian.Uint16(block[:2])
	if int(payloadLen) > MaxPayloadSize {
		return nil, ErrInvalidPayloadLength
	}

	payload := make([]byte, payloadLen)
	copy(payload, block[2:2+payloadLen])
	return payload, nil
}

// WriteBlock serializes a payload into a BlockSize padded block
// and writes it to the connection.
func WriteBlock(conn net.Conn, payload []byte) error {
	if len(payload) > MaxPayloadSize {
		return ErrInvalidPayloadLength
	}

	var block [BlockSize]byte
	binary.BigEndian.PutUint16(block[:2], uint16(len(payload)))
	copy(block[2:], payload)

	// Pad with zero bytes (block is already zero-initialized)
	// No explicit padding loop needed since Go initializes arrays to zero.

	_, err := conn.Write(block[:])
	return err
}

// ReadDeadline returns the read deadline for connections
func ReadDeadline() time.Time {
	return time.Now().Add(5 * time.Minute)
}

// WriteDeadline returns the write deadline for connections
func WriteDeadline() time.Time {
	return time.Now().Add(10 * time.Second)
}
