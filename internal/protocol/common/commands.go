package common

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"log/slog"
)

// SMP text command tags (wire format uses ASCII strings, not byte codes)
const (
	// Legacy byte codes retained for internal routing between goroutines.
	// These are NOT sent on the wire - the wire uses text tags.
	CmdNEW  byte = 0x01
	CmdIDS  byte = 0x02
	CmdSUB  byte = 0x03
	CmdKEY  byte = 0x04
	CmdSEND byte = 0x05
	CmdMSG  byte = 0x06
	CmdACK  byte = 0x07
	CmdOFF  byte = 0x08
	CmdDEL  byte = 0x09
	CmdGET  byte = 0x0A
	CmdOK   byte = 0x0B
	CmdERR  byte = 0x0C
	CmdPING byte = 0x0D
	CmdPONG byte = 0x0E
	CmdEND  byte = 0x0F
	CmdSKEY byte = 0x10
	CmdPFWD byte = 0x16
	CmdRFWD byte = 0x17
	CmdRRES byte = 0x18
	CmdPRES byte = 0x19
	CmdQROT byte = 0x1A
	CmdQACK byte = 0x1B
	CmdPRXY byte = 0x11
)

// Wire text tags for SMP commands (as sent/received on the wire)
var (
	TagNEW  = []byte("NEW ")
	TagIDS  = []byte("IDS ")
	TagSUB  = []byte("SUB")
	TagKEY  = []byte("KEY ")
	TagSKEY = []byte("SKEY ")
	TagSEND = []byte("SEND ")
	TagMSG  = []byte("MSG ")
	TagACK  = []byte("ACK ")
	TagOFF  = []byte("OFF")
	TagDEL  = []byte("DEL")
	TagOK   = []byte("OK")
	TagERR  = []byte("ERR ")
	TagPING = []byte("PING")
	TagPONG = []byte("PONG")
	TagEND  = []byte("END")
	TagPRXY = []byte("PRXY ")
)

// Error codes - internal byte values for routing. The wire format uses text
// strings (e.g., "ERR AUTH"), not binary bytes. See errorCodeToText().
const (
	ErrAuth      byte = 0x01
	ErrNoQueue   byte = 0x02
	ErrNoMsg     byte = 0x03
	ErrDuplicate byte = 0x04
	ErrQuota     byte = 0x05
	ErrLarge     byte = 0x06
	ErrInternal  byte = 0x07
	ErrBlocked   byte = 0x08
	ErrNoKey     byte = 0x09
	ErrDisabled  byte = 0x0A
	ErrVersion   byte = 0x0B
	ErrTimeout   byte = 0x0C
	ErrSyntax    byte = 0x0D
	ErrCmdSyntax byte = 0x0E
	ErrProhibit  byte = 0x0F
	ErrNoAuth    byte = 0x10
	ErrHasAuth   byte = 0x11
	ErrNoEntity  byte = 0x12
)

// errorCodeToText maps internal error codes to SMP wire text.
func errorCodeToText(code byte) []byte {
	switch code {
	case ErrAuth:
		return []byte("AUTH")
	case ErrNoQueue:
		return []byte("NO_QUEUE")
	case ErrNoMsg:
		return []byte("NO_MSG")
	case ErrDuplicate:
		return []byte("DUPLICATE")
	case ErrQuota:
		return []byte("QUOTA")
	case ErrLarge:
		return []byte("LARGE_MSG")
	case ErrInternal:
		return []byte("INTERNAL")
	case ErrBlocked:
		return []byte("BLOCKED")
	case ErrNoKey:
		return []byte("NO_KEY")
	case ErrDisabled:
		return []byte("DISABLED")
	case ErrVersion:
		return []byte("VERSION")
	case ErrTimeout:
		return []byte("TIMEOUT")
	case ErrSyntax:
		return []byte("SYNTAX")
	case ErrCmdSyntax:
		return []byte("CMD SYNTAX")
	case ErrProhibit:
		return []byte("CMD PROHIBITED")
	case ErrNoAuth:
		return []byte("CMD NO_AUTH")
	case ErrHasAuth:
		return []byte("CMD HAS_AUTH")
	case ErrNoEntity:
		return []byte("CMD NO_ENTITY")
	default:
		return []byte("INTERNAL")
	}
}

// Flags
const (
	FlagCoverTraffic byte = 0x01
	FlagNotification byte = 0x02
	FlagPriority     byte = 0x04
)

// CorrIDSize is the size of a correlation ID (24 bytes)
const CorrIDSize = 24

// Command represents a parsed client command
type Command struct {
	Type          byte
	CorrelationID [CorrIDSize]byte
	EntityID      [CorrIDSize]byte
	HasEntityID   bool
	Signature     []byte
	SignedData    []byte // bytes covered by the signature
	Body          []byte // command-specific body (after the command tag)
}

// Response represents a server response
type Response struct {
	Type          byte
	CorrelationID [CorrIDSize]byte
	EntityID      [CorrIDSize]byte
	HasEntityID   bool
	MessageID     [CorrIDSize]byte
	Timestamp     uint64
	Flags         byte
	ErrorCode     byte
	Body          []byte

	// Deliveries are additional responses to send to specific clients
	// after this response has been queued.
	Deliveries []Delivery
}

// Delivery represents a response to deliver to a specific client channel
type Delivery struct {
	Target chan<- Response
	Resp   Response
}

// Serialize encodes a response into the SMP transmission wire format.
//
// Wire format:
//
//	content = transmissionCount(0x01) + transmissionLength(Word16 BE) + transmission
//	transmission = authorization(0x00) + corrId + entityId + command
//	corrId = 0x18 + 24 bytes (or 0x00 for server notifications)
//	entityId = shortString(1 byte len + data)
//	command = text tag + body
func (r Response) Serialize() []byte {
	// Build transmission
	t := make([]byte, 0, 128)

	// authorization = 0x00 (server responses are unsigned)
	t = append(t, 0x00)

	// corrId: 0x18 + 24 bytes for responses, 0x00 for notifications (MSG, END)
	isNotification := r.Type == CmdMSG || r.Type == CmdEND
	if isNotification {
		t = append(t, 0x00) // empty corrId
	} else {
		t = append(t, CorrIDSize) // length prefix = 24
		t = append(t, r.CorrelationID[:]...)
	}

	// entityId = shortString
	if r.HasEntityID {
		t = append(t, CorrIDSize) // length = 24
		t = append(t, r.EntityID[:]...)
	} else {
		t = append(t, 0x00) // length = 0
	}

	// Command tag + body
	switch r.Type {
	case CmdPONG:
		t = append(t, TagPONG...)
	case CmdOK:
		t = append(t, TagOK...)
	case CmdERR:
		t = append(t, TagERR...)
		t = append(t, errorCodeToText(r.ErrorCode)...)
	case CmdIDS:
		t = append(t, TagIDS...)
		t = append(t, r.Body...) // pre-encoded IDS body
	case CmdMSG:
		t = append(t, TagMSG...)
		// msgId = shortString(24 bytes)
		t = append(t, CorrIDSize)
		t = append(t, r.MessageID[:]...)
		// Body is the complete encryptedRcvMsgBody (16082 bytes)
		// containing auth tag + encrypted(padded(timestamp + flags + sentBody))
		t = append(t, r.Body...)
	case CmdEND:
		t = append(t, TagEND...)
	}

	// Wrap in content: transmissionCount + transmissionLength + transmission
	content := make([]byte, 0, 3+len(t))
	content = append(content, 0x01) // transmissionCount = 1
	tLen := uint16(len(t))
	content = append(content, byte(tLen>>8), byte(tLen))
	content = append(content, t...)

	return content
}

// ParsePayload extracts commands from a block payload.
//
// Wire format:
//
//	content = transmissionCount(1 byte) + transmissions
//	transmissions = transmissionLength(Word16 BE) + transmission [+ more]
//	transmission = authorization + corrId + entityId + smpCommand
//	authorization = shortString (1 byte len + sig bytes)
//	corrId = 1 byte len + data (0x18 + 24 bytes, or 0x00)
//	entityId = shortString (1 byte len + data)
//	smpCommand = text tag + body
func ParsePayload(payload []byte) ([]Command, error) {
	if len(payload) < 1 {
		return nil, ErrBlockTooShort
	}

	batchCount := int(payload[0])
	offset := 1
	commands := make([]Command, 0, batchCount)

	for i := 0; i < batchCount; i++ {
		if offset+2 > len(payload) {
			return commands, ErrBlockTooShort
		}

		tLen := int(payload[offset])<<8 | int(payload[offset+1])
		offset += 2

		if offset+tLen > len(payload) {
			return commands, ErrBlockTooShort
		}

		cmd, err := parseTransmission(payload[offset : offset+tLen])
		if err != nil {
			return commands, err
		}
		commands = append(commands, cmd)
		offset += tLen
	}

	return commands, nil
}

// parseTransmission parses a single SMP transmission into a Command.
//
// Wire format:
//
//	transmission = authorization + authorized
//	authorization = shortString (1 byte len + signature bytes)
//	authorized = corrId + entityId + smpCommand
//	corrId = 1 byte len + data
//	entityId = shortString
//	smpCommand = text tag + body
//
// Note: sessionIdentifier is NOT in wire format for v7.
// It IS included in signature computation (handled by caller).
func parseTransmission(data []byte) (Command, error) {
	var cmd Command
	offset := 0

	if len(data) < 1 {
		return cmd, ErrBlockTooShort
	}

	// authorization = shortString (1 byte len + sig)
	sigLen := int(data[offset])
	offset++
	if offset+sigLen > len(data) {
		return cmd, ErrBlockTooShort
	}
	if sigLen > 0 {
		cmd.Signature = make([]byte, sigLen)
		copy(cmd.Signature, data[offset:offset+sigLen])
	}
	offset += sigLen

	// Everything from here is the "authorized" part (signed data).
	// For signature verification, we need: shortString(sessionID) + corrId + entityId + command
	// But sessionID is NOT in the wire format - it's prepended by the verifier.
	// So signedData captures: corrId + entityId + command (from wire)
	signedStart := offset

	// corrId = 1 byte len + data
	if offset >= len(data) {
		return cmd, ErrBlockTooShort
	}
	corrIDLen := int(data[offset])
	offset++
	if corrIDLen > 0 {
		if offset+corrIDLen > len(data) {
			return cmd, ErrBlockTooShort
		}
		if corrIDLen >= CorrIDSize {
			copy(cmd.CorrelationID[:], data[offset:offset+CorrIDSize])
		}
	}
	offset += corrIDLen

	// entityId = shortString
	if offset >= len(data) {
		return cmd, ErrBlockTooShort
	}
	entityLen := int(data[offset])
	offset++
	if entityLen > 0 {
		if offset+entityLen > len(data) {
			return cmd, ErrBlockTooShort
		}
		if entityLen >= CorrIDSize {
			copy(cmd.EntityID[:], data[offset:offset+CorrIDSize])
		}
		cmd.HasEntityID = true
	}
	offset += entityLen

	// smpCommand = text tag + body
	if offset >= len(data) {
		return cmd, ErrBlockTooShort
	}

	remaining := data[offset:]
	cmd.Type, cmd.Body = parseTextCommand(remaining)

	// Capture signed data (corrId through end of command)
	cmd.SignedData = make([]byte, len(data)-signedStart)
	copy(cmd.SignedData, data[signedStart:])

	return cmd, nil
}

// parseTextCommand parses a text command tag and returns the internal
// command byte code and the remaining body after the tag.
func parseTextCommand(data []byte) (byte, []byte) {
	// Check tags in order (longer tags first to avoid prefix conflicts)
	type tagEntry struct {
		tag  []byte
		code byte
	}
	tags := []tagEntry{
		{TagSEND, CmdSEND},
		{TagSKEY, CmdSKEY},
		{TagPRXY, CmdPRXY},
		{TagPING, CmdPING},
		{TagPONG, CmdPONG},
		{TagNEW, CmdNEW},
		{TagIDS, CmdIDS},
		{TagSUB, CmdSUB},
		{TagKEY, CmdKEY},
		{TagMSG, CmdMSG},
		{TagACK, CmdACK},
		{TagOFF, CmdOFF},
		{TagDEL, CmdDEL},
		{TagOK, CmdOK},
		{TagERR, CmdERR},
		{TagEND, CmdEND},
	}

	for _, te := range tags {
		if bytes.HasPrefix(data, te.tag) {
			body := data[len(te.tag):]
			if len(body) > 0 {
				bodyCopy := make([]byte, len(body))
				copy(bodyCopy, body)
				return te.code, bodyCopy
			}
			return te.code, nil
		}
	}

	// Unknown command - log first 20 bytes for debugging
	n := len(data)
	if n > 20 {
		n = 20
	}
	slog.Info("parseTextCommand: no tag match",
		"first_bytes_hex", hex.EncodeToString(data[:n]),
		"first_bytes_ascii", string(data[:n]),
		"data_len", len(data),
	)
	return 0xFF, nil
}

// BuildTransmission builds a single transmission for sending.
// This is a helper for constructing SMP wire-format transmissions.
//
//	transmission = authorization + corrId + entityId + command
//	authorization = shortString (0x00 for unsigned, or len + sig for signed)
//	corrId = 0x18 + 24 bytes
//	entityId = shortString
func BuildTransmission(sig []byte, corrID [CorrIDSize]byte, entityID []byte, cmdTag []byte, cmdBody []byte) []byte {
	t := make([]byte, 0, 128+len(cmdBody))

	// authorization
	if len(sig) > 0 {
		t = append(t, byte(len(sig)))
		t = append(t, sig...)
	} else {
		t = append(t, 0x00)
	}

	// corrId = length prefix + data
	t = append(t, CorrIDSize)
	t = append(t, corrID[:]...)

	// entityId = shortString
	if len(entityID) > 0 {
		t = append(t, byte(len(entityID)))
		t = append(t, entityID...)
	} else {
		t = append(t, 0x00)
	}

	// command tag + body
	t = append(t, cmdTag...)
	t = append(t, cmdBody...)

	return t
}

// WrapTransmissionBlock wraps a transmission into a 16384-byte block.
func WrapTransmissionBlock(transmission []byte) [BlockSize]byte {
	content := make([]byte, 0, 3+len(transmission))
	content = append(content, 0x01) // transmissionCount = 1
	tLen := uint16(len(transmission))
	content = append(content, byte(tLen>>8), byte(tLen))
	content = append(content, transmission...)

	var block [BlockSize]byte
	binary.BigEndian.PutUint16(block[:2], uint16(len(content)))
	copy(block[2:], content)
	// Pad with '#' (0x23) per SMP spec: pad = N*"#"
	for i := 2 + len(content); i < BlockSize; i++ {
		block[i] = PaddingByte
	}
	return block
}

// BuildSignedData builds the data that gets signed for a command.
// signedData = shortString(sessionID) + corrId(len+data) + entityId(shortString) + cmdTag + cmdBody
//
// Note: sessionID is included in the signed data but NOT in the wire format (v7+).
func BuildSignedData(sessionID []byte, corrID [CorrIDSize]byte, entityID []byte, cmdTag []byte, cmdBody []byte) []byte {
	sd := make([]byte, 0, 128+len(cmdBody))

	// shortString(sessionID) - included in signature computation
	sd = append(sd, byte(len(sessionID)))
	if len(sessionID) > 0 {
		sd = append(sd, sessionID...)
	}

	// corrId = length prefix + data
	sd = append(sd, CorrIDSize)
	sd = append(sd, corrID[:]...)

	// entityId = shortString
	if len(entityID) > 0 {
		sd = append(sd, byte(len(entityID)))
		sd = append(sd, entityID...)
	} else {
		sd = append(sd, 0x00)
	}

	// command tag + body
	sd = append(sd, cmdTag...)
	sd = append(sd, cmdBody...)

	return sd
}
