package common

// Command codes
const (
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
	CmdPFWD byte = 0x10
	CmdRFWD byte = 0x11
	CmdRRES byte = 0x12
	CmdPRES byte = 0x13
	CmdQROT byte = 0x14
	CmdQACK byte = 0x15
)

// Error codes
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
)

// Flags
const (
	FlagCoverTraffic byte = 0x01
	FlagNotification byte = 0x02
	FlagPriority     byte = 0x04
)

// Command represents a parsed client command
type Command struct {
	Type          byte
	CorrelationID [24]byte
	EntityID      [24]byte
	HasEntityID   bool
	Signature     []byte
	SignedData    []byte // bytes covered by the signature (session_id through command+body)
	Body          []byte
}

// Response represents a server response
type Response struct {
	Type          byte
	CorrelationID [24]byte
	EntityID      [24]byte
	HasEntityID   bool
	MessageID     [24]byte
	Timestamp     uint64
	Flags         byte
	ErrorCode     byte
	Body          []byte

	// Deliveries are additional responses to send to specific clients
	// after this response has been queued. Used by SEND and ACK to
	// deliver MSG after the OK response.
	Deliveries []Delivery
}

// Delivery represents a response to deliver to a specific client channel
type Delivery struct {
	Target chan<- Response
	Resp   Response
}

// Serialize encodes a response into bytes for block framing
func (r Response) Serialize() []byte {
	// Simplified serialization for the skeleton
	// TODO: implement full transmission encoding per spec
	buf := make([]byte, 0, 128)

	// Batch count = 1
	buf = append(buf, 0x01)

	// Build transmission
	transmission := make([]byte, 0, 64)

	// Signature length = 0 (unsigned for now)
	transmission = append(transmission, 0x00)

	// Session ID length = 0
	transmission = append(transmission, 0x00)

	// Correlation ID (24 bytes)
	transmission = append(transmission, r.CorrelationID[:]...)

	// Entity ID
	if r.HasEntityID {
		transmission = append(transmission, 24) // length
		transmission = append(transmission, r.EntityID[:]...)
	} else {
		transmission = append(transmission, 0x00) // length = 0
	}

	// Command byte
	transmission = append(transmission, r.Type)

	// Command-specific data
	switch r.Type {
	case CmdERR:
		transmission = append(transmission, r.ErrorCode)
	case CmdIDS:
		// IDS body is pre-encoded in r.Body
		transmission = append(transmission, r.Body...)
	case CmdMSG:
		transmission = append(transmission, r.MessageID[:]...)
		// timestamp (8 bytes)
		ts := make([]byte, 8)
		ts[0] = byte(r.Timestamp >> 56)
		ts[1] = byte(r.Timestamp >> 48)
		ts[2] = byte(r.Timestamp >> 40)
		ts[3] = byte(r.Timestamp >> 32)
		ts[4] = byte(r.Timestamp >> 24)
		ts[5] = byte(r.Timestamp >> 16)
		ts[6] = byte(r.Timestamp >> 8)
		ts[7] = byte(r.Timestamp)
		transmission = append(transmission, ts...)
		transmission = append(transmission, r.Flags)
		transmission = append(transmission, r.Body...)
	}

	// Transmission length (2 bytes)
	tLen := uint16(len(transmission))
	buf = append(buf, byte(tLen>>8), byte(tLen))
	buf = append(buf, transmission...)

	return buf
}

// ParsePayload extracts commands from a block payload
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

// parseTransmission parses a single transmission into a Command
func parseTransmission(data []byte) (Command, error) {
	var cmd Command
	offset := 0

	if len(data) < 1 {
		return cmd, ErrBlockTooShort
	}

	// Signature
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

	// Everything from here to the end is the signed data
	signedStart := offset

	// Session ID (skip for now)
	if offset >= len(data) {
		return cmd, ErrBlockTooShort
	}
	sessLen := int(data[offset])
	offset++
	offset += sessLen

	// Correlation ID (24 bytes)
	if offset+24 > len(data) {
		return cmd, ErrBlockTooShort
	}
	copy(cmd.CorrelationID[:], data[offset:offset+24])
	offset += 24

	// Entity ID
	if offset >= len(data) {
		return cmd, ErrBlockTooShort
	}
	entityLen := int(data[offset])
	offset++
	if entityLen > 0 {
		if offset+entityLen > len(data) {
			return cmd, ErrBlockTooShort
		}
		copy(cmd.EntityID[:], data[offset:offset+entityLen])
		cmd.HasEntityID = true
	}
	offset += entityLen

	// Command type
	if offset >= len(data) {
		return cmd, ErrBlockTooShort
	}
	cmd.Type = data[offset]
	offset++

	// Remaining bytes are command-specific body
	if offset < len(data) {
		cmd.Body = make([]byte, len(data)-offset)
		copy(cmd.Body, data[offset:])
	}

	// Capture signed data (everything after signature)
	cmd.SignedData = make([]byte, len(data)-signedStart)
	copy(cmd.SignedData, data[signedStart:])

	return cmd, nil
}
