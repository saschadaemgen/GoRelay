package main

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/saschadaemgen/GoRelay/internal/protocol/common"
	"github.com/saschadaemgen/GoRelay/internal/protocol/smp"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: smp-capture <host:port>")
		fmt.Println("Example: smp-capture smp.simplego.dev:5223")
		os.Exit(1)
	}
	addr := os.Args[1]

	fmt.Printf("=== SMP Capture Tool ===\n")
	fmt.Printf("Target: %s\n\n", addr)

	// Step 1: TLS connect
	fmt.Println("[1] TLS connect...")
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 10 * time.Second},
		"tcp",
		addr,
		&tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{"smp/1"},
			MinVersion:         tls.VersionTLS12,
			MaxVersion:         tls.VersionTLS12,
		},
	)
	if err != nil {
		fmt.Printf("TLS dial failed: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	state := conn.ConnectionState()
	fmt.Printf("  TLS version: 0x%04x\n", state.Version)
	fmt.Printf("  ALPN: %q\n", state.NegotiatedProtocol)
	fmt.Printf("  TLSUnique len: %d\n", len(state.TLSUnique))
	fmt.Printf("  Peer certs: %d\n", len(state.PeerCertificates))

	// Step 2: Read raw ServerHello block
	fmt.Println("\n[2] Reading ServerHello (raw 16384 bytes)...")
	var shBlock [16384]byte
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	_, err = io.ReadFull(conn, shBlock[:])
	if err != nil {
		fmt.Printf("Read ServerHello failed: %v\n", err)
		os.Exit(1)
	}

	shContentLen := binary.BigEndian.Uint16(shBlock[:2])
	fmt.Printf("  ServerHello block contentLength: %d\n", shContentLen)
	fmt.Printf("  First 64 bytes:\n")
	printHexDump(shBlock[:64])
	fmt.Printf("  Padding byte (last byte): 0x%02x (%q)\n", shBlock[16383], string(shBlock[16383]))
	// Check what the padding is
	paddingByte := shBlock[2+shContentLen]
	fmt.Printf("  First padding byte (at offset %d): 0x%02x (%q)\n", 2+shContentLen, paddingByte, string(paddingByte))

	// Parse ServerHello - the real SMP server sends raw handshake data
	// (NOT wrapped in transmissionCount + transmissionLength)
	shPayload := shBlock[2 : 2+shContentLen]
	fmt.Printf("  First byte of payload: 0x%02x\n", shPayload[0])

	// Try parsing directly as ServerHello (real server format)
	serverHello, err := smp.DecodeServerHello(shPayload)
	if err != nil {
		// Try with transmission wrapper (GoRelay format)
		fmt.Printf("  Direct parse failed: %v\n", err)
		fmt.Printf("  Trying with transmission wrapper...\n")
		if len(shPayload) >= 3 {
			fmt.Printf("  transmissionCount: %d\n", shPayload[0])
			shTransLen := binary.BigEndian.Uint16(shPayload[1:3])
			fmt.Printf("  transmissionLength: %d\n", shTransLen)
			if 3+int(shTransLen) <= len(shPayload) {
				serverHello, err = smp.DecodeServerHello(shPayload[3 : 3+shTransLen])
			}
		}
		if err != nil {
			fmt.Printf("DecodeServerHello failed both ways: %v\n", err)
			os.Exit(1)
		}
	}
	fmt.Printf("  ServerHello parsed: vMin=%d vMax=%d sessionID_len=%d cert_len=%d\n",
		serverHello.VersionMin, serverHello.VersionMax,
		len(serverHello.SessionID), len(serverHello.ServerCertDER))

	// Step 3: Build and send ClientHello
	fmt.Println("\n[3] Sending ClientHello...")

	caFingerprint := ""
	if len(state.PeerCertificates) >= 2 {
		caFingerprint = smp.ComputeCAFingerprint(state.PeerCertificates[1])
	} else if len(state.PeerCertificates) >= 1 {
		caFingerprint = smp.ComputeCAFingerprint(state.PeerCertificates[0])
	}
	fmt.Printf("  CA fingerprint (b64): %s\n", caFingerprint)

	// Build ClientHello manually so we can capture exact bytes
	// Use the CA cert (last in chain) for fingerprint
	caCert := state.PeerCertificates[len(state.PeerCertificates)-1]
	fingerprintRaw := smp.ComputeCAFingerprintRaw(caCert)
	fmt.Printf("  CA fingerprint raw (%d bytes): %s\n", len(fingerprintRaw), hex.EncodeToString(fingerprintRaw))

	ch := &smp.ClientHello{
		Version: serverHello.VersionMax,
		KeyHash: fingerprintRaw,
	}
	chBytes := ch.Encode()
	fmt.Printf("  ClientHello bytes (%d): %s\n", len(chBytes), hex.EncodeToString(chBytes))

	// Wrap in block and send (raw, no transmission wrapper - matching handshake format)
	var chBlock [16384]byte
	binary.BigEndian.PutUint16(chBlock[:2], uint16(len(chBytes)))
	copy(chBlock[2:], chBytes)
	for i := 2 + len(chBytes); i < 16384; i++ {
		chBlock[i] = '#'
	}
	conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	_, err = conn.Write(chBlock[:])
	if err != nil {
		fmt.Printf("Write ClientHello failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("  ClientHello sent")

	// Step 4: Send NEW command
	fmt.Println("\n[4] Sending NEW command...")
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Printf("Generate Ed25519 key: %v\n", err)
		os.Exit(1)
	}
	_ = priv

	dhKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		fmt.Printf("Generate X25519 key: %v\n", err)
		os.Exit(1)
	}

	authKeySPKI := smp.EncodeEd25519SPKI(pub)
	dhKeySPKI := smp.EncodeX25519SPKI(dhKey.PublicKey().Bytes())

	newBody := make([]byte, 0, 128)
	newBody = append(newBody, byte(len(authKeySPKI)))
	newBody = append(newBody, authKeySPKI...)
	newBody = append(newBody, byte(len(dhKeySPKI)))
	newBody = append(newBody, dhKeySPKI...)
	newBody = append(newBody, '0', 'S', 'T')

	var corrID [24]byte
	if _, err := rand.Read(corrID[:]); err != nil {
		fmt.Printf("Generate corrID: %v\n", err)
		os.Exit(1)
	}

	// Build NEW transmission: no signature for NEW (self-certifying)
	t := common.BuildTransmission(nil, corrID, nil, common.TagNEW, newBody)
	fmt.Printf("  NEW transmission (%d bytes): %s\n", len(t), hex.EncodeToString(t))

	// Wrap in block with '#' padding
	var newBlock [16384]byte
	content := make([]byte, 0, 3+len(t))
	content = append(content, 0x01)
	tLen := uint16(len(t))
	content = append(content, byte(tLen>>8), byte(tLen))
	content = append(content, t...)
	binary.BigEndian.PutUint16(newBlock[:2], uint16(len(content)))
	copy(newBlock[2:], content)
	for i := 2 + len(content); i < 16384; i++ {
		newBlock[i] = '#'
	}

	fmt.Printf("  NEW block first 128 bytes:\n")
	printHexDump(newBlock[:128])

	conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	_, err = conn.Write(newBlock[:])
	if err != nil {
		fmt.Printf("Write NEW block failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("  NEW command sent")

	// Step 5: Read response
	fmt.Println("\n[5] Reading response (raw 16384 bytes)...")
	var respBlock [16384]byte
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	_, err = io.ReadFull(conn, respBlock[:])
	if err != nil {
		fmt.Printf("Read response failed: %v\n", err)
		os.Exit(1)
	}

	respContentLen := binary.BigEndian.Uint16(respBlock[:2])
	fmt.Printf("  Response contentLength: %d\n", respContentLen)
	fmt.Printf("  First 256 bytes:\n")
	printHexDump(respBlock[:256])

	// Detailed analysis
	fmt.Printf("\n  === Detailed Analysis ===\n")
	fmt.Printf("  Bytes 0-1 (contentLength): %d (0x%04x)\n", respContentLen, respContentLen)

	if respContentLen > 0 && respContentLen <= 16382 {
		payload := respBlock[2 : 2+respContentLen]
		fmt.Printf("  Byte 2 (transmissionCount): %d\n", payload[0])

		if len(payload) >= 3 {
			transLen := binary.BigEndian.Uint16(payload[1:3])
			fmt.Printf("  Bytes 3-4 (transmissionLength): %d\n", transLen)

			if len(payload) >= 3+int(transLen) {
				trans := payload[3 : 3+transLen]
				fmt.Printf("  Byte 5 (authorization len): %d\n", trans[0])

				off := 1
				if trans[0] > 0 {
					off += int(trans[0])
				}
				if off < len(trans) {
					corrIdLen := int(trans[off])
					fmt.Printf("  corrId length prefix: %d\n", corrIdLen)
					off += 1 + corrIdLen

					if off < len(trans) {
						entityIdLen := int(trans[off])
						fmt.Printf("  entityId length prefix: %d\n", entityIdLen)
						off += 1 + entityIdLen

						if off < len(trans) {
							remaining := trans[off:]
							maxShow := 64
							if len(remaining) < maxShow {
								maxShow = len(remaining)
							}
							fmt.Printf("  Command bytes (first %d): %s\n", maxShow, hex.EncodeToString(remaining[:maxShow]))
							fmt.Printf("  Command as ASCII: %q\n", string(remaining[:maxShow]))
						}
					}
				}
			}
		}
	}

	// Padding analysis
	padStart := 2 + int(respContentLen)
	if padStart < 16384 {
		fmt.Printf("\n  Padding byte at offset %d: 0x%02x (%q)\n", padStart, respBlock[padStart], string(respBlock[padStart]))
		fmt.Printf("  Last byte: 0x%02x (%q)\n", respBlock[16383], string(respBlock[16383]))

		// Check if all padding bytes are the same
		allSame := true
		padByte := respBlock[padStart]
		for i := padStart; i < 16384; i++ {
			if respBlock[i] != padByte {
				allSame = false
				fmt.Printf("  Padding inconsistent at offset %d: 0x%02x vs 0x%02x\n", i, respBlock[i], padByte)
				break
			}
		}
		if allSame {
			fmt.Printf("  All padding bytes: 0x%02x (%q) - %d bytes\n", padByte, string(padByte), 16384-padStart)
		}
	}

	fmt.Println("\n=== Done ===")
}

func printHexDump(data []byte) {
	for i := 0; i < len(data); i += 16 {
		end := i + 16
		if end > len(data) {
			end = len(data)
		}
		hexPart := hex.EncodeToString(data[i:end])
		// Add spaces every 2 chars
		spaced := ""
		for j := 0; j < len(hexPart); j += 2 {
			if j > 0 {
				spaced += " "
			}
			end := j + 2
			if end > len(hexPart) {
				end = len(hexPart)
			}
			spaced += hexPart[j:end]
		}
		// ASCII representation
		ascii := ""
		for _, b := range data[i:end] {
			if b >= 32 && b < 127 {
				ascii += string(b)
			} else {
				ascii += "."
			}
		}
		fmt.Printf("    %04x: %-48s  %s\n", i, spaced, ascii)
	}
}
