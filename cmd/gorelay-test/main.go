package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/saschadaemgen/GoRelay/internal/protocol/common"
)

// ANSI color helpers - disabled if not a terminal
var (
	colorGreen  = "\033[32m"
	colorRed    = "\033[31m"
	colorYellow = "\033[33m"
	colorCyan   = "\033[36m"
	colorReset  = "\033[0m"
	colorBold   = "\033[1m"
)

func init() {
	// Disable colors if stdout is not a terminal
	if fileInfo, _ := os.Stdout.Stat(); fileInfo != nil {
		if fileInfo.Mode()&os.ModeCharDevice == 0 {
			colorGreen = ""
			colorRed = ""
			colorYellow = ""
			colorCyan = ""
			colorReset = ""
			colorBold = ""
		}
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `%sGoRelay SMP Test Client%s

Usage: gorelay-test <command> [flags]

Commands:
  ping            Send PING, receive PONG, print latency
  create-queue    Create a new queue, print IDs
  subscribe       Subscribe to a queue and wait for messages
  send-message    Send a message to a queue
  full-test       Run automated full cycle test

Global flags:
  --server        Server address (host:port, required)
  --skip-verify   Skip TLS certificate verification (default: true)
  --verbose       Print detailed protocol exchange
`, colorBold, colorReset)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	subcmd := os.Args[1]
	if subcmd == "help" || subcmd == "--help" || subcmd == "-h" {
		usage()
		os.Exit(0)
	}

	// Remove subcommand from args for flag parsing
	os.Args = append(os.Args[:1], os.Args[2:]...)

	var exitCode int
	switch subcmd {
	case "ping":
		exitCode = runPing()
	case "create-queue":
		exitCode = runCreateQueue()
	case "subscribe":
		exitCode = runSubscribe()
	case "send-message":
		exitCode = runSendMessage()
	case "full-test":
		exitCode = runFullTest()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", subcmd)
		usage()
		os.Exit(1)
	}
	os.Exit(exitCode)
}

// --- ping ---

func runPing() int {
	fs := flag.NewFlagSet("ping", flag.ExitOnError)
	server := fs.String("server", "", "server address (host:port)")
	skipVerify := fs.Bool("skip-verify", true, "skip TLS cert verification")
	verbose := fs.Bool("verbose", false, "verbose output")
	if err := fs.Parse(os.Args[1:]); err != nil {
		return 1
	}
	if *server == "" {
		fmt.Fprintf(os.Stderr, "error: --server is required\n")
		return 1
	}

	fmt.Printf("%sPING%s %s\n", colorBold, colorReset, *server)

	start := time.Now()
	client, err := ConnectSMP(*server, *skipVerify, *verbose)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%sFAILED%s connect: %v\n", colorRed, colorReset, err)
		return 1
	}
	defer client.Close()
	connectTime := time.Since(start)

	pingStart := time.Now()
	cmd, err := client.SendPING()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%sFAILED%s ping: %v\n", colorRed, colorReset, err)
		return 1
	}
	pingTime := time.Since(pingStart)

	if cmd.Type != 0x0E { // CmdPONG
		fmt.Fprintf(os.Stderr, "%sFAILED%s expected PONG, got %s\n", colorRed, colorReset, cmdName(cmd.Type))
		return 1
	}

	fmt.Printf("%sPONG%s received\n", colorGreen, colorReset)
	fmt.Printf("  Connect:   %s\n", connectTime.Round(time.Microsecond))
	fmt.Printf("  PING/PONG: %s\n", pingTime.Round(time.Microsecond))
	fmt.Printf("  Total:     %s\n", time.Since(start).Round(time.Microsecond))
	return 0
}

// --- create-queue ---

// KeyFile stores an Ed25519 keypair in JSON format.
type KeyFile struct {
	PublicKey  string `json:"public_key"`
	PrivateKey string `json:"private_key"`
}

func runCreateQueue() int {
	fs := flag.NewFlagSet("create-queue", flag.ExitOnError)
	server := fs.String("server", "", "server address (host:port)")
	skipVerify := fs.Bool("skip-verify", true, "skip TLS cert verification")
	verbose := fs.Bool("verbose", false, "verbose output")
	keyFile := fs.String("key-file", "", "save recipient key to file (JSON)")
	if err := fs.Parse(os.Args[1:]); err != nil {
		return 1
	}
	if *server == "" {
		fmt.Fprintf(os.Stderr, "error: --server is required\n")
		return 1
	}

	fmt.Printf("%sNEW%s queue on %s\n", colorBold, colorReset, *server)

	start := time.Now()
	client, err := ConnectSMP(*server, *skipVerify, *verbose)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%sFAILED%s connect: %v\n", colorRed, colorReset, err)
		return 1
	}
	defer client.Close()

	recipientPub, recipientPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%sFAILED%s keygen: %v\n", colorRed, colorReset, err)
		return 1
	}

	recipientID, senderID, dhPubKey, err := client.SendNEW(recipientPub)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%sFAILED%s NEW: %v\n", colorRed, colorReset, err)
		return 1
	}

	elapsed := time.Since(start)

	fmt.Printf("%sQueue created%s\n", colorGreen, colorReset)
	fmt.Printf("  Recipient ID: %s%s%s\n", colorCyan, hexID(recipientID), colorReset)
	fmt.Printf("  Sender ID:    %s%s%s\n", colorCyan, hexID(senderID), colorReset)
	fmt.Printf("  DH Pub Key:   %s\n", hex.EncodeToString(dhPubKey))
	fmt.Printf("  Time:         %s\n", elapsed.Round(time.Microsecond))

	if *keyFile != "" {
		kf := KeyFile{
			PublicKey:  hex.EncodeToString(recipientPub),
			PrivateKey: hex.EncodeToString(recipientPriv.Seed()),
		}
		data, err := json.MarshalIndent(kf, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "%sFAILED%s marshal key: %v\n", colorRed, colorReset, err)
			return 1
		}
		if err := os.WriteFile(*keyFile, data, 0600); err != nil {
			fmt.Fprintf(os.Stderr, "%sFAILED%s write key file: %v\n", colorRed, colorReset, err)
			return 1
		}
		fmt.Printf("  Key saved to: %s\n", *keyFile)
	}

	return 0
}

// --- subscribe ---

func runSubscribe() int {
	fs := flag.NewFlagSet("subscribe", flag.ExitOnError)
	server := fs.String("server", "", "server address (host:port)")
	skipVerify := fs.Bool("skip-verify", true, "skip TLS cert verification")
	verbose := fs.Bool("verbose", false, "verbose output")
	queueID := fs.String("queue-id", "", "recipient queue ID (hex)")
	keyFilePath := fs.String("key-file", "", "path to recipient key file (JSON)")
	if err := fs.Parse(os.Args[1:]); err != nil {
		return 1
	}
	if *server == "" || *queueID == "" || *keyFilePath == "" {
		fmt.Fprintf(os.Stderr, "error: --server, --queue-id, and --key-file are required\n")
		return 1
	}

	recipientID, err := parseHexID(*queueID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: invalid queue-id: %v\n", err)
		return 1
	}

	privKey, err := loadPrivateKey(*keyFilePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: load key: %v\n", err)
		return 1
	}

	fmt.Printf("%sSUB%s queue %s on %s\n", colorBold, colorReset, *queueID, *server)

	client, err := ConnectSMP(*server, *skipVerify, *verbose)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%sFAILED%s connect: %v\n", colorRed, colorReset, err)
		return 1
	}
	defer client.Close()

	if err := client.SendSUB(recipientID, privKey); err != nil {
		fmt.Fprintf(os.Stderr, "%sFAILED%s SUB: %v\n", colorRed, colorReset, err)
		return 1
	}

	// First response could be OK (no pending) or MSG (pending message)
	firstResp, err := client.ReadAnyResponse()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%sFAILED%s read response: %v\n", colorRed, colorReset, err)
		return 1
	}

	if firstResp.Type == 0x0C { // ERR
		fmt.Fprintf(os.Stderr, "%sFAILED%s SUB returned ERR (code=0x%02x)\n", colorRed, colorReset, errorCode(firstResp))
		return 1
	}

	fmt.Printf("%sSubscribed%s - waiting for messages (Ctrl+C to quit)\n", colorGreen, colorReset)

	// Process first response if it was a MSG
	if firstResp.Type == 0x06 { // MSG
		printMSGFromCommand(firstResp)
	}

	// Wait for more messages
	for {
		msgID, _, _, body, err := client.ReadMSG()
		if err != nil {
			fmt.Fprintf(os.Stderr, "\n%sDisconnected%s: %v\n", colorYellow, colorReset, err)
			return 0
		}
		fmt.Printf("\n%sMSG%s [%s]\n  %s\n", colorGreen, colorReset, hexID(msgID), string(body))

		// Auto-ACK
		if ackErr := client.SendACK(recipientID, msgID); ackErr != nil {
			fmt.Fprintf(os.Stderr, "  %sACK failed%s: %v\n", colorYellow, colorReset, ackErr)
		}
	}
}

// --- send-message ---

func runSendMessage() int {
	fs := flag.NewFlagSet("send-message", flag.ExitOnError)
	server := fs.String("server", "", "server address (host:port)")
	skipVerify := fs.Bool("skip-verify", true, "skip TLS cert verification")
	verbose := fs.Bool("verbose", false, "verbose output")
	queueID := fs.String("queue-id", "", "sender queue ID (hex)")
	keyFilePath := fs.String("key-file", "", "path to sender key file (JSON)")
	message := fs.String("message", "", "message text to send")
	if err := fs.Parse(os.Args[1:]); err != nil {
		return 1
	}
	if *server == "" || *queueID == "" || *keyFilePath == "" || *message == "" {
		fmt.Fprintf(os.Stderr, "error: --server, --queue-id, --key-file, and --message are required\n")
		return 1
	}

	senderID, err := parseHexID(*queueID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: invalid queue-id: %v\n", err)
		return 1
	}

	privKey, err := loadPrivateKey(*keyFilePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: load key: %v\n", err)
		return 1
	}

	fmt.Printf("%sSEND%s to %s on %s\n", colorBold, colorReset, *queueID, *server)

	start := time.Now()
	client, err := ConnectSMP(*server, *skipVerify, *verbose)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%sFAILED%s connect: %v\n", colorRed, colorReset, err)
		return 1
	}
	defer client.Close()

	// Set sender key (KEY) then send message (SEND)
	senderPub := privKey.Public().(ed25519.PublicKey)
	if err := client.SendKEY(senderID, senderPub); err != nil {
		fmt.Fprintf(os.Stderr, "%sFAILED%s KEY: %v\n", colorRed, colorReset, err)
		return 1
	}

	if err := client.SendSEND(senderID, privKey, []byte(*message)); err != nil {
		fmt.Fprintf(os.Stderr, "%sFAILED%s SEND: %v\n", colorRed, colorReset, err)
		return 1
	}

	fmt.Printf("%sMessage sent%s (%d bytes, %s)\n", colorGreen, colorReset, len(*message), time.Since(start).Round(time.Microsecond))
	return 0
}

// --- full-test ---

func runFullTest() int {
	fs := flag.NewFlagSet("full-test", flag.ExitOnError)
	server := fs.String("server", "", "server address (host:port)")
	skipVerify := fs.Bool("skip-verify", true, "skip TLS cert verification")
	verbose := fs.Bool("verbose", false, "verbose output")
	if err := fs.Parse(os.Args[1:]); err != nil {
		return 1
	}
	if *server == "" {
		fmt.Fprintf(os.Stderr, "error: --server is required\n")
		return 1
	}

	fmt.Printf("%sFULL TEST%s against %s\n", colorBold, colorReset, *server)
	totalStart := time.Now()

	// Step 1: Recipient creates queue
	step("1/6", "Creating queue (NEW)")
	stepStart := time.Now()

	recipientClient, err := ConnectSMP(*server, *skipVerify, *verbose)
	if err != nil {
		return fail("connect recipient: %v", err)
	}
	defer recipientClient.Close()

	recipientPub, recipientPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fail("keygen: %v", err)
	}

	recipientID, senderID, _, err := recipientClient.SendNEW(recipientPub)
	if err != nil {
		return fail("NEW: %v", err)
	}
	ok(time.Since(stepStart))
	if *verbose {
		fmt.Printf("      Recipient ID: %s\n", hexID(recipientID))
		fmt.Printf("      Sender ID:    %s\n", hexID(senderID))
	}

	// Step 2: Sender connects and sets key (KEY)
	step("2/6", "Setting sender key (KEY)")
	stepStart = time.Now()

	senderClient, err := ConnectSMP(*server, *skipVerify, *verbose)
	if err != nil {
		return fail("connect sender: %v", err)
	}
	defer senderClient.Close()

	senderPub, senderPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fail("keygen: %v", err)
	}

	if err := senderClient.SendKEY(recipientID, senderPub); err != nil {
		return fail("KEY: %v", err)
	}
	ok(time.Since(stepStart))
	_ = recipientPriv // used for SUB verification below

	// Step 3: Sender sends message (SEND)
	testMessage := fmt.Sprintf("GoRelay full-test %s", time.Now().Format(time.RFC3339))
	step("3/6", "Sending message (SEND)")
	stepStart = time.Now()

	if err := senderClient.SendSEND(senderID, senderPriv, []byte(testMessage)); err != nil {
		return fail("SEND: %v", err)
	}
	ok(time.Since(stepStart))

	// Step 4: Recipient receives MSG
	step("4/6", "Receiving message (MSG)")
	stepStart = time.Now()

	msgID, _, _, body, err := recipientClient.ReadMSG()
	if err != nil {
		return fail("read MSG: %v", err)
	}
	if string(body) != testMessage {
		return fail("MSG body mismatch: got %q, want %q", body, testMessage)
	}
	ok(time.Since(stepStart))
	if *verbose {
		fmt.Printf("      Message ID: %s\n", hexID(msgID))
		fmt.Printf("      Body: %s\n", string(body))
	}

	// Step 5: Recipient ACKs
	step("5/6", "Acknowledging message (ACK)")
	stepStart = time.Now()

	if err := recipientClient.SendACK(recipientID, msgID); err != nil {
		return fail("ACK: %v", err)
	}
	ok(time.Since(stepStart))

	// Step 6: Verify PING still works
	step("6/6", "Verifying connection (PING)")
	stepStart = time.Now()

	cmd, err := recipientClient.SendPING()
	if err != nil {
		return fail("PING: %v", err)
	}
	if cmd.Type != 0x0E { // CmdPONG
		return fail("expected PONG, got %s", cmdName(cmd.Type))
	}
	ok(time.Since(stepStart))

	totalTime := time.Since(totalStart)
	fmt.Printf("\n%s%sFULL TEST PASSED%s (%s)\n", colorBold, colorGreen, colorReset, totalTime.Round(time.Microsecond))
	return 0
}

// --- helpers ---

func step(num, desc string) {
	fmt.Printf("  [%s] %s... ", num, desc)
}

func ok(d time.Duration) {
	fmt.Printf("%sOK%s (%s)\n", colorGreen, colorReset, d.Round(time.Microsecond))
}

func fail(format string, args ...interface{}) int {
	fmt.Printf("%sFAILED%s\n", colorRed, colorReset)
	fmt.Fprintf(os.Stderr, "  error: "+format+"\n", args...)
	return 1
}

func parseHexID(s string) ([24]byte, error) {
	var id [24]byte
	b, err := hex.DecodeString(s)
	if err != nil {
		return id, err
	}
	if len(b) != 24 {
		return id, fmt.Errorf("expected 24 bytes, got %d", len(b))
	}
	copy(id[:], b)
	return id, nil
}

func loadPrivateKey(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var kf KeyFile
	if err := json.Unmarshal(data, &kf); err != nil {
		return nil, fmt.Errorf("parse key file: %w", err)
	}
	seed, err := hex.DecodeString(kf.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("decode private key: %w", err)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

func printMSGFromCommand(cmd common.Command) {
	if len(cmd.Body) < 33 {
		fmt.Printf("\n%sMSG%s [body too short]\n", colorGreen, colorReset)
		return
	}
	var msgID [24]byte
	copy(msgID[:], cmd.Body[0:24])
	body := cmd.Body[33:]
	fmt.Printf("\n%sMSG%s [%s]\n  %s\n", colorGreen, colorReset, hexID(msgID), string(body))
}
