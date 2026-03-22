package server

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"runtime/debug"
	"sync"
	"sync/atomic"

	"github.com/saschadaemgen/GoRelay/internal/config"
	"github.com/saschadaemgen/GoRelay/internal/protocol/common"
	"github.com/saschadaemgen/GoRelay/internal/protocol/smp"
	"github.com/saschadaemgen/GoRelay/internal/queue"
)


// Server is the core GoRelay server
type Server struct {
	config          *config.Config
	store           queue.Store
	subHub          *SubscriptionHub
	certManager     *CertManager
	metrics         *Metrics
	smpURI          string
	connectionCount atomic.Int64
	clientWg        sync.WaitGroup
}

// New creates a new GoRelay server instance
func New(cfg *config.Config) (*Server, error) {
	store := queue.NewMemoryStore()
	return newWithStore(cfg, store)
}

// NewWithBadger creates a server backed by BadgerDB.
func NewWithBadger(cfg *config.Config) (*Server, error) {
	badgerCfg := queue.BadgerStoreConfig{
		Path:       cfg.Store.Path,
		DefaultTTL: cfg.Store.DefaultTTL,
		MaxTTL:     cfg.Store.MaxTTL,
	}
	store, err := queue.NewBadgerStore(badgerCfg)
	if err != nil {
		return nil, fmt.Errorf("badger store: %w", err)
	}
	return newWithStore(cfg, store)
}

func newWithStore(cfg *config.Config, store queue.Store) (*Server, error) {
	var cm *CertManager
	if cfg.SMP.Enabled {
		var err error
		cm, err = NewCertManager(cfg.Server.DataDir)
		if err != nil {
			return nil, fmt.Errorf("cert manager: %w", err)
		}
	}

	return &Server{
		config:      cfg,
		store:       store,
		subHub:      NewSubscriptionHub(),
		certManager: cm,
		metrics:     NewMetrics(),
	}, nil
}

// Run starts SMP, GRP, and admin listeners and blocks until context is cancelled
func (s *Server) Run(ctx context.Context) error {
	errCh := make(chan error, 3)

	if s.config.SMP.Enabled {
		go func() {
			if err := s.listenSMP(ctx); err != nil {
				errCh <- fmt.Errorf("smp listener: %w", err)
			}
		}()
	}

	if s.config.GRP.Enabled {
		go func() {
			if err := s.listenGRP(ctx); err != nil {
				errCh <- fmt.Errorf("grp listener: %w", err)
			}
		}()
	}

	// Start admin dashboard
	if s.config.Metrics.Enabled && s.config.Metrics.Address != "" {
		go func() {
			if err := s.startAdmin(ctx, s.config.Metrics.Address); err != nil {
				errCh <- fmt.Errorf("admin server: %w", err)
			}
		}()
	}

	slog.Info("GoRelay is ready",
		"smp", s.config.SMP.Address,
		"grp", s.config.GRP.Address,
	)

	// Wait for context cancellation or fatal error
	select {
	case <-ctx.Done():
		slog.Info("shutdown signal received, stopping server")
		s.shutdown()
		return nil
	case err := <-errCh:
		s.shutdown()
		return err
	}
}

// listenSMP starts the SMP listener on port 5223
func (s *Server) listenSMP(ctx context.Context) error {
	tlsConfig := s.certManager.TLSConfig()

	listener, err := tls.Listen("tcp", s.config.SMP.Address, tlsConfig)
	if err != nil {
		return fmt.Errorf("listen smp: %w", err)
	}
	defer listener.Close()

	host := s.config.Server.Hostname
	port := s.config.SMP.Address
	// Extract port number from address like ":5223" or "0.0.0.0:5223"
	if idx := len(port) - 1; idx >= 0 {
		for i := len(port) - 1; i >= 0; i-- {
			if port[i] == ':' {
				port = port[i+1:]
				break
			}
		}
	}
	s.smpURI = s.certManager.SMPURI(host, port)
	slog.Info("SMP listener ready", "address", s.config.SMP.Address, "uri", s.smpURI)

	go func() {
		<-ctx.Done()
		listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				slog.Error("smp accept error", "err", err)
				continue
			}
		}

		slog.Debug("SMP raw TCP connection accepted", "remote", conn.RemoteAddr().String())

		if s.connectionCount.Load() >= int64(s.config.Limits.MaxConnections) {
			slog.Warn("SMP connection rejected: max connections reached", "remote", conn.RemoteAddr().String())
			conn.Close()
			continue
		}

		s.connectionCount.Add(1)
		s.metrics.ActiveConnectionsSMP.Add(1)
		s.metrics.TotalConnectionsSMP.Add(1)
		s.metrics.UpdatePeakConnections()
		s.clientWg.Add(1)
		go func() {
			defer s.clientWg.Done()
			defer s.connectionCount.Add(-1)
			defer s.metrics.ActiveConnectionsSMP.Add(-1)
			s.handleSMPConnection(ctx, conn)
		}()
	}
}

// listenGRP starts the GRP listener on port 7443
func (s *Server) listenGRP(ctx context.Context) error {
	listener, err := net.Listen("tcp", s.config.GRP.Address)
	if err != nil {
		return fmt.Errorf("listen grp: %w", err)
	}
	defer listener.Close()

	slog.Info("GRP listener started", "address", s.config.GRP.Address)

	go func() {
		<-ctx.Done()
		listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				slog.Error("grp accept error", "err", err)
				continue
			}
		}

		if s.connectionCount.Load() >= int64(s.config.Limits.MaxConnections) {
			conn.Close()
			continue
		}

		s.connectionCount.Add(1)
		s.metrics.ActiveConnectionsGRP.Add(1)
		s.metrics.TotalConnectionsGRP.Add(1)
		s.metrics.UpdatePeakConnections()
		s.clientWg.Add(1)
		go func() {
			defer s.clientWg.Done()
			defer s.connectionCount.Add(-1)
			defer s.metrics.ActiveConnectionsGRP.Add(-1)
			s.handleGRPConnection(ctx, conn)
		}()
	}
}

// handleSMPConnection handles a single SMP client connection
func (s *Server) handleSMPConnection(ctx context.Context, conn net.Conn) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("PANIC in handleSMPConnection", "panic", r, "stack", string(debug.Stack()))
		}
	}()
	defer conn.Close()

	slog.Debug("SMP connection accepted", "remote", conn.RemoteAddr().String())

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		slog.Error("connection is not TLS", "remote", conn.RemoteAddr().String())
		return
	}

	// Complete TLS handshake
	slog.Debug("starting TLS handshake", "remote", conn.RemoteAddr().String())
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		slog.Error("TLS handshake failed", "err", err, "remote", conn.RemoteAddr().String())
		return
	}

	// Check ALPN - do not reject, but track for version range
	state := tlsConn.ConnectionState()
	alpnConfirmed := state.NegotiatedProtocol == "smp/1"

	slog.Debug("TLS handshake complete",
		"version", fmt.Sprintf("0x%04x", state.Version),
		"cipher", fmt.Sprintf("0x%04x", state.CipherSuite),
		"alpn", state.NegotiatedProtocol,
		"alpn_confirmed", alpnConfirmed,
		"tls_unique_len", len(state.TLSUnique),
	)

	// Extract TLS channel binding (tls-unique / RFC 5929).
	// With TLS 1.2 this is the client's Finished message, matching
	// what the Haskell tls library returns via getPeerFinished.
	sessionID := state.TLSUnique
	if len(sessionID) == 0 {
		slog.Error("tls-unique channel binding is empty, rejecting connection")
		return
	}

	// Build handshake parameters
	params := smp.ServerHandshakeParams{
		OnlineCertDER: s.certManager.OnlineCertDER(),
		OnlineKey:     s.certManager.OnlineKey(),
		CAFingerprint: s.certManager.Fingerprint(),
		SessionID:     sessionID,
		VersionMin:    smp.SMPVersionMin,
		VersionMax:    smp.SMPVersionMax,
		ALPNConfirmed: alpnConfirmed,
	}

	// SMP version handshake (inside 16 KB block framing)
	slog.Debug("starting SMP handshake")
	hsResult, err := smp.ServerHandshake(tlsConn, params)
	if err != nil {
		slog.Error("SMP handshake failed", "err", err)
		return
	}

	slog.Info("SMP handshake complete", "version", hsResult.Version)

	client := NewClient(conn, ProtocolSMP)
	client.sessionID = sessionID
	client.smpVersion = hsResult.Version
	defer s.clientDisconnected(client)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(3)

	go func() {
		defer func() {
			if r := recover(); r != nil {
				slog.Error("PANIC in receiver", "panic", r, "stack", string(debug.Stack()))
			}
		}()
		defer wg.Done()
		defer cancel()
		s.receiver(ctx, client)
	}()
	go func() {
		defer func() {
			if r := recover(); r != nil {
				slog.Error("PANIC in processor", "panic", r, "stack", string(debug.Stack()))
			}
		}()
		defer wg.Done()
		defer cancel()
		s.processor(ctx, client)
	}()
	go func() {
		defer func() {
			if r := recover(); r != nil {
				slog.Error("PANIC in sender", "panic", r, "stack", string(debug.Stack()))
			}
		}()
		defer wg.Done()
		defer cancel()
		s.sender(ctx, client)
	}()

	wg.Wait()
	slog.Debug("SMP connection handler exiting")
}

// handleGRPConnection handles a single GRP client connection
func (s *Server) handleGRPConnection(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	// TODO: Noise handshake with hybrid PQC
	// For now, just read version byte and log
	buf := make([]byte, 1)
	if _, err := conn.Read(buf); err != nil {
		return
	}

	if buf[0] != 0x01 { // GRP/1
		return
	}

	slog.Info("GRP client connected", "version", buf[0], "connections", s.connectionCount.Load())

	// TODO: implement full GRP connection handling
	// Placeholder: close after version check
}

// receiver reads 16 KB blocks from the connection
func (s *Server) receiver(ctx context.Context, c *Client) {
	slog.Debug("receiver goroutine started")
	for {
		select {
		case <-ctx.Done():
			slog.Debug("receiver: context cancelled")
			return
		default:
		}

		c.conn.SetReadDeadline(common.ReadDeadline())
		block, err := common.ReadBlock(c.conn)
		if err != nil {
			slog.Debug("receiver: read block failed", "err", err)
			return
		}

		slog.Debug("receiver: got block", "first32", hex.EncodeToString(block[:min(32, len(block))]))

		cmds, err := common.ParsePayload(block)
		if err != nil {
			slog.Debug("receiver: parse error", "err", err, "first32", hex.EncodeToString(block[:min(32, len(block))]))
			continue
		}

		slog.Debug("receiver: parsed commands", "count", len(cmds))

		for _, cmd := range cmds {
			slog.Debug("receiver: dispatching command", "type", fmt.Sprintf("0x%02x", cmd.Type))
			select {
			case c.rcvQ <- cmd:
			case <-ctx.Done():
				slog.Debug("receiver: context cancelled during dispatch")
				return
			}
		}
	}
}

// processor handles commands from the receive queue
func (s *Server) processor(ctx context.Context, c *Client) {
	slog.Debug("processor goroutine started")
	for {
		select {
		case <-ctx.Done():
			slog.Debug("processor: context cancelled")
			return
		case cmd := <-c.rcvQ:
			slog.Debug("processor: handling command", "type", fmt.Sprintf("0x%02x", cmd.Type))
			resp := s.dispatch(c, cmd)
			slog.Debug("processor: response ready", "type", fmt.Sprintf("0x%02x", resp.Type), "deliveries", len(resp.Deliveries))
			deliveries := resp.Deliveries
			resp.Deliveries = nil
			select {
			case c.sndQ <- resp:
			case <-ctx.Done():
				slog.Debug("processor: context cancelled during send")
				return
			}
			// Send follow-up deliveries after the primary response
			for _, d := range deliveries {
				select {
				case d.Target <- d.Resp:
				case <-ctx.Done():
					return
				}
			}
		}
	}
}

// sender writes responses as 16 KB blocks
func (s *Server) sender(ctx context.Context, c *Client) {
	slog.Debug("sender goroutine started")
	for {
		select {
		case <-ctx.Done():
			slog.Debug("sender: context cancelled")
			return
		case resp := <-c.sndQ:
			payload := resp.Serialize()
			slog.Info("sender: writing response",
				"type", fmt.Sprintf("0x%02x", resp.Type),
				"payload_len", len(payload),
				"payload_hex", hex.EncodeToString(payload),
			)
			c.conn.SetWriteDeadline(common.WriteDeadline())
			if err := common.WriteBlock(c.conn, payload); err != nil {
				slog.Debug("sender: write block failed", "err", err)
				return
			}
		}
	}
}

// dispatch routes a command to the appropriate handler
func (s *Server) dispatch(c *Client, cmd common.Command) common.Response {
	s.metrics.CommandsProcessed.Add(1)
	switch cmd.Type {
	case common.CmdPING:
		return common.Response{
			Type:          common.CmdPONG,
			CorrelationID: cmd.CorrelationID,
		}
	case common.CmdNEW:
		return s.handleNEW(c, cmd)
	case common.CmdSUB:
		return s.handleSUB(c, cmd)
	case common.CmdKEY:
		return s.handleKEY(c, cmd)
	case common.CmdSEND:
		return s.handleSEND(c, cmd)
	case common.CmdACK:
		return s.handleACK(c, cmd)
	default:
		// TODO: implement all command handlers
		return common.Response{
			Type:          common.CmdERR,
			CorrelationID: cmd.CorrelationID,
			ErrorCode:     common.ErrInternal,
		}
	}
}

// handleNEW creates a new queue and returns IDS with recipientID, senderID,
// and server DH public key. Implicitly subscribes the creating connection.
//
// NEW body (after "NEW " tag):
//
//	recipientAuthPublicKey = shortString(SPKI DER Ed25519)
//	recipientDhPublicKey   = shortString(SPKI DER X25519)
//	basicAuth              = "0" (no auth) or "1" + shortString(password)  [v9+]
//	subscribeMode          = "S" (subscribe) or "C" (create only)
//	sndSecure              = "T" or "F"                                    [v9+]
func (s *Server) handleNEW(c *Client, cmd common.Command) common.Response {
	errResp := common.Response{
		Type:          common.CmdERR,
		CorrelationID: cmd.CorrelationID,
	}

	body := cmd.Body
	slog.Info("NEW command debug",
		"smp_version", c.smpVersion,
		"body_hex", hex.EncodeToString(body),
		"body_len", len(body),
		"has_signature", len(cmd.Signature) > 0,
		"sig_len", len(cmd.Signature),
		"corr_id_hex", hex.EncodeToString(cmd.CorrelationID[:]),
	)
	off := 0

	// recipientAuthPublicKey = shortString(SPKI DER)
	if off >= len(body) {
		errResp.ErrorCode = common.ErrInternal
		return errResp
	}
	authKeyLen := int(body[off])
	off++
	if off+authKeyLen > len(body) {
		errResp.ErrorCode = common.ErrInternal
		return errResp
	}
	authKeySPKI := body[off : off+authKeyLen]
	off += authKeyLen

	recipientKey, parseErr := smp.ParseEd25519SPKI(authKeySPKI)
	if parseErr != nil {
		slog.Debug("NEW: invalid recipient auth key SPKI", "err", parseErr)
		errResp.ErrorCode = common.ErrInternal
		return errResp
	}

	// Verify signature: for NEW, the signature is self-certifying
	// (verified against the key in the command body itself)
	if len(cmd.Signature) > 0 && len(cmd.SignedData) > 0 {
		// Build the signed data with sessionID prepended
		signedWithSession := make([]byte, 0, 1+len(c.sessionID)+len(cmd.SignedData))
		signedWithSession = append(signedWithSession, byte(len(c.sessionID)))
		signedWithSession = append(signedWithSession, c.sessionID...)
		signedWithSession = append(signedWithSession, cmd.SignedData...)
		if !ed25519.Verify(recipientKey, signedWithSession, cmd.Signature) {
			errResp.ErrorCode = common.ErrAuth
			return errResp
		}
	}

	// recipientDhPublicKey = shortString(SPKI DER X25519) - parse but we
	// use server-generated DH keys for now
	if off < len(body) {
		dhKeyLen := int(body[off])
		off++
		off += dhKeyLen // skip past it
	}

	// Fields after recipientDhPublicKey depend on protocol version:
	// v7-v8: subscribeMode only
	// v9+:   basicAuth + subscribeMode + sndSecure
	subscribeMode := byte('S')
	sndSecure := byte('T')

	if c.smpVersion >= 9 {
		// basicAuth = "0" or "1" + shortString
		if off < len(body) {
			if body[off] == '1' {
				off++ // skip '1'
				if off < len(body) {
					passLen := int(body[off])
					off++
					off += passLen // skip password
				}
			} else {
				off++ // skip '0'
			}
		}
	}

	// subscribeMode = "S" or "C" (all versions)
	if off < len(body) {
		subscribeMode = body[off]
		off++
	}

	if c.smpVersion >= 9 {
		// sndSecure = "T" or "F"
		if off < len(body) {
			sndSecure = body[off]
			off++
		}
	}

	// CreateQueue handles idempotency internally
	q, err := s.store.CreateQueue(recipientKey)
	if err != nil {
		slog.Error("create queue failed", "err", err)
		errResp.ErrorCode = common.ErrInternal
		return errResp
	}
	s.metrics.ActiveQueues.Add(1)

	// Generate server DH keypair if not already set (new queue)
	if q.ServerDHPubKey == nil {
		dhPriv, dhErr := ecdh.X25519().GenerateKey(rand.Reader)
		if dhErr != nil {
			slog.Error("generate server DH key failed", "err", dhErr)
			errResp.ErrorCode = common.ErrInternal
			return errResp
		}
		q.ServerDHPubKey = dhPriv.PublicKey().Bytes()
		q.ServerDHSecret = dhPriv.Bytes()
	}

	// Implicit subscription if subscribeMode is "S"
	if subscribeMode == 'S' {
		oldSub := s.subHub.Subscribe(q.RecipientID, c)
		c.subscriptions[q.RecipientID] = true
		if oldSub != nil && oldSub != c {
			oldSub.sndQ <- common.Response{
				Type:        common.CmdEND,
				HasEntityID: true,
				EntityID:    q.RecipientID,
			}
		}
	}

	// Build IDS response body:
	//   recipientId = shortString(24 bytes)
	//   senderId = shortString(24 bytes)
	//   srvDhPublicKey = shortString(SPKI DER X25519)
	//   sndSecure = "T" or "F"  [v9+ only]
	dhPubSPKI := smp.EncodeX25519SPKI(q.ServerDHPubKey)
	idsBody := make([]byte, 0, 1+24+1+24+1+len(dhPubSPKI)+1)
	// recipientId
	idsBody = append(idsBody, 24)
	idsBody = append(idsBody, q.RecipientID[:]...)
	// senderId
	idsBody = append(idsBody, 24)
	idsBody = append(idsBody, q.SenderID[:]...)
	// srvDhPublicKey
	idsBody = append(idsBody, byte(len(dhPubSPKI)))
	idsBody = append(idsBody, dhPubSPKI...)
	// sndSecure (v9+ only)
	if c.smpVersion >= 9 {
		idsBody = append(idsBody, sndSecure)
	}

	idsResp := common.Response{
		Type:          common.CmdIDS,
		CorrelationID: cmd.CorrelationID,
		Body:          idsBody,
	}

	// Debug: log the complete serialized transmission bytes
	serialized := idsResp.Serialize()
	slog.Info("IDS response debug",
		"ids_body_hex", hex.EncodeToString(idsBody),
		"ids_body_len", len(idsBody),
		"serialized_hex", hex.EncodeToString(serialized),
		"serialized_len", len(serialized),
		"corr_id_hex", hex.EncodeToString(cmd.CorrelationID[:]),
		"recipient_id_hex", hex.EncodeToString(q.RecipientID[:]),
		"sender_id_hex", hex.EncodeToString(q.SenderID[:]),
		"dh_spki_len", len(dhPubSPKI),
		"dh_spki_hex", hex.EncodeToString(dhPubSPKI),
		"snd_secure", string(sndSecure),
	)

	return idsResp
}

// handleSUB subscribes a connection to an existing queue.
// Verifies Ed25519 signature, enforces one-subscriber-per-queue,
// and delivers a pending message if available.
func (s *Server) handleSUB(c *Client, cmd common.Command) common.Response {
	errResp := common.Response{
		Type:          common.CmdERR,
		CorrelationID: cmd.CorrelationID,
	}

	if !cmd.HasEntityID {
		errResp.ErrorCode = common.ErrNoQueue
		return errResp
	}

	// Look up queue by recipientID (entityID)
	q, err := s.store.GetQueue(cmd.EntityID)
	if err != nil {
		errResp.ErrorCode = common.ErrNoQueue
		return errResp
	}

	// Verify Ed25519 signature against queue's recipientKey.
	// signedData on wire = corrId + entityId + command
	// For verification: prepend shortString(sessionID)
	if len(cmd.Signature) == 0 || len(cmd.SignedData) == 0 {
		s.metrics.AddSecurityEvent("auth_failure", "SUB missing signature")
		errResp.ErrorCode = common.ErrAuth
		return errResp
	}

	signedWithSession := prependSessionID(c.sessionID, cmd.SignedData)
	if !ed25519.Verify(q.RecipientKey, signedWithSession, cmd.Signature) {
		s.metrics.AddSecurityEvent("auth_failure", "SUB invalid signature")
		errResp.ErrorCode = common.ErrAuth
		return errResp
	}

	// Same connection already subscribed - no-op, return OK
	currentSub := s.subHub.GetSubscriber(q.RecipientID)
	if currentSub == c {
		// Still check for pending message
		msg, msgErr := s.store.PopMessage(q.RecipientID)
		if msgErr == nil && msg != nil {
			return common.Response{
				Type:          common.CmdMSG,
				CorrelationID: cmd.CorrelationID,
				HasEntityID:   true,
				EntityID:      q.RecipientID,
				MessageID:     msg.ID,
				Timestamp:     msg.Timestamp,
				Flags:         msg.Flags,
				Body:          msg.Body,
			}
		}
		return common.Response{
			Type:          common.CmdOK,
			CorrelationID: cmd.CorrelationID,
		}
	}

	// Subscribe (atomically swaps old subscriber)
	oldSub := s.subHub.Subscribe(q.RecipientID, c)
	c.subscriptions[q.RecipientID] = true
	if oldSub != nil && oldSub != c {
		s.metrics.AddSecurityEvent("subscription_takeover", "queue subscription transferred")
		// Send END to displaced subscriber
		oldSub.sndQ <- common.Response{
			Type:        common.CmdEND,
			HasEntityID: true,
			EntityID:    q.RecipientID,
		}
	}

	// Check for pending message
	msg, msgErr := s.store.PopMessage(q.RecipientID)
	if msgErr == nil && msg != nil {
		return common.Response{
			Type:          common.CmdMSG,
			CorrelationID: cmd.CorrelationID,
			HasEntityID:   true,
			EntityID:      q.RecipientID,
			MessageID:     msg.ID,
			Timestamp:     msg.Timestamp,
			Flags:         msg.Flags,
			Body:          msg.Body,
		}
	}

	return common.Response{
		Type:          common.CmdOK,
		CorrelationID: cmd.CorrelationID,
	}
}

// handleKEY sets the sender's public key on a queue (one-time operation).
// The command uses senderID as entityID.
func (s *Server) handleKEY(c *Client, cmd common.Command) common.Response {
	errResp := common.Response{
		Type:          common.CmdERR,
		CorrelationID: cmd.CorrelationID,
	}

	if !cmd.HasEntityID {
		errResp.ErrorCode = common.ErrNoQueue
		return errResp
	}

	// Body: shortString(SPKI DER Ed25519 sender key)
	if len(cmd.Body) < 1 {
		errResp.ErrorCode = common.ErrInternal
		return errResp
	}
	keyLen := int(cmd.Body[0])
	if 1+keyLen > len(cmd.Body) {
		errResp.ErrorCode = common.ErrInternal
		return errResp
	}
	keySPKI := cmd.Body[1 : 1+keyLen]

	senderKey, parseErr := smp.ParseEd25519SPKI(keySPKI)
	if parseErr != nil {
		// Fallback: try raw 32-byte key for backward compatibility with tests
		if len(cmd.Body) >= ed25519.PublicKeySize {
			senderKey = make(ed25519.PublicKey, ed25519.PublicKeySize)
			copy(senderKey, cmd.Body[:ed25519.PublicKeySize])
		} else {
			errResp.ErrorCode = common.ErrInternal
			return errResp
		}
	}

	err := s.store.SetSenderKey(cmd.EntityID, senderKey)
	if err != nil {
		if err == queue.ErrKeyAlreadySet {
			errResp.ErrorCode = common.ErrAuth
			return errResp
		}
		if err == queue.ErrNoQueue {
			errResp.ErrorCode = common.ErrNoQueue
			return errResp
		}
		slog.Error("set sender key failed", "err", err)
		errResp.ErrorCode = common.ErrInternal
		return errResp
	}

	return common.Response{
		Type:          common.CmdOK,
		CorrelationID: cmd.CorrelationID,
	}
}

// handleSEND stores a message and delivers it if the recipient is subscribed.
// The command uses senderID as entityID.
func (s *Server) handleSEND(c *Client, cmd common.Command) common.Response {
	errResp := common.Response{
		Type:          common.CmdERR,
		CorrelationID: cmd.CorrelationID,
	}

	if !cmd.HasEntityID {
		errResp.ErrorCode = common.ErrNoQueue
		return errResp
	}

	// Look up queue by senderID
	q, err := s.store.GetQueueBySenderID(cmd.EntityID)
	if err != nil {
		errResp.ErrorCode = common.ErrNoQueue
		return errResp
	}

	// Verify sender key is set
	if q.SenderKey == nil {
		errResp.ErrorCode = common.ErrNoKey
		return errResp
	}

	// Verify Ed25519 signature (with sessionID prepended for verification)
	if len(cmd.Signature) == 0 || len(cmd.SignedData) == 0 {
		s.metrics.AddSecurityEvent("auth_failure", "SEND missing signature")
		errResp.ErrorCode = common.ErrAuth
		return errResp
	}

	signedWithSession := prependSessionID(c.sessionID, cmd.SignedData)
	if !ed25519.Verify(q.SenderKey, signedWithSession, cmd.Signature) {
		s.metrics.AddSecurityEvent("auth_failure", "SEND invalid signature")
		errResp.ErrorCode = common.ErrAuth
		return errResp
	}

	// Store message (body is the encrypted message content)
	msg, err := s.store.PushMessage(cmd.EntityID, 0, cmd.Body)
	if err != nil {
		slog.Error("push message failed", "err", err)
		errResp.ErrorCode = common.ErrInternal
		return errResp
	}
	s.metrics.MessagesSent.Add(1)

	okResp := common.Response{
		Type:          common.CmdOK,
		CorrelationID: cmd.CorrelationID,
	}

	// Only deliver MSG immediately if this message is at the head of the queue
	// (no other unACKed messages ahead of it). Otherwise, it will be delivered
	// when the current in-flight message is ACKed.
	sub := s.subHub.GetSubscriber(q.RecipientID)
	if sub != nil {
		headMsg, peekErr := s.store.PopMessage(q.RecipientID)
		if peekErr == nil && headMsg.ID == msg.ID {
			s.metrics.MessagesReceived.Add(1)
			okResp.Deliveries = []common.Delivery{{
				Target: sub.sndQ,
				Resp: common.Response{
					Type:        common.CmdMSG,
					HasEntityID: true,
					EntityID:    q.RecipientID,
					MessageID:   msg.ID,
					Timestamp:   msg.Timestamp,
					Flags:       msg.Flags,
					Body:        msg.Body,
				},
			}}
		}
	}

	return okResp
}

// handleACK acknowledges a message, deletes it, and delivers the next if available.
// The command uses recipientID as entityID.
func (s *Server) handleACK(c *Client, cmd common.Command) common.Response {
	errResp := common.Response{
		Type:          common.CmdERR,
		CorrelationID: cmd.CorrelationID,
	}

	if !cmd.HasEntityID {
		errResp.ErrorCode = common.ErrNoQueue
		return errResp
	}

	// Body: shortString(msgID) - 1 byte len + 24 bytes
	var msgID [24]byte
	if len(cmd.Body) >= 1 {
		msgIDLen := int(cmd.Body[0])
		if msgIDLen >= 24 && 1+msgIDLen <= len(cmd.Body) {
			copy(msgID[:], cmd.Body[1:1+24])
		} else if len(cmd.Body) >= 24 {
			// Fallback: raw 24-byte msgID for backward compatibility
			copy(msgID[:], cmd.Body[:24])
		}
	}

	// AckMessage is idempotent
	err := s.store.AckMessage(cmd.EntityID, msgID)
	if err != nil {
		slog.Error("ack message failed", "err", err)
		errResp.ErrorCode = common.ErrInternal
		return errResp
	}

	okResp := common.Response{
		Type:          common.CmdOK,
		CorrelationID: cmd.CorrelationID,
	}

	// Check for next pending message and deliver after OK is sent
	nextMsg, msgErr := s.store.PopMessage(cmd.EntityID)
	if msgErr == nil && nextMsg != nil {
		s.metrics.MessagesReceived.Add(1)
		okResp.Deliveries = []common.Delivery{{
			Target: c.sndQ,
			Resp: common.Response{
				Type:        common.CmdMSG,
				HasEntityID: true,
				EntityID:    cmd.EntityID,
				MessageID:   nextMsg.ID,
				Timestamp:   nextMsg.Timestamp,
				Flags:       nextMsg.Flags,
				Body:        nextMsg.Body,
			},
		}}
	}

	return okResp
}

// clientDisconnected cleans up after a client disconnects
func (s *Server) clientDisconnected(c *Client) {
	for queueID := range c.subscriptions {
		s.subHub.Unsubscribe(queueID, c)
	}
	slog.Info("client disconnected",
		"protocol", c.protocol,
		"commands", c.commandCount,
	)
}

// prependSessionID prepends shortString(sessionID) to the signed data
// for signature verification. The sessionID is NOT in the wire format (v7+)
// but IS included in the signature computation.
func prependSessionID(sessionID []byte, signedData []byte) []byte {
	result := make([]byte, 0, 1+len(sessionID)+len(signedData))
	result = append(result, byte(len(sessionID)))
	if len(sessionID) > 0 {
		result = append(result, sessionID...)
	}
	result = append(result, signedData...)
	return result
}

// shutdown gracefully stops the server
func (s *Server) shutdown() {
	slog.Info("waiting for active connections to close")
	s.clientWg.Wait()
	slog.Info("all connections closed")
	if err := s.store.Close(); err != nil {
		slog.Error("close store failed", "err", err)
	}
}
