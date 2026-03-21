package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"

	"github.com/saschadaemgen/GoRelay/internal/config"
	"github.com/saschadaemgen/GoRelay/internal/protocol/common"
	"github.com/saschadaemgen/GoRelay/internal/queue"
)

// Server is the core GoRelay server
type Server struct {
	config          *config.Config
	store           queue.Store
	subHub          *SubscriptionHub
	connectionCount atomic.Int64
	clientWg        sync.WaitGroup
}

// New creates a new GoRelay server instance
func New(cfg *config.Config) (*Server, error) {
	store := queue.NewMemoryStore()

	return &Server{
		config: cfg,
		store:  store,
		subHub: NewSubscriptionHub(),
	}, nil
}

// Run starts both SMP and GRP listeners and blocks until context is cancelled
func (s *Server) Run(ctx context.Context) error {
	errCh := make(chan error, 2)

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
	// TODO: load real TLS certificates
	// For now, generate self-signed cert for development
	cert, err := generateDevCert()
	if err != nil {
		return fmt.Errorf("load tls cert: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"smp/1"},
	}

	listener, err := tls.Listen("tcp", s.config.SMP.Address, tlsConfig)
	if err != nil {
		return fmt.Errorf("listen smp: %w", err)
	}
	defer listener.Close()

	slog.Info("SMP listener started", "address", s.config.SMP.Address)

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

		if s.connectionCount.Load() >= int64(s.config.Limits.MaxConnections) {
			conn.Close()
			continue
		}

		s.connectionCount.Add(1)
		s.clientWg.Add(1)
		go func() {
			defer s.clientWg.Done()
			defer s.connectionCount.Add(-1)
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
		s.clientWg.Add(1)
		go func() {
			defer s.clientWg.Done()
			defer s.connectionCount.Add(-1)
			s.handleGRPConnection(ctx, conn)
		}()
	}
}

// handleSMPConnection handles a single SMP client connection
func (s *Server) handleSMPConnection(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return
	}

	// Complete TLS handshake
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return
	}

	// Verify ALPN
	state := tlsConn.ConnectionState()
	if state.NegotiatedProtocol != "smp/1" {
		return
	}

	slog.Info("SMP client connected", "connections", s.connectionCount.Load())

	client := NewClient(conn, ProtocolSMP)
	defer s.clientDisconnected(client)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(3)

	go func() { defer wg.Done(); defer cancel(); s.receiver(ctx, client) }()
	go func() { defer wg.Done(); defer cancel(); s.processor(ctx, client) }()
	go func() { defer wg.Done(); defer cancel(); s.sender(ctx, client) }()

	wg.Wait()
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
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		c.conn.SetReadDeadline(common.ReadDeadline())
		block, err := common.ReadBlock(c.conn)
		if err != nil {
			return
		}

		cmds, err := common.ParsePayload(block)
		if err != nil {
			slog.Debug("parse error", "err", err)
			continue
		}

		for _, cmd := range cmds {
			select {
			case c.rcvQ <- cmd:
			case <-ctx.Done():
				return
			}
		}
	}
}

// processor handles commands from the receive queue
func (s *Server) processor(ctx context.Context, c *Client) {
	for {
		select {
		case <-ctx.Done():
			return
		case cmd := <-c.rcvQ:
			resp := s.dispatch(c, cmd)
			select {
			case c.sndQ <- resp:
			case <-ctx.Done():
				return
			}
		}
	}
}

// sender writes responses as 16 KB blocks
func (s *Server) sender(ctx context.Context, c *Client) {
	for {
		select {
		case <-ctx.Done():
			return
		case resp := <-c.sndQ:
			c.conn.SetWriteDeadline(common.WriteDeadline())
			if err := common.WriteBlock(c.conn, resp.Serialize()); err != nil {
				return
			}
		}
	}
}

// dispatch routes a command to the appropriate handler
func (s *Server) dispatch(c *Client, cmd common.Command) common.Response {
	switch cmd.Type {
	case common.CmdPING:
		return common.Response{
			Type:          common.CmdPONG,
			CorrelationID: cmd.CorrelationID,
		}
	default:
		// TODO: implement all command handlers
		return common.Response{
			Type:          common.CmdERR,
			CorrelationID: cmd.CorrelationID,
			ErrorCode:     common.ErrInternal,
		}
	}
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

// shutdown gracefully stops the server
func (s *Server) shutdown() {
	slog.Info("waiting for active connections to close")
	s.clientWg.Wait()
	slog.Info("all connections closed")
}
