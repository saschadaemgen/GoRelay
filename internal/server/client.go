package server

import (
	"net"
	"time"

	"github.com/saschadaemgen/GoRelay/internal/protocol/common"
)

// Protocol identifies SMP or GRP
type Protocol string

const (
	ProtocolSMP Protocol = "smp"
	ProtocolGRP Protocol = "grp"
)

// Client represents a connected client
type Client struct {
	conn          net.Conn
	protocol      Protocol
	rcvQ          chan common.Command
	sndQ          chan common.Response
	subscriptions map[[24]byte]bool
	createdAt     time.Time
	commandCount  int64
}

// NewClient creates a new client for the given connection
func NewClient(conn net.Conn, proto Protocol) *Client {
	return &Client{
		conn:          conn,
		protocol:      proto,
		rcvQ:          make(chan common.Command, 128),
		sndQ:          make(chan common.Response, 128),
		subscriptions: make(map[[24]byte]bool),
		createdAt:     time.Now(),
	}
}
