package server

import (
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

// Metrics collects server-wide statistics using lock-free atomic counters.
type Metrics struct {
	startTime time.Time

	// Connections
	ActiveConnectionsSMP atomic.Int64
	ActiveConnectionsGRP atomic.Int64
	TotalConnectionsSMP  atomic.Int64
	TotalConnectionsGRP  atomic.Int64
	PeakConnections      atomic.Int64

	// Queues
	ActiveQueues atomic.Int64

	// Messages
	MessagesSent     atomic.Int64
	MessagesReceived atomic.Int64
	MessagesExpired  atomic.Int64
	MessagesDiscarded atomic.Int64 // auto-discarded by DeliveryAttempts

	// Commands
	CommandsProcessed atomic.Int64

	// Security events ring buffer
	eventsMu sync.Mutex
	events   []SecurityEvent
}

// SecurityEvent records a non-sensitive security-relevant event.
type SecurityEvent struct {
	Time    time.Time `json:"time"`
	Type    string    `json:"type"`
	Detail  string    `json:"detail"`
}

// NewMetrics creates a new metrics collector.
func NewMetrics() *Metrics {
	return &Metrics{
		startTime: time.Now(),
		events:    make([]SecurityEvent, 0, 64),
	}
}

// Uptime returns the server uptime duration.
func (m *Metrics) Uptime() time.Duration {
	return time.Since(m.startTime)
}

// UpdatePeakConnections updates the peak if the current total exceeds it.
func (m *Metrics) UpdatePeakConnections() {
	current := m.ActiveConnectionsSMP.Load() + m.ActiveConnectionsGRP.Load()
	for {
		peak := m.PeakConnections.Load()
		if current <= peak {
			return
		}
		if m.PeakConnections.CompareAndSwap(peak, current) {
			return
		}
	}
}

// AddSecurityEvent appends an event to the ring buffer (max 50).
func (m *Metrics) AddSecurityEvent(eventType, detail string) {
	m.eventsMu.Lock()
	defer m.eventsMu.Unlock()

	ev := SecurityEvent{
		Time:   time.Now(),
		Type:   eventType,
		Detail: detail,
	}
	m.events = append(m.events, ev)
	if len(m.events) > 50 {
		m.events = m.events[len(m.events)-50:]
	}
}

// SecurityEvents returns a copy of the last 50 events (newest last).
func (m *Metrics) SecurityEvents() []SecurityEvent {
	m.eventsMu.Lock()
	defer m.eventsMu.Unlock()

	out := make([]SecurityEvent, len(m.events))
	copy(out, m.events)
	return out
}

// Snapshot returns a point-in-time copy of all metrics.
func (m *Metrics) Snapshot() MetricsSnapshot {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	return MetricsSnapshot{
		UptimeSeconds:        int64(m.Uptime().Seconds()),
		ActiveConnectionsSMP: m.ActiveConnectionsSMP.Load(),
		ActiveConnectionsGRP: m.ActiveConnectionsGRP.Load(),
		ActiveConnectionsTotal: m.ActiveConnectionsSMP.Load() + m.ActiveConnectionsGRP.Load(),
		TotalConnectionsSMP:  m.TotalConnectionsSMP.Load(),
		TotalConnectionsGRP:  m.TotalConnectionsGRP.Load(),
		PeakConnections:      m.PeakConnections.Load(),
		ActiveQueues:         m.ActiveQueues.Load(),
		MessagesSent:         m.MessagesSent.Load(),
		MessagesReceived:     m.MessagesReceived.Load(),
		MessagesExpired:      m.MessagesExpired.Load(),
		MessagesDiscarded:    m.MessagesDiscarded.Load(),
		CommandsProcessed:    m.CommandsProcessed.Load(),
		MemAllocMB:           float64(memStats.Alloc) / 1024 / 1024,
		MemSysMB:             float64(memStats.Sys) / 1024 / 1024,
		NumGoroutines:        runtime.NumGoroutine(),
	}
}

// MetricsSnapshot is a JSON-serializable snapshot of server metrics.
type MetricsSnapshot struct {
	UptimeSeconds          int64   `json:"uptime_seconds"`
	ActiveConnectionsSMP   int64   `json:"active_connections_smp"`
	ActiveConnectionsGRP   int64   `json:"active_connections_grp"`
	ActiveConnectionsTotal int64   `json:"active_connections_total"`
	TotalConnectionsSMP    int64   `json:"total_connections_smp"`
	TotalConnectionsGRP    int64   `json:"total_connections_grp"`
	PeakConnections        int64   `json:"peak_connections"`
	ActiveQueues           int64   `json:"active_queues"`
	MessagesSent           int64   `json:"messages_sent"`
	MessagesReceived       int64   `json:"messages_received"`
	MessagesExpired        int64   `json:"messages_expired"`
	MessagesDiscarded      int64   `json:"messages_discarded"`
	CommandsProcessed      int64   `json:"commands_processed"`
	MemAllocMB             float64 `json:"mem_alloc_mb"`
	MemSysMB               float64 `json:"mem_sys_mb"`
	NumGoroutines          int     `json:"num_goroutines"`
}
