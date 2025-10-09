// internal/tunnel/session.go
package tunnel

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/orbvpn/orbx.protocol/pkg/models"
)

// Session represents a VPN tunnel session
type Session struct {
	ID           string
	UserID       int
	Protocol     string
	StartTime    time.Time
	LastActivity time.Time

	BytesSent     atomic.Int64
	BytesReceived atomic.Int64

	conn   net.Conn
	mu     sync.RWMutex
	ctx    context.Context
	cancel context.CancelFunc

	closed atomic.Bool
}

// NewSession creates a new tunnel session
func NewSession(userID int, protocol string) *Session {
	ctx, cancel := context.WithCancel(context.Background())

	return &Session{
		ID:           generateSessionID(),
		UserID:       userID,
		Protocol:     protocol,
		StartTime:    time.Now(),
		LastActivity: time.Now(),
		ctx:          ctx,
		cancel:       cancel,
	}
}

// RouteData routes data through the tunnel
func (s *Session) RouteData(data []byte) ([]byte, error) {
	if s.closed.Load() {
		return nil, fmt.Errorf("session closed")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Update activity timestamp
	s.LastActivity = time.Now()

	// In production, this would route to actual VPN tunnel
	// For now, echo back (for testing)
	response := make([]byte, len(data))
	copy(response, data)

	// Update metrics
	s.BytesSent.Add(int64(len(data)))
	s.BytesReceived.Add(int64(len(response)))

	return response, nil
}

// Connect establishes the actual VPN connection
func (s *Session) Connect(targetAddr string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.conn != nil {
		return fmt.Errorf("already connected")
	}

	// Establish connection with timeout
	dialer := net.Dialer{
		Timeout: 10 * time.Second,
	}

	conn, err := dialer.DialContext(s.ctx, "tcp", targetAddr)
	if err != nil {
		return fmt.Errorf("connection failed: %w", err)
	}

	s.conn = conn
	s.LastActivity = time.Now()

	return nil
}

// Write writes data to the tunnel
func (s *Session) Write(data []byte) (int, error) {
	if s.closed.Load() {
		return 0, fmt.Errorf("session closed")
	}

	s.mu.RLock()
	conn := s.conn
	s.mu.RUnlock()

	if conn == nil {
		return 0, fmt.Errorf("not connected")
	}

	n, err := conn.Write(data)
	if err != nil {
		return n, err
	}

	s.BytesSent.Add(int64(n))
	s.LastActivity = time.Now()

	return n, nil
}

// Read reads data from the tunnel
func (s *Session) Read(buf []byte) (int, error) {
	if s.closed.Load() {
		return 0, fmt.Errorf("session closed")
	}

	s.mu.RLock()
	conn := s.conn
	s.mu.RUnlock()

	if conn == nil {
		return 0, fmt.Errorf("not connected")
	}

	n, err := conn.Read(buf)
	if err != nil {
		return n, err
	}

	s.BytesReceived.Add(int64(n))
	s.LastActivity = time.Now()

	return n, nil
}

// Close closes the session
func (s *Session) Close() error {
	if !s.closed.CompareAndSwap(false, true) {
		return nil // Already closed
	}

	s.cancel()

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.conn != nil {
		return s.conn.Close()
	}

	return nil
}

// GetMetrics returns session metrics
func (s *Session) GetMetrics() *models.UsageMetrics {
	return &models.UsageMetrics{
		UserID:    s.UserID,
		SessionID: s.ID,
		BytesSent: s.BytesSent.Load(),
		BytesRecv: s.BytesReceived.Load(),
		Duration:  time.Since(s.StartTime),
		Protocol:  s.Protocol,
	}
}

// IsIdle checks if session is idle
func (s *Session) IsIdle(timeout time.Duration) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return time.Since(s.LastActivity) > timeout
}

// IsClosed checks if session is closed
func (s *Session) IsClosed() bool {
	return s.closed.Load()
}

func generateSessionID() string {
	return fmt.Sprintf("orbx-%d-%d", time.Now().Unix(), time.Now().Nanosecond())
}
