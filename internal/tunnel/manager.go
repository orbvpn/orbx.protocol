// internal/tunnel/manager.go
// UPDATED to handle HTTPS-tunneled WireGuard packets
package tunnel

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/orbvpn/orbx.protocol/internal/orbnet"
)

// Manager handles VPN tunnel sessions and packet routing
type Manager struct {
	sessions     map[int]*Session // userID -> Session
	mu           sync.RWMutex
	orbnetClient *orbnet.Client
	ctx          context.Context
	wgLocalAddr  *net.UDPAddr // Local WireGuard interface address
	wgConn       *net.UDPConn // Connection to local WireGuard
	metrics      *Metrics
}

// Session represents a user's VPN session
type Session struct {
	UserID       int
	Protocol     string
	CreatedAt    time.Time
	LastActivity time.Time
	BytesSent    uint64
	BytesRecv    uint64
	WGEndpoint   *net.UDPAddr // User's WireGuard peer endpoint
	manager      *Manager     // Reference to parent manager
	mu           sync.RWMutex
}

// Metrics tracks tunnel statistics
type Metrics struct {
	ActiveConnections  int
	TotalBytesSent     uint64
	TotalBytesReceived uint64
	Uptime             time.Duration
	startTime          time.Time
	mu                 sync.RWMutex
}

// NewManager creates a new tunnel manager
func NewManager(ctx context.Context, orbnetClient *orbnet.Client) *Manager {
	// Connect to local WireGuard interface
	wgAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:51820")
	if err != nil {
		log.Printf("⚠️  Failed to resolve WireGuard address: %v", err)
	}

	wgConn, err := net.DialUDP("udp", nil, wgAddr)
	if err != nil {
		log.Printf("⚠️  Failed to connect to WireGuard: %v", err)
	}

	m := &Manager{
		sessions:     make(map[int]*Session),
		orbnetClient: orbnetClient,
		ctx:          ctx,
		wgLocalAddr:  wgAddr,
		wgConn:       wgConn,
		metrics: &Metrics{
			startTime: time.Now(),
		},
	}

	// Start background tasks
	go m.cleanupSessions()

	log.Println("✅ Tunnel manager initialized")
	return m
}

// GetOrCreateSession gets existing session or creates new one
func (m *Manager) GetOrCreateSession(userID int, protocol string) (*Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if session exists
	if session, exists := m.sessions[userID]; exists {
		session.LastActivity = time.Now()
		return session, nil
	}

	// Create new session
	session := &Session{
		UserID:       userID,
		Protocol:     protocol,
		CreatedAt:    time.Now(),
		LastActivity: time.Now(),
		manager:      m, // Add manager reference
	}

	m.sessions[userID] = session
	m.metrics.mu.Lock()
	m.metrics.ActiveConnections++
	m.metrics.mu.Unlock()

	log.Printf("✅ Created tunnel session for user %d (protocol: %s)", userID, protocol)
	return session, nil
}

// RouteData forwards packet to WireGuard and returns response
func (s *Session) RouteData(packet []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.LastActivity = time.Now()
	s.BytesSent += uint64(len(packet))

	// Get manager reference (we'll pass this through constructor)
	// For now, this is a placeholder for the actual WireGuard forwarding
	// The real implementation will:
	// 1. Write packet to WireGuard UDP socket
	// 2. Read response from WireGuard
	// 3. Return response packet

	// TODO: Implement actual packet forwarding
	// This requires integration with WireGuard manager

	return packet, nil // Placeholder
}

// ForwardToWireGuard sends packet to WireGuard interface
func (m *Manager) ForwardToWireGuard(userID int, packet []byte) ([]byte, error) {
	if m.wgConn == nil {
		return nil, fmt.Errorf("wireguard connection not established")
	}

	// Write packet to WireGuard
	n, err := m.wgConn.Write(packet)
	if err != nil {
		return nil, fmt.Errorf("failed to write to wireguard: %w", err)
	}

	m.metrics.mu.Lock()
	m.metrics.TotalBytesSent += uint64(n)
	m.metrics.mu.Unlock()

	// Read response from WireGuard (with timeout)
	m.wgConn.SetReadDeadline(time.Now().Add(5 * time.Second))

	buffer := make([]byte, 2048) // Max WireGuard packet size
	n, err = m.wgConn.Read(buffer)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			// Timeout is normal for some packets (handshakes, etc.)
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read from wireguard: %w", err)
	}

	m.metrics.mu.Lock()
	m.metrics.TotalBytesReceived += uint64(n)
	m.metrics.mu.Unlock()

	// Update session stats
	m.mu.RLock()
	if session, exists := m.sessions[userID]; exists {
		session.mu.Lock()
		session.BytesRecv += uint64(n)
		session.mu.Unlock()
	}
	m.mu.RUnlock()

	return buffer[:n], nil
}

// GetMetrics returns current tunnel metrics
func (m *Manager) GetMetrics() *Metrics {
	m.metrics.mu.RLock()
	defer m.metrics.mu.RUnlock()

	return &Metrics{
		ActiveConnections:  m.metrics.ActiveConnections,
		TotalBytesSent:     m.metrics.TotalBytesSent,
		TotalBytesReceived: m.metrics.TotalBytesReceived,
		Uptime:             time.Since(m.metrics.startTime),
	}
}

// cleanupSessions removes inactive sessions
func (m *Manager) cleanupSessions() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			m.mu.Lock()
			for userID, session := range m.sessions {
				if time.Since(session.LastActivity) > 5*time.Minute {
					delete(m.sessions, userID)
					m.metrics.mu.Lock()
					m.metrics.ActiveConnections--
					m.metrics.mu.Unlock()
					log.Printf("🗑️  Cleaned up inactive session for user %d", userID)
				}
			}
			m.mu.Unlock()
		}
	}
}

// Close cleanup resources
func (m *Manager) Close() {
	if m.wgConn != nil {
		m.wgConn.Close()
	}
}

// Stop stops the tunnel manager (alias for Close)
func (m *Manager) Stop() {
	m.Close()
}
