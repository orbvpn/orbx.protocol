// internal/tunnel/http_tunnel.go
package tunnel

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"time"
)

// HTTPTunnel represents an HTTP tunnel for WireGuard traffic
type HTTPTunnel struct {
	UserID    int
	Protocol  string // "shaparak", "teams", "https", etc.
	conn      net.Conn
	wgConn    net.Conn // Connection to local WireGuard interface
	ctx       context.Context
	cancel    context.CancelFunc
	mu        sync.Mutex
	active    bool
	bytesIn   uint64
	bytesOut  uint64
	createdAt time.Time
}

// HTTPTunnelManager manages active HTTP tunnels
type HTTPTunnelManager struct {
	tunnels map[int]*HTTPTunnel // userID -> tunnel
	mu      sync.RWMutex
	wgAddr  string // WireGuard interface address (e.g., "127.0.0.1:51820")
}

// NewHTTPTunnelManager creates a new tunnel manager
func NewHTTPTunnelManager(wgAddr string) *HTTPTunnelManager {
	return &HTTPTunnelManager{
		tunnels: make(map[int]*HTTPTunnel),
		wgAddr:  wgAddr,
	}
}

// EstablishTunnel creates a new HTTP tunnel for a user
func (m *HTTPTunnelManager) EstablishTunnel(w http.ResponseWriter, r *http.Request, userID int, protocol string) error {
	log.Printf("🔵 Establishing HTTP tunnel for user %d with protocol: %s", userID, protocol)

	// Check if tunnel already exists
	m.mu.Lock()
	if existing, ok := m.tunnels[userID]; ok {
		log.Printf("⚠️  Closing existing tunnel for user %d", userID)
		existing.Close()
		delete(m.tunnels, userID)
	}
	m.mu.Unlock()

	// Hijack the HTTP connection to get raw TCP/TLS socket
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		return fmt.Errorf("webserver doesn't support hijacking")
	}

	conn, bufrw, err := hijacker.Hijack()
	if err != nil {
		return fmt.Errorf("failed to hijack connection: %w", err)
	}

	// Send success response before taking over connection
	response := "HTTP/1.1 200 OK\r\n" +
		"Content-Type: application/json\r\n" +
		"Connection: keep-alive\r\n" +
		"\r\n" +
		`{"status":"tunnel_established","protocol":"` + protocol + `"}` + "\r\n"

	if _, err := bufrw.WriteString(response); err != nil {
		conn.Close()
		return fmt.Errorf("failed to write response: %w", err)
	}

	if err := bufrw.Flush(); err != nil {
		conn.Close()
		return fmt.Errorf("failed to flush response: %w", err)
	}

	// Connect to local WireGuard interface
	wgConn, err := net.Dial("udp", m.wgAddr)
	if err != nil {
		conn.Close()
		return fmt.Errorf("failed to connect to WireGuard: %w", err)
	}

	// Create tunnel
	ctx, cancel := context.WithCancel(context.Background())
	tunnel := &HTTPTunnel{
		UserID:    userID,
		Protocol:  protocol,
		conn:      conn,
		wgConn:    wgConn,
		ctx:       ctx,
		cancel:    cancel,
		active:    true,
		createdAt: time.Now(),
	}

	// Register tunnel
	m.mu.Lock()
	m.tunnels[userID] = tunnel
	m.mu.Unlock()

	log.Printf("✅ HTTP tunnel established for user %d", userID)

	// Start forwarding in background
	go tunnel.Forward()

	return nil
}

// Forward handles bidirectional packet forwarding
func (t *HTTPTunnel) Forward() {
	defer t.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	// Client -> WireGuard
	go func() {
		defer wg.Done()
		t.forwardClientToWireGuard()
	}()

	// WireGuard -> Client
	go func() {
		defer wg.Done()
		t.forwardWireGuardToClient()
	}()

	wg.Wait()
	log.Printf("🔵 Tunnel closed for user %d (duration: %v)", t.UserID, time.Since(t.createdAt))
}

// forwardClientToWireGuard reads from HTTP connection and sends to WireGuard
func (t *HTTPTunnel) forwardClientToWireGuard() {
	buffer := make([]byte, 65535) // Max UDP packet size

	for {
		select {
		case <-t.ctx.Done():
			return
		default:
		}

		// Set read deadline
		t.conn.SetReadDeadline(time.Now().Add(30 * time.Second))

		// Read packet from HTTP connection
		n, err := t.conn.Read(buffer)
		if err != nil {
			if err != io.EOF {
				log.Printf("❌ Error reading from client: %v", err)
			}
			return
		}

		if n == 0 {
			continue
		}

		// Forward to WireGuard
		_, err = t.wgConn.Write(buffer[:n])
		if err != nil {
			log.Printf("❌ Error writing to WireGuard: %v", err)
			return
		}

		t.mu.Lock()
		t.bytesIn += uint64(n)
		t.mu.Unlock()
	}
}

// forwardWireGuardToClient reads from WireGuard and sends to HTTP connection
func (t *HTTPTunnel) forwardWireGuardToClient() {
	buffer := make([]byte, 65535)

	for {
		select {
		case <-t.ctx.Done():
			return
		default:
		}

		// Set read deadline
		t.wgConn.SetReadDeadline(time.Now().Add(30 * time.Second))

		// Read from WireGuard
		n, err := t.wgConn.Read(buffer)
		if err != nil {
			if err != io.EOF && !isTimeout(err) {
				log.Printf("❌ Error reading from WireGuard: %v", err)
			}
			return
		}

		if n == 0 {
			continue
		}

		// Forward to client
		_, err = t.conn.Write(buffer[:n])
		if err != nil {
			log.Printf("❌ Error writing to client: %v", err)
			return
		}

		t.mu.Lock()
		t.bytesOut += uint64(n)
		t.mu.Unlock()
	}
}

// Close closes the tunnel
func (t *HTTPTunnel) Close() {
	t.mu.Lock()
	defer t.mu.Unlock()

	if !t.active {
		return
	}

	t.active = false
	t.cancel()

	if t.conn != nil {
		t.conn.Close()
	}

	if t.wgConn != nil {
		t.wgConn.Close()
	}

	log.Printf("📊 Tunnel stats - User %d: In=%d bytes, Out=%d bytes",
		t.UserID, t.bytesIn, t.bytesOut)
}

// GetStats returns tunnel statistics
func (t *HTTPTunnel) GetStats() (bytesIn, bytesOut uint64, duration time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.bytesIn, t.bytesOut, time.Since(t.createdAt)
}

// CloseTunnel closes a specific user's tunnel
func (m *HTTPTunnelManager) CloseTunnel(userID int) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	tunnel, ok := m.tunnels[userID]
	if !ok {
		return fmt.Errorf("no tunnel found for user %d", userID)
	}

	tunnel.Close()
	delete(m.tunnels, userID)

	return nil
}

// GetActiveTunnels returns the number of active tunnels
func (m *HTTPTunnelManager) GetActiveTunnels() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.tunnels)
}

func isTimeout(err error) bool {
	if netErr, ok := err.(net.Error); ok {
		return netErr.Timeout()
	}
	return false
}
