// internal/tunnel/manager.go
package tunnel

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/orbvpn/orbx.protocol/internal/orbnet"
)

// Manager manages all VPN tunnel sessions
type Manager struct {
	sessions     map[string]*Session
	userSessions map[int][]*Session // userID -> sessions
	mu           sync.RWMutex

	orbnetClient *orbnet.Client

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// Metrics
	totalConnections   int64
	activeConnections  int64
	totalBytesSent     int64
	totalBytesReceived int64
	startTime          time.Time
}

// NewManager creates a new tunnel manager
func NewManager(ctx context.Context, orbnetClient *orbnet.Client) *Manager {
	mgrCtx, cancel := context.WithCancel(ctx)

	mgr := &Manager{
		sessions:     make(map[string]*Session),
		userSessions: make(map[int][]*Session),
		orbnetClient: orbnetClient,
		ctx:          mgrCtx,
		cancel:       cancel,
		startTime:    time.Now(),
	}

	// Start background tasks
	mgr.startCleanupRoutine()
	mgr.startMetricsReporter()

	return mgr
}

// GetOrCreateSession gets existing or creates new session
func (m *Manager) GetOrCreateSession(userID int, protocol string) (*Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check for existing active session
	if sessions, exists := m.userSessions[userID]; exists {
		for _, session := range sessions {
			if session.Protocol == protocol && !session.IsClosed() {
				return session, nil
			}
		}
	}

	// Create new session
	session := NewSession(userID, protocol)

	m.sessions[session.ID] = session
	m.userSessions[userID] = append(m.userSessions[userID], session)

	m.totalConnections++
	m.activeConnections++

	return session, nil
}

// GetSession retrieves a session by ID
func (m *Manager) GetSession(sessionID string) (*Session, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	session, exists := m.sessions[sessionID]
	if !exists {
		return nil, fmt.Errorf("session not found")
	}

	return session, nil
}

// CloseSession closes a specific session
func (m *Manager) CloseSession(sessionID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	session, exists := m.sessions[sessionID]
	if !exists {
		return fmt.Errorf("session not found")
	}

	// Close the session
	if err := session.Close(); err != nil {
		return err
	}

	// Report usage to OrbNet
	metrics := session.GetMetrics()
	metrics.DisconnectAt = time.Now()

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := m.orbnetClient.RecordUsage(ctx, metrics); err != nil {
			// Log error but don't fail
			fmt.Printf("Failed to report usage: %v\n", err)
		}
	}()

	// Update metrics
	m.activeConnections--
	m.totalBytesSent += session.BytesSent.Load()
	m.totalBytesReceived += session.BytesReceived.Load()

	// Remove from maps
	delete(m.sessions, sessionID)
	m.removeUserSession(session.UserID, sessionID)

	return nil
}

// removeUserSession removes session from user's session list
func (m *Manager) removeUserSession(userID int, sessionID string) {
	sessions := m.userSessions[userID]
	for i, s := range sessions {
		if s.ID == sessionID {
			m.userSessions[userID] = append(sessions[:i], sessions[i+1:]...)
			break
		}
	}

	if len(m.userSessions[userID]) == 0 {
		delete(m.userSessions, userID)
	}
}

// GetUserSessions returns all sessions for a user
func (m *Manager) GetUserSessions(userID int) []*Session {
	m.mu.RLock()
	defer m.mu.RUnlock()

	sessions := m.userSessions[userID]
	result := make([]*Session, len(sessions))
	copy(result, sessions)

	return result
}

// startCleanupRoutine starts background cleanup of idle sessions
func (m *Manager) startCleanupRoutine() {
	m.wg.Add(1)

	go func() {
		defer m.wg.Done()

		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()

		idleTimeout := 5 * time.Minute

		for {
			select {
			case <-m.ctx.Done():
				return
			case <-ticker.C:
				m.cleanupIdleSessions(idleTimeout)
			}
		}
	}()
}

// cleanupIdleSessions removes idle sessions
func (m *Manager) cleanupIdleSessions(timeout time.Duration) {
	m.mu.Lock()
	var toClose []string

	for id, session := range m.sessions {
		if session.IsIdle(timeout) {
			toClose = append(toClose, id)
		}
	}
	m.mu.Unlock()

	// Close idle sessions
	for _, id := range toClose {
		if err := m.CloseSession(id); err != nil {
			fmt.Printf("Failed to close idle session %s: %v\n", id, err)
		}
	}
}

// startMetricsReporter starts periodic metrics reporting
func (m *Manager) startMetricsReporter() {
	m.wg.Add(1)

	go func() {
		defer m.wg.Done()

		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-m.ctx.Done():
				return
			case <-ticker.C:
				m.reportMetrics()
			}
		}
	}()
}

// reportMetrics reports current metrics to OrbNet
func (m *Manager) reportMetrics() {
	m.mu.RLock()
	activeCount := int(m.activeConnections)
	m.mu.RUnlock()

	metrics := &orbnet.ServerMetrics{
		ActiveConnections: activeCount,
		CPUUsage:          0, // TODO: Implement CPU monitoring
		MemoryUsage:       0, // TODO: Implement memory monitoring
		LatencyMs:         0, // TODO: Implement latency monitoring
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Report to OrbNet (serverID should come from config)
	if err := m.orbnetClient.Heartbeat(ctx, 1, metrics); err != nil {
		fmt.Printf("Failed to send heartbeat: %v\n", err)
	}
}

// GetMetrics returns current manager metrics
func (m *Manager) GetMetrics() *ManagerMetrics {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return &ManagerMetrics{
		ActiveConnections:  int(m.activeConnections),
		TotalConnections:   m.totalConnections,
		TotalBytesSent:     m.totalBytesSent,
		TotalBytesReceived: m.totalBytesReceived,
		Uptime:             time.Since(m.startTime),
	}
}

// ManagerMetrics represents tunnel manager metrics
type ManagerMetrics struct {
	ActiveConnections  int
	TotalConnections   int64
	TotalBytesSent     int64
	TotalBytesReceived int64
	Uptime             time.Duration
}

// Stop gracefully stops the manager
func (m *Manager) Stop() {
	m.cancel()

	// Close all sessions
	m.mu.Lock()
	sessionIDs := make([]string, 0, len(m.sessions))
	for id := range m.sessions {
		sessionIDs = append(sessionIDs, id)
	}
	m.mu.Unlock()

	for _, id := range sessionIDs {
		m.CloseSession(id)
	}

	// Wait for background tasks
	m.wg.Wait()
}
