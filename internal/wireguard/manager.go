// internal/wireguard/manager.go
package wireguard

import (
	"fmt"
	"log"
	"net"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/orbvpn/orbx.protocol/internal/config"
	"github.com/orbvpn/orbx.protocol/internal/network" // ✅ Use your existing IPPool
)

type Peer struct {
	UserUUID      string    `json:"userUuid"`
	PublicKey     string    `json:"publicKey"`
	AllowedIPs    string    `json:"allowedIPs"`
	AllocatedIP   net.IP    `json:"allocatedIP"`
	AddedAt       time.Time `json:"addedAt"`
	LastHandshake time.Time `json:"lastHandshake,omitempty"`
	BytesRx       int64     `json:"bytesRx"`
	BytesTx       int64     `json:"bytesTx"`
}

type Manager struct {
	config     *config.WireGuardConfig
	peers      map[string]*Peer // key: userUuid
	peersByKey map[string]*Peer // key: publicKey
	mu         sync.RWMutex
	privateKey string
	publicKey  string
	running    bool
	ipPool     *network.IPPool // ✅ Use your IPPool
	dns        []string
}

func NewManager(cfg *config.WireGuardConfig) (*Manager, error) {
	// Generate server keys if not provided
	privateKey := cfg.PrivateKey
	publicKey := cfg.PublicKey

	if privateKey == "" {
		var err error
		privateKey, publicKey, err = GenerateKeyPair() // ✅ Your function works perfectly
		if err != nil {
			return nil, fmt.Errorf("failed to generate keys: %w", err)
		}
		log.Printf("🔑 Generated WireGuard keys")
	}

	// Create IP pool using your network package
	ipPool, err := network.NewIPPool(cfg.Address) // ✅ Your IPPool API
	if err != nil {
		return nil, fmt.Errorf("failed to create IP pool: %w", err)
	}

	return &Manager{
		config:     cfg,
		peers:      make(map[string]*Peer),
		peersByKey: make(map[string]*Peer),
		privateKey: privateKey,
		publicKey:  publicKey,
		ipPool:     ipPool,
		dns:        []string{"1.1.1.1", "1.0.0.1"},
	}, nil
}

func (m *Manager) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.running {
		return fmt.Errorf("WireGuard is already running")
	}

	// Create WireGuard interface
	if err := m.createInterface(); err != nil {
		return fmt.Errorf("failed to create interface: %w", err)
	}

	// Configure interface
	if err := m.configureInterface(); err != nil {
		return fmt.Errorf("failed to configure interface: %w", err)
	}

	// Enable IP forwarding
	if err := m.enableIPForwarding(); err != nil {
		return fmt.Errorf("failed to enable IP forwarding: %w", err)
	}

	// Setup NAT
	if err := m.setupNAT(); err != nil {
		return fmt.Errorf("failed to setup NAT: %w", err)
	}

	m.running = true
	log.Printf("✅ WireGuard interface %s started (listen port: %d)",
		m.config.Interface, m.config.ListenPort)
	log.Printf("📡 Public key: %s", m.publicKey)

	return nil
}

func (m *Manager) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.running {
		return nil
	}

	// Remove NAT rules
	m.removeNAT()

	// Remove interface
	cmd := exec.Command("ip", "link", "delete", m.config.Interface)
	if err := cmd.Run(); err != nil {
		log.Printf("Warning: failed to delete interface: %v", err)
	}

	m.running = false
	log.Printf("🛑 WireGuard interface stopped")

	return nil
}

func (m *Manager) createInterface() error {
	iface := m.config.Interface

	// Remove existing interface if it exists
	exec.Command("ip", "link", "delete", iface).Run()

	// Create WireGuard interface
	cmd := exec.Command("ip", "link", "add", iface, "type", "wireguard")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to create interface: %w", err)
	}

	// Set interface address
	cmd = exec.Command("ip", "address", "add", m.config.Address, "dev", iface)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to set address: %w", err)
	}

	// Set MTU
	cmd = exec.Command("ip", "link", "set", "mtu", fmt.Sprintf("%d", m.config.MTU), "dev", iface)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to set MTU: %w", err)
	}

	// Bring interface up
	cmd = exec.Command("ip", "link", "set", "up", "dev", iface)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to bring interface up: %w", err)
	}

	return nil
}

func (m *Manager) configureInterface() error {
	iface := m.config.Interface

	// Set private key
	cmd := exec.Command("wg", "set", iface, "private-key", "/dev/stdin")
	cmd.Stdin = strings.NewReader(m.privateKey)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to set private key: %w", err)
	}

	// Set listen port
	cmd = exec.Command("wg", "set", iface,
		"listen-port", fmt.Sprintf("%d", m.config.ListenPort))
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to set listen port: %w", err)
	}

	return nil
}

func (m *Manager) enableIPForwarding() error {
	cmd := exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1")
	return cmd.Run()
}

func (m *Manager) setupNAT() error {
	// Get default interface
	cmd := exec.Command("ip", "route", "show", "default")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to get default route: %w", err)
	}

	fields := strings.Fields(string(output))
	if len(fields) < 5 {
		return fmt.Errorf("unexpected route output")
	}
	defaultIface := fields[4]

	// Setup NAT using iptables
	cmd = exec.Command("iptables", "-t", "nat", "-A", "POSTROUTING",
		"-o", defaultIface, "-j", "MASQUERADE")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to setup NAT: %w", err)
	}

	// Allow forwarding from WireGuard interface
	cmd = exec.Command("iptables", "-A", "FORWARD",
		"-i", m.config.Interface, "-j", "ACCEPT")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to setup forwarding: %w", err)
	}

	cmd = exec.Command("iptables", "-A", "FORWARD",
		"-o", m.config.Interface, "-j", "ACCEPT")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to setup forwarding: %w", err)
	}

	return nil
}

func (m *Manager) removeNAT() {
	// Get default interface
	cmd := exec.Command("ip", "route", "show", "default")
	output, _ := cmd.Output()
	fields := strings.Fields(string(output))
	if len(fields) >= 5 {
		defaultIface := fields[4]
		exec.Command("iptables", "-t", "nat", "-D", "POSTROUTING",
			"-o", defaultIface, "-j", "MASQUERADE").Run()
	}

	exec.Command("iptables", "-D", "FORWARD",
		"-i", m.config.Interface, "-j", "ACCEPT").Run()
	exec.Command("iptables", "-D", "FORWARD",
		"-o", m.config.Interface, "-j", "ACCEPT").Run()
}

func (m *Manager) AddPeer(userUUID, publicKey string) (net.IP, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if peer already exists
	if peer, exists := m.peers[userUUID]; exists {
		log.Printf("Peer %s already exists, returning existing IP: %s", userUUID, peer.AllocatedIP)
		return peer.AllocatedIP, nil
	}

	// ✅ Use your IPPool API - it tracks by userID automatically!
	ip, err := m.ipPool.AllocateIP(userUUID)
	if err != nil {
		return nil, fmt.Errorf("failed to allocate IP: %w", err)
	}

	allowedIPs := fmt.Sprintf("%s/32", ip.String())

	// Add peer to WireGuard
	cmd := exec.Command("wg", "set", m.config.Interface,
		"peer", publicKey,
		"allowed-ips", allowedIPs)

	if err := cmd.Run(); err != nil {
		m.ipPool.ReleaseIP(userUUID) // ✅ Use your release API
		return nil, fmt.Errorf("failed to add peer: %w", err)
	}

	// Store peer info
	peer := &Peer{
		UserUUID:    userUUID,
		PublicKey:   publicKey,
		AllowedIPs:  allowedIPs,
		AllocatedIP: ip,
		AddedAt:     time.Now(),
	}

	m.peers[userUUID] = peer
	m.peersByKey[publicKey] = peer

	log.Printf("✅ Added peer: %s (IP: %s)", userUUID, ip)

	return ip, nil
}

func (m *Manager) RemovePeer(userUUID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	peer, exists := m.peers[userUUID]
	if !exists {
		return fmt.Errorf("peer not found: %s", userUUID)
	}

	// Remove peer from WireGuard
	cmd := exec.Command("wg", "set", m.config.Interface,
		"peer", peer.PublicKey, "remove")

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to remove peer: %w", err)
	}

	// ✅ Use your IPPool release API
	if err := m.ipPool.ReleaseIP(userUUID); err != nil {
		log.Printf("Warning: failed to release IP: %v", err)
	}

	// Remove from maps
	delete(m.peers, userUUID)
	delete(m.peersByKey, peer.PublicKey)

	log.Printf("🗑️  Removed peer: %s", userUUID)

	return nil
}

func (m *Manager) GetPeers() []*Peer {
	m.mu.RLock()
	defer m.mu.RUnlock()

	peers := make([]*Peer, 0, len(m.peers))
	for _, peer := range m.peers {
		peers = append(peers, peer)
	}

	return peers
}

func (m *Manager) GetPeerCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.peers)
}

func (m *Manager) GetPublicKey() string {
	return m.publicKey
}

func (m *Manager) GetGateway() net.IP {
	return m.ipPool.GetGateway() // ✅ Use your IPPool method
}

func (m *Manager) GetDNS() []string {
	return m.dns
}

func (m *Manager) GetMTU() int {
	return m.config.MTU
}

func (m *Manager) GetPeerStatus(userUUID string) map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	peer, exists := m.peers[userUUID]
	if !exists {
		return map[string]interface{}{
			"connected": false,
		}
	}

	return map[string]interface{}{
		"connected":      true,
		"allocatedIP":    peer.AllocatedIP.String(),
		"bytesRx":        peer.BytesRx,
		"bytesTx":        peer.BytesTx,
		"lastHandshake":  peer.LastHandshake,
		"connectedSince": peer.AddedAt,
	}
}

func (m *Manager) UpdatePeerStats() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Get WireGuard stats
	cmd := exec.Command("wg", "show", m.config.Interface, "dump")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to get stats: %w", err)
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines[1:] { // Skip header
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}

		publicKey := fields[0]
		peer, exists := m.peersByKey[publicKey]
		if !exists {
			continue
		}

		// Update stats
		fmt.Sscanf(fields[5], "%d", &peer.BytesRx)
		fmt.Sscanf(fields[6], "%d", &peer.BytesTx)

		// Parse last handshake
		if fields[4] != "0" {
			var timestamp int64
			fmt.Sscanf(fields[4], "%d", &timestamp)
			peer.LastHandshake = time.Unix(timestamp, 0)
		}
	}

	return nil
}
