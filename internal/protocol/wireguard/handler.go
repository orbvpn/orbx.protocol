package wireguard

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"

	"github.com/orbvpn/orbx.protocol/internal/network"
	"github.com/orbvpn/orbx.protocol/pkg/models"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
)

// Handler manages WireGuard connections
type Handler struct {
	config   *models.WireGuardConfig
	device   *device.Device
	tunIface *network.TunInterface
	ipPool   *network.IPPool
	router   *network.Router
	peers    map[string]*models.WireGuardPeer
	peersMu  sync.RWMutex
	ctx      context.Context
	cancel   context.CancelFunc
}

// NewHandler creates a new WireGuard handler
func NewHandler(config *models.WireGuardConfig) (*Handler, error) {
	ctx, cancel := context.WithCancel(context.Background())

	// Create IP pool
	ipPool, err := network.NewIPPool(config.IPPool)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create IP pool: %w", err)
	}

	// Create TUN interface
	tunIface, err := network.NewTunInterface(config.InterfaceName, ipPool, config.MTU)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create TUN interface: %w", err)
	}

	// Create WireGuard device
	logger := device.NewLogger(
		device.LogLevelError,
		fmt.Sprintf("[%s] ", config.InterfaceName),
	)

	wgDevice := device.NewDevice(tunIface.Device(), conn.NewDefaultBind(), logger)

	handler := &Handler{
		config:   config,
		device:   wgDevice,
		tunIface: tunIface,
		ipPool:   ipPool,
		peers:    make(map[string]*models.WireGuardPeer),
		ctx:      ctx,
		cancel:   cancel,
	}

	// Configure WireGuard device
	if err := handler.configureDevice(); err != nil {
		handler.Close()
		return nil, err
	}

	// Setup routing
	handler.router = network.NewRouter(tunIface.Name(), config.PublicInterface)
	if err := handler.router.EnableNAT(); err != nil {
		handler.Close()
		return nil, fmt.Errorf("failed to enable NAT: %w", err)
	}

	// Start device
	wgDevice.Up()

	log.Printf("WireGuard handler started on %s", tunIface.Name())

	return handler, nil
}

// configureDevice sets up the WireGuard device with initial configuration
func (h *Handler) configureDevice() error {
	config := fmt.Sprintf(`private_key=%s
listen_port=%d
`, h.config.PrivateKey, h.config.ListenPort)

	if err := h.device.IpcSet(config); err != nil {
		return fmt.Errorf("failed to configure WireGuard device: %w", err)
	}

	return nil
}

// AddPeer adds a new WireGuard peer
func (h *Handler) AddPeer(userID string, publicKey string) (net.IP, error) {
	h.peersMu.Lock()
	defer h.peersMu.Unlock()

	// Allocate IP for peer
	ip, err := h.ipPool.AllocateIP(userID)
	if err != nil {
		return nil, fmt.Errorf("failed to allocate IP: %w", err)
	}

	// Create peer configuration
	peer := &models.WireGuardPeer{
		PublicKey:           publicKey,
		AllowedIPs:          []string{fmt.Sprintf("%s/32", ip.String())},
		PersistentKeepalive: h.config.PersistentKeepalive,
	}

	// Add peer to WireGuard device
	peerConfig := fmt.Sprintf(`public_key=%s
allowed_ip=%s/32
persistent_keepalive_interval=%d
`, publicKey, ip.String(), peer.PersistentKeepalive)

	if err := h.device.IpcSet(peerConfig); err != nil {
		h.ipPool.ReleaseIP(userID)
		return nil, fmt.Errorf("failed to add peer to device: %w", err)
	}

	h.peers[userID] = peer

	log.Printf("Added WireGuard peer for user %s with IP %s", userID, ip.String())

	return ip, nil
}

// RemovePeer removes a WireGuard peer
func (h *Handler) RemovePeer(userID string) error {
	h.peersMu.Lock()
	defer h.peersMu.Unlock()

	peer, exists := h.peers[userID]
	if !exists {
		return fmt.Errorf("peer not found: %s", userID)
	}

	// Remove from WireGuard device
	peerConfig := fmt.Sprintf(`public_key=%s
remove=true
`, peer.PublicKey)

	if err := h.device.IpcSet(peerConfig); err != nil {
		return fmt.Errorf("failed to remove peer from device: %w", err)
	}

	// Release IP
	if err := h.ipPool.ReleaseIP(userID); err != nil {
		log.Printf("Warning: failed to release IP for user %s: %v", userID, err)
	}

	delete(h.peers, userID)

	log.Printf("Removed WireGuard peer for user %s", userID)

	return nil
}

// HandlePacket processes a WireGuard packet (called by protocol router)
func (h *Handler) HandlePacket(userID string, packet []byte) error {
	// WireGuard device handles packets automatically through TUN interface
	// This method is here for consistency with protocol interface
	// Actual packet handling is done by the WireGuard device
	return nil
}

// Close shuts down the WireGuard handler
func (h *Handler) Close() error {
	h.cancel()

	if h.device != nil {
		h.device.Close()
	}

	if h.router != nil {
		h.router.DisableNAT()
	}

	if h.tunIface != nil {
		h.tunIface.Close()
	}

	log.Println("WireGuard handler stopped")

	return nil
}

// Add these methods to the Handler struct in wireguard/handler.go

// GetGateway returns the VPN gateway IP
func (h *Handler) GetGateway() net.IP {
	return h.ipPool.GetGateway()
}

// GetDNS returns the DNS servers
func (h *Handler) GetDNS() []string {
	return h.config.DNS
}

// GetMTU returns the MTU
func (h *Handler) GetMTU() int {
	return h.config.MTU
}

// GetPeerStatus returns the status of a peer
func (h *Handler) GetPeerStatus(userID string) map[string]interface{} {
	h.peersMu.RLock()
	defer h.peersMu.RUnlock()

	peer, exists := h.peers[userID]
	if !exists {
		return map[string]interface{}{
			"connected": false,
		}
	}

	return map[string]interface{}{
		"connected":  true,
		"publicKey":  peer.PublicKey,
		"allowedIPs": peer.AllowedIPs,
	}
}
