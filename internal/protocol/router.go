// internal/protocol/router.go
package protocol

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"github.com/orbvpn/orbx.protocol/internal/config"
	"github.com/orbvpn/orbx.protocol/internal/crypto"
	"github.com/orbvpn/orbx.protocol/internal/protocol/doh"
	"github.com/orbvpn/orbx.protocol/internal/protocol/google"
	"github.com/orbvpn/orbx.protocol/internal/protocol/https"
	"github.com/orbvpn/orbx.protocol/internal/protocol/shaparak"
	"github.com/orbvpn/orbx.protocol/internal/protocol/teams"
	"github.com/orbvpn/orbx.protocol/internal/protocol/wireguard"
	"github.com/orbvpn/orbx.protocol/internal/tunnel"
	"github.com/orbvpn/orbx.protocol/pkg/models"
)

// Router routes requests to appropriate protocol handlers
type Router struct {
	// Disguise protocol handlers
	teamsHandler    *Handler
	shaparakHandler *Handler
	dohHandler      *Handler
	httpsHandler    *Handler
	googleHandler   *Handler

	// VPN protocol handlers
	wireguardHandler *wireguard.Handler
	detector         *Detector

	ctx context.Context
}

// NewRouter creates a new protocol router
func NewRouter(cfg *config.Config, cryptoMgr *crypto.Manager, tunnelMgr *tunnel.Manager) (*Router, error) {
	ctx := context.Background()

	router := &Router{
		teamsHandler:    NewHandler(teams.NewProtocol(cryptoMgr, tunnelMgr), ctx),
		shaparakHandler: NewHandler(shaparak.NewProtocol(cryptoMgr, tunnelMgr), ctx),
		dohHandler:      NewHandler(doh.NewProtocol(cryptoMgr, tunnelMgr), ctx),
		httpsHandler:    NewHandler(https.NewProtocol(cryptoMgr, tunnelMgr), ctx),
		googleHandler:   NewHandler(google.NewProtocol(cryptoMgr, tunnelMgr), ctx),
		detector:        NewDetector(),
		ctx:             ctx,
	}

	// Initialize WireGuard handler if enabled
	if cfg.WireGuard.Enabled {
		wgHandler, err := wireguard.NewHandler(&cfg.WireGuard)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize WireGuard: %w", err)
		}
		router.wireguardHandler = wgHandler
		log.Println("✅ WireGuard protocol initialized")
	}

	return router, nil
}

// HandleTeams returns the Teams protocol handler
func (r *Router) HandleTeams() http.Handler {
	return r.teamsHandler
}

// HandleShaparak returns the Shaparak protocol handler
func (r *Router) HandleShaparak() http.Handler {
	return r.shaparakHandler
}

// HandleDoH returns the DNS over HTTPS handler
func (r *Router) HandleDoH() http.Handler {
	return r.dohHandler
}

// HandleHTTPS returns the fragmented HTTPS handler
func (r *Router) HandleHTTPS() http.Handler {
	return r.httpsHandler
}

// HandleGoogle returns the Google Workspace handler
func (r *Router) HandleGoogle() http.Handler {
	return r.googleHandler
}

// RouteVPNPacket routes a VPN packet to the appropriate handler
func (r *Router) RouteVPNPacket(userID string, packet []byte) error {
	// Detect which VPN protocol this packet belongs to
	vpnProtocol := r.detector.DetectVPNProtocol(packet)

	switch vpnProtocol {
	case models.VPNProtocolWireGuard:
		if r.wireguardHandler == nil {
			return fmt.Errorf("WireGuard handler not initialized")
		}
		return r.wireguardHandler.HandlePacket(userID, packet)

	case models.VPNProtocolOrbX:
		return fmt.Errorf("OrbX native protocol not yet implemented")

	case models.VPNProtocolVLESS:
		return fmt.Errorf("VLESS protocol not yet implemented")

	case models.VPNProtocolREALITY:
		return fmt.Errorf("REALITY protocol not yet implemented")

	case models.VPNProtocolOpenConnect:
		return fmt.Errorf("OpenConnect protocol not yet implemented")

	default:
		return fmt.Errorf("unknown VPN protocol")
	}
}

// GetWireGuardHandler returns the WireGuard handler (for peer management)
func (r *Router) GetWireGuardHandler() *wireguard.Handler {
	return r.wireguardHandler
}

// Close shuts down all protocol handlers
func (r *Router) Close() error {
	if r.wireguardHandler != nil {
		if err := r.wireguardHandler.Close(); err != nil {
			log.Printf("Error closing WireGuard handler: %v", err)
		}
	}
	return nil
}
