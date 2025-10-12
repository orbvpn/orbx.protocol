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
	"github.com/orbvpn/orbx.protocol/internal/tunnel"
	"github.com/orbvpn/orbx.protocol/internal/wireguard"
)

// Router routes requests to appropriate protocol handlers
type Router struct {
	// Disguise protocol handlers
	teamsHandler    *Handler
	shaparakHandler *Handler
	dohHandler      *Handler
	httpsHandler    *Handler
	googleHandler   *Handler

	// VPN protocol handler
	wireguardManager *wireguard.Manager // ✅ Use Manager, not Handler

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
		ctx:             ctx,
	}

	// Initialize WireGuard if enabled
	if cfg.WireGuard.Enabled {
		wgMgr, err := wireguard.NewManager(&cfg.WireGuard)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize WireGuard: %w", err)
		}

		if err := wgMgr.Start(); err != nil {
			return nil, fmt.Errorf("failed to start WireGuard: %w", err)
		}

		router.wireguardManager = wgMgr
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

// GetWireGuardHandler returns the WireGuard manager (for peer management)
func (r *Router) GetWireGuardHandler() *wireguard.Manager {
	return r.wireguardManager
}

// Close shuts down all protocol handlers
func (r *Router) Close() error {
	if r.wireguardManager != nil {
		if err := r.wireguardManager.Stop(); err != nil {
			log.Printf("Error closing WireGuard: %v", err)
		}
	}
	return nil
}
