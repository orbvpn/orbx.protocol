// internal/protocol/router.go
package protocol

import (
	"context"
	"net/http"

	"github.com/orbvpn/orbx.protocol/internal/config"
	"github.com/orbvpn/orbx.protocol/internal/crypto"
	"github.com/orbvpn/orbx.protocol/internal/protocol/doh"
	"github.com/orbvpn/orbx.protocol/internal/protocol/https"
	"github.com/orbvpn/orbx.protocol/internal/protocol/shaparak"
	"github.com/orbvpn/orbx.protocol/internal/protocol/teams"
	"github.com/orbvpn/orbx.protocol/internal/tunnel"
)

// Router routes requests to appropriate protocol handlers
type Router struct {
	teamsHandler    *Handler
	shaparakHandler *Handler
	dohHandler      *Handler
	httpsHandler    *Handler

	ctx context.Context
}

// NewRouter creates a new protocol router
func NewRouter(cfg *config.Config, cryptoMgr *crypto.Manager, tunnelMgr *tunnel.Manager) *Router {
	ctx := context.Background()

	return &Router{
		teamsHandler:    NewHandler(teams.NewProtocol(cryptoMgr, tunnelMgr), ctx),
		shaparakHandler: NewHandler(shaparak.NewProtocol(cryptoMgr, tunnelMgr), ctx),
		dohHandler:      NewHandler(doh.NewProtocol(cryptoMgr, tunnelMgr), ctx),
		httpsHandler:    NewHandler(https.NewProtocol(cryptoMgr, tunnelMgr), ctx),
		ctx:             ctx,
	}
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
