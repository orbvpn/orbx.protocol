// internal/protocol/protocol.go
package protocol

import (
	"context"
	"net/http"
)

// Protocol defines the interface for all OrbX protocols
type Protocol interface {
	// Name returns the protocol name
	Name() string

	// Handle processes an HTTP request for this protocol
	Handle(w http.ResponseWriter, r *http.Request) error

	// Validate checks if the request is valid for this protocol
	Validate(r *http.Request) bool
}

// Handler wraps a protocol with common functionality
type Handler struct {
	protocol Protocol
	ctx      context.Context
}

// NewHandler creates a new protocol handler
func NewHandler(protocol Protocol, ctx context.Context) *Handler {
	return &Handler{
		protocol: protocol,
		ctx:      ctx,
	}
}

// ServeHTTP implements http.Handler
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Validate request
	if !h.protocol.Validate(r) {
		http.Error(w, "Invalid request for protocol", http.StatusBadRequest)
		return
	}

	// Handle request
	if err := h.protocol.Handle(w, r); err != nil {
		http.Error(w, "Protocol error", http.StatusInternalServerError)
		return
	}
}
