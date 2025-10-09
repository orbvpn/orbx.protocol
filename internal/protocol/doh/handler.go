// internal/protocol/doh/handler.go
package doh

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"

	"github.com/orbvpn/orbx.protocol/internal/auth"
	"github.com/orbvpn/orbx.protocol/internal/crypto"
	"github.com/orbvpn/orbx.protocol/internal/tunnel"
	"github.com/orbvpn/orbx.protocol/pkg/models"
)

// Protocol implements DNS over HTTPS
type Protocol struct {
	crypto *crypto.Manager
	tunnel *tunnel.Manager
}

// NewProtocol creates a new DoH protocol handler
func NewProtocol(cryptoMgr *crypto.Manager, tunnelMgr *tunnel.Manager) *Protocol {
	return &Protocol{
		crypto: cryptoMgr,
		tunnel: tunnelMgr,
	}
}

// Name returns the protocol name
func (p *Protocol) Name() string {
	return "doh"
}

// Validate checks if the request is a valid DoH request
func (p *Protocol) Validate(r *http.Request) bool {
	// DoH uses GET or POST
	if r.Method != "GET" && r.Method != "POST" {
		return false
	}

	// Check for DoH content type
	if r.Method == "POST" {
		ct := r.Header.Get("Content-Type")
		if ct != "application/dns-message" {
			return false
		}
	}

	// GET requests must have dns parameter
	if r.Method == "GET" && r.URL.Query().Get("dns") == "" {
		return false
	}

	return true
}

// Handle processes DoH requests
func (p *Protocol) Handle(w http.ResponseWriter, r *http.Request) error {
	// Get user from context
	user, err := auth.GetUserFromContext(r.Context())
	if err != nil {
		return fmt.Errorf("user not found: %w", err)
	}

	// Parse DNS query
	dnsQuery, err := p.parseDNSQuery(r)
	if err != nil {
		return fmt.Errorf("failed to parse DNS query: %w", err)
	}

	// Deobfuscate (our VPN data is hidden in DNS query)
	data, err := p.crypto.DeobfuscatePacket(dnsQuery)
	if err != nil {
		return fmt.Errorf("deobfuscation failed: %w", err)
	}

	// Create tunnel session
	session, err := p.tunnel.GetOrCreateSession(user.UserID, models.ProtocolDoH)
	if err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}

	// Route data through tunnel
	response, err := session.RouteData(data)
	if err != nil {
		return fmt.Errorf("routing failed: %w", err)
	}

	// Obfuscate response
	obfuscated, err := p.crypto.ObfuscatePacket(response)
	if err != nil {
		return fmt.Errorf("obfuscation failed: %w", err)
	}

	// Send DoH response
	return p.sendDNSResponse(w, obfuscated)
}

// parseDNSQuery extracts data from DoH request
func (p *Protocol) parseDNSQuery(r *http.Request) ([]byte, error) {
	if r.Method == "GET" {
		// GET: dns parameter is base64url encoded
		dnsParam := r.URL.Query().Get("dns")
		return base64.RawURLEncoding.DecodeString(dnsParam)
	}

	// POST: body is the DNS message
	return io.ReadAll(r.Body)
}

// sendDNSResponse sends a DoH response
func (p *Protocol) sendDNSResponse(w http.ResponseWriter, data []byte) error {
	// Set DoH headers
	w.Header().Set("Content-Type", "application/dns-message")
	w.Header().Set("Cache-Control", "max-age=300")

	w.WriteHeader(http.StatusOK)
	_, err := w.Write(data)
	return err
}
