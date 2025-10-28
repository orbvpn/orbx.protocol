// internal/protocol/doh/handler.go
package doh

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"

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

func NewProtocol(cryptoMgr *crypto.Manager, tunnelMgr *tunnel.Manager) *Protocol {
	return &Protocol{
		crypto: cryptoMgr,
		tunnel: tunnelMgr,
	}
}

func (p *Protocol) Name() string {
	return "doh"
}

// Validate checks if the request should be handled by DoH protocol
func (p *Protocol) Validate(r *http.Request) bool {
	// 🔓 PERMISSIVE MODE: Accept any request with valid Bearer token
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") && len(authHeader) > 10 {
		return true
	}

	// 🔒 STRICT MODE: Validate DoH-specific characteristics
	ct := r.Header.Get("Content-Type")

	// DoH uses application/dns-message
	if ct == "application/dns-message" ||
		ct == "application/dns-json" {
		return true
	}

	// Check for dns query parameter (GET requests)
	if r.Method == "GET" && r.URL.Query().Get("dns") != "" {
		return true
	}

	return false
}

// Handle processes DoH protocol requests
func (p *Protocol) Handle(w http.ResponseWriter, r *http.Request) error {
	// Get authenticated user
	user, err := auth.GetUserFromContext(r.Context())
	if err != nil {
		return fmt.Errorf("user not found: %w", err)
	}

	// Parse DoH payload
	payload, err := p.parseDohPayload(r)
	if err != nil {
		return fmt.Errorf("failed to parse payload: %w", err)
	}

	// Deobfuscate packet data
	data, err := p.crypto.DeobfuscatePacket(payload)
	if err != nil {
		return fmt.Errorf("deobfuscation failed: %w", err)
	}

	// Get or create tunnel session
	session, err := p.tunnel.GetOrCreateSession(user.UserID, string(models.ProtocolDoH))
	if err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}

	// Route through VPN tunnel
	response, err := session.RouteData(data)
	if err != nil {
		return fmt.Errorf("routing failed: %w", err)
	}

	// Obfuscate response
	obfuscated, err := p.crypto.ObfuscatePacket(response)
	if err != nil {
		return fmt.Errorf("obfuscation failed: %w", err)
	}

	// Send DoH-like response
	return p.sendDohResponse(w, obfuscated)
}

// parseDohPayload extracts packet data from DoH request
func (p *Protocol) parseDohPayload(r *http.Request) ([]byte, error) {
	// GET request with dns query parameter
	if r.Method == "GET" {
		dnsParam := r.URL.Query().Get("dns")
		if dnsParam == "" {
			return nil, fmt.Errorf("missing dns query parameter")
		}

		// Decode base64url-encoded DNS message
		decoded, err := base64.RawURLEncoding.DecodeString(dnsParam)
		if err != nil {
			return nil, fmt.Errorf("invalid base64url encoding: %w", err)
		}

		return decoded, nil
	}

	// POST request with binary DNS message in body
	if r.Method == "POST" {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			return nil, fmt.Errorf("read body failed: %w", err)
		}
		defer r.Body.Close()

		return body, nil
	}

	return nil, fmt.Errorf("unsupported method: %s", r.Method)
}

// sendDohResponse sends a DoH-formatted response
func (p *Protocol) sendDohResponse(w http.ResponseWriter, data []byte) error {
	// Set DoH-specific headers
	w.Header().Set("Content-Type", "application/dns-message")
	w.Header().Set("Cache-Control", "max-age=0")

	w.WriteHeader(http.StatusOK)
	_, err := w.Write(data)
	return err
}
