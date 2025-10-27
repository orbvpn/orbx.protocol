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

// Protocol implements DNS over HTTPS protocol mimicry
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

// Validate checks if the request looks like DoH traffic
func (p *Protocol) Validate(r *http.Request) bool {
	if r.Method != "GET" && r.Method != "POST" {
		return false
	}

	if r.Method == "POST" {
		ct := r.Header.Get("Content-Type")
		if ct != "application/dns-message" {
			return false
		}
	}

	if r.Method == "GET" && r.URL.Query().Get("dns") == "" {
		return false
	}

	return true
}

// Handle processes DoH protocol requests
func (p *Protocol) Handle(w http.ResponseWriter, r *http.Request) error {
	user, err := auth.GetUserFromContext(r.Context())
	if err != nil {
		return fmt.Errorf("user not found: %w", err)
	}

	payload, err := p.parsePayload(r)
	if err != nil {
		return fmt.Errorf("failed to parse payload: %w", err)
	}

	wgPacket, err := p.crypto.DeobfuscatePacket(payload)
	if err != nil {
		return fmt.Errorf("deobfuscation failed: %w", err)
	}

	session, err := p.tunnel.GetOrCreateSession(user.UserID, string(models.ProtocolDoH))
	if err != nil {
		return fmt.Errorf("failed to get session: %w", err)
	}

	responsePacket, err := session.RouteData(wgPacket)
	if err != nil {
		return fmt.Errorf("routing failed: %w", err)
	}

	var obfuscated []byte
	if responsePacket != nil {
		obfuscated, err = p.crypto.ObfuscatePacket(responsePacket)
		if err != nil {
			return fmt.Errorf("obfuscation failed: %w", err)
		}
	} else {
		obfuscated = []byte{}
	}

	return p.sendResponse(w, obfuscated)
}

func (p *Protocol) parsePayload(r *http.Request) ([]byte, error) {
	if r.Method == "GET" {
		// GET request - DNS query in URL parameter
		dnsParam := r.URL.Query().Get("dns")
		if dnsParam == "" {
			return nil, fmt.Errorf("missing dns parameter")
		}

		data, err := base64.RawURLEncoding.DecodeString(dnsParam)
		if err != nil {
			return nil, fmt.Errorf("failed to decode dns parameter: %w", err)
		}

		return data, nil
	}

	// POST request - DNS message in body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()

	return body, nil
}

func (p *Protocol) sendResponse(w http.ResponseWriter, data []byte) error {
	w.Header().Set("Content-Type", "application/dns-message")
	w.Header().Set("Cache-Control", "max-age=300")
	w.Header().Set("X-Content-Type-Options", "nosniff")

	w.WriteHeader(http.StatusOK)
	_, err := w.Write(data)
	return err
}
