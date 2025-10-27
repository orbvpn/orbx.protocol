// internal/protocol/https/handler.go
package https

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/orbvpn/orbx.protocol/internal/auth"
	"github.com/orbvpn/orbx.protocol/internal/crypto"
	"github.com/orbvpn/orbx.protocol/internal/tunnel"
)

// Protocol implements fragmented HTTPS protocol (fallback)
type Protocol struct {
	crypto *crypto.Manager
	tunnel *tunnel.Manager
}

// NewProtocol creates a new HTTPS protocol handler
func NewProtocol(cryptoMgr *crypto.Manager, tunnelMgr *tunnel.Manager) *Protocol {
	return &Protocol{
		crypto: cryptoMgr,
		tunnel: tunnelMgr,
	}
}

// Name returns the protocol name
func (p *Protocol) Name() string {
	return "https"
}

// Validate checks if the request looks like HTTPS traffic (always true - fallback)
func (p *Protocol) Validate(r *http.Request) bool {
	return true // Fallback handler accepts everything
}

// Handle processes HTTPS protocol requests
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

	session, err := p.tunnel.GetOrCreateSession(user.UserID, "https")
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
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()

	var msg struct {
		Data string `json:"data"`
	}

	if err := json.Unmarshal(body, &msg); err != nil {
		return nil, fmt.Errorf("invalid https message: %w", err)
	}

	data, err := base64.StdEncoding.DecodeString(msg.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to decode data: %w", err)
	}

	return data, nil
}

func (p *Protocol) sendResponse(w http.ResponseWriter, data []byte) error {
	response := map[string]interface{}{
		"status": "ok",
		"data":   base64.StdEncoding.EncodeToString(data),
	}

	jsonData, err := json.Marshal(response)
	if err != nil {
		return err
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-cache")

	w.WriteHeader(http.StatusOK)
	_, err = w.Write(jsonData)
	return err
}
