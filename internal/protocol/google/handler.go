// internal/protocol/google/handler.go
package google

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/orbvpn/orbx.protocol/internal/auth"
	"github.com/orbvpn/orbx.protocol/internal/crypto"
	"github.com/orbvpn/orbx.protocol/internal/tunnel"
	"github.com/orbvpn/orbx.protocol/pkg/models"
)

// Protocol implements Google Workspace protocol mimicry
type Protocol struct {
	crypto *crypto.Manager
	tunnel *tunnel.Manager
}

// NewProtocol creates a new Google protocol handler
func NewProtocol(cryptoMgr *crypto.Manager, tunnelMgr *tunnel.Manager) *Protocol {
	return &Protocol{
		crypto: cryptoMgr,
		tunnel: tunnelMgr,
	}
}

// Name returns the protocol name
func (p *Protocol) Name() string {
	return "google"
}

// Validate checks if the request looks like Google Workspace traffic
func (p *Protocol) Validate(r *http.Request) bool {
	ua := r.Header.Get("User-Agent")
	if !strings.Contains(ua, "Google") && !strings.Contains(ua, "Chrome") {
		return false
	}

	path := r.URL.Path
	if !strings.Contains(path, "/drive/") &&
		!strings.Contains(path, "/meet/") &&
		!strings.Contains(path, "/calendar/") &&
		!strings.Contains(path, "/google/") {
		return false
	}

	return true
}

// Handle processes Google protocol requests
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

	session, err := p.tunnel.GetOrCreateSession(user.UserID, string(models.ProtocolGoogle))
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
		Kind      string `json:"kind"`
		Data      string `json:"data"`
		Timestamp string `json:"timestamp"`
		RequestId string `json:"requestId"`
	}

	if err := json.Unmarshal(body, &msg); err != nil {
		return nil, fmt.Errorf("invalid google message: %w", err)
	}

	data, err := base64.StdEncoding.DecodeString(msg.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to decode data: %w", err)
	}

	return data, nil
}

func (p *Protocol) sendResponse(w http.ResponseWriter, data []byte) error {
	response := map[string]interface{}{
		"kind":      "drive#file",
		"data":      base64.StdEncoding.EncodeToString(data),
		"timestamp": time.Now().Format(time.RFC3339),
		"id":        fmt.Sprintf("file_%d", time.Now().UnixNano()),
	}

	jsonData, err := json.Marshal(response)
	if err != nil {
		return err
	}

	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.Header().Set("X-Goog-Api-Version", "v1")
	w.Header().Set("X-Frame-Options", "SAMEORIGIN")
	w.Header().Set("Cache-Control", "no-cache, no-store, max-age=0")
	w.Header().Set("X-Content-Type-Options", "nosniff")

	w.WriteHeader(http.StatusOK)
	_, err = w.Write(jsonData)
	return err
}
