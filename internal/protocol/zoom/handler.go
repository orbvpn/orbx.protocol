package zoom

import (
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
	return "zoom"
}

func (p *Protocol) Validate(r *http.Request) bool {
	ua := r.Header.Get("User-Agent")

	// Zoom uses specific user agents
	if !strings.Contains(ua, "zoom") && !strings.Contains(ua, "ZoomClient") {
		return false
	}

	// Zoom-specific headers
	if r.Header.Get("X-Zoom-STYPE") == "" && r.Header.Get("X-Zoom-Token") == "" {
		return false
	}

	return true
}

func (p *Protocol) Handle(w http.ResponseWriter, r *http.Request) error {
	user, err := auth.GetUserFromContext(r.Context())
	if err != nil {
		return fmt.Errorf("user not found: %w", err)
	}

	payload, err := p.parseZoomPayload(r)
	if err != nil {
		return fmt.Errorf("failed to parse payload: %w", err)
	}

	data, err := p.crypto.DeobfuscatePacket(payload)
	if err != nil {
		return fmt.Errorf("deobfuscation failed: %w", err)
	}

	session, err := p.tunnel.GetOrCreateSession(user.UserID, string(models.ProtocolZoom))
	if err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}

	response, err := session.RouteData(data)
	if err != nil {
		return fmt.Errorf("routing failed: %w", err)
	}

	obfuscated, err := p.crypto.ObfuscatePacket(response)
	if err != nil {
		return fmt.Errorf("obfuscation failed: %w", err)
	}

	return p.sendZoomResponse(w, obfuscated)
}

func (p *Protocol) parseZoomPayload(r *http.Request) ([]byte, error) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()

	var zoomMsg struct {
		Type      string `json:"type"`    // "media", "control", "data"
		Payload   string `json:"payload"` // Base64 encoded
		SessionID string `json:"sessionId"`
		Timestamp int64  `json:"ts"`
	}

	if err := json.Unmarshal(body, &zoomMsg); err != nil {
		return nil, fmt.Errorf("invalid zoom message: %w", err)
	}

	return []byte(zoomMsg.Payload), nil
}

func (p *Protocol) sendZoomResponse(w http.ResponseWriter, data []byte) error {
	response := map[string]interface{}{
		"type":      "data",
		"payload":   string(data),
		"sessionId": generateSessionID(),
		"ts":        time.Now().Unix(),
		"server":    "zoom-media-gateway",
	}

	jsonData, err := json.Marshal(response)
	if err != nil {
		return err
	}

	// Zoom-specific headers
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Zoom-STYPE", "video")
	w.Header().Set("X-Zoom-Server-Version", "5.17.0.21860")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")

	w.WriteHeader(http.StatusOK)
	_, err = w.Write(jsonData)
	return err
}

func generateSessionID() string {
	return fmt.Sprintf("zmg-%d", time.Now().UnixNano())
}
