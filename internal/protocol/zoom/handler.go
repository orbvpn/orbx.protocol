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

// Validate checks if the request should be handled by Zoom protocol
func (p *Protocol) Validate(r *http.Request) bool {
	// 🔓 PERMISSIVE MODE: Accept any request with valid Bearer token
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") && len(authHeader) > 10 {
		return true
	}

	// 🔒 STRICT MODE: Validate Zoom-specific characteristics
	ua := r.Header.Get("User-Agent")

	// Check for Zoom user agents
	if strings.Contains(ua, "Zoom") ||
		strings.Contains(ua, "ZoomClient") ||
		strings.Contains(ua, "us.zoom.videomeetings") {
		return true
	}

	// Check for Zoom-specific headers
	if r.Header.Get("X-Zoom-Client") != "" ||
		r.Header.Get("X-Zm-Trackingid") != "" {
		return true
	}

	return false
}

// Handle processes Zoom protocol requests
func (p *Protocol) Handle(w http.ResponseWriter, r *http.Request) error {
	// Get authenticated user
	user, err := auth.GetUserFromContext(r.Context())
	if err != nil {
		return fmt.Errorf("user not found: %w", err)
	}

	// Parse Zoom payload
	payload, err := p.parseZoomPayload(r)
	if err != nil {
		return fmt.Errorf("failed to parse payload: %w", err)
	}

	// Deobfuscate packet data
	data, err := p.crypto.DeobfuscatePacket(payload)
	if err != nil {
		return fmt.Errorf("deobfuscation failed: %w", err)
	}

	// Get or create tunnel session
	session, err := p.tunnel.GetOrCreateSession(user.UserID, string(models.ProtocolZoom))
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

	// Send Zoom-like response
	return p.sendZoomResponse(w, obfuscated)
}

// ZoomMessage represents a Zoom API message payload
type ZoomMessage struct {
	Type      string `json:"type"`
	MeetingID string `json:"meeting_id,omitempty"`
	Data      string `json:"data"` // Base64-encoded packet data
	Timestamp int64  `json:"timestamp"`
	UserID    string `json:"user_id,omitempty"`
}

// parseZoomPayload extracts packet data from Zoom-formatted request
func (p *Protocol) parseZoomPayload(r *http.Request) ([]byte, error) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, fmt.Errorf("read body failed: %w", err)
	}
	defer r.Body.Close()

	// Try to parse as JSON
	var zoomMsg ZoomMessage
	if err := json.Unmarshal(body, &zoomMsg); err != nil {
		// Not JSON, treat as raw data
		return body, nil
	}

	// Extract base64-encoded data
	if zoomMsg.Data == "" {
		return nil, fmt.Errorf("empty data in Zoom message")
	}

	return []byte(zoomMsg.Data), nil
}

// sendZoomResponse sends a Zoom-formatted response
func (p *Protocol) sendZoomResponse(w http.ResponseWriter, data []byte) error {
	response := ZoomMessage{
		Type:      "response",
		Data:      string(data), // Already base64-encoded
		Timestamp: time.Now().Unix(),
	}

	// Set Zoom-like headers
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Zoom-Api-Version", "2.0")
	w.Header().Set("X-Response-Time", fmt.Sprintf("%d", time.Now().UnixMilli()))

	w.WriteHeader(http.StatusOK)
	return json.NewEncoder(w).Encode(response)
}
