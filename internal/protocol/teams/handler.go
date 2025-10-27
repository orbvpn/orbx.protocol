// internal/protocol/teams/handler.go
package teams

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

// Protocol implements Microsoft Teams protocol mimicry with WireGuard tunneling
type Protocol struct {
	crypto *crypto.Manager
	tunnel *tunnel.Manager
}

// NewProtocol creates a new Teams protocol handler
func NewProtocol(cryptoMgr *crypto.Manager, tunnelMgr *tunnel.Manager) *Protocol {
	return &Protocol{
		crypto: cryptoMgr,
		tunnel: tunnelMgr,
	}
}

// Name returns the protocol name
func (p *Protocol) Name() string {
	return "teams"
}

// Validate checks if the request looks like Teams traffic
func (p *Protocol) Validate(r *http.Request) bool {
	// Check for Teams-like User-Agent
	ua := r.Header.Get("User-Agent")
	if !strings.Contains(ua, "Teams") && !strings.Contains(ua, "Microsoft") {
		return false
	}

	// Check for Teams-like headers
	if r.Header.Get("X-Ms-Client-Version") == "" {
		return false
	}

	return true
}

// Handle processes Teams protocol requests and tunnels WireGuard packets
func (p *Protocol) Handle(w http.ResponseWriter, r *http.Request) error {
	// Get user from context
	user, err := auth.GetUserFromContext(r.Context())
	if err != nil {
		return fmt.Errorf("user not found: %w", err)
	}

	// Parse Teams-like request containing WireGuard packet
	payload, err := p.parsePayload(r)
	if err != nil {
		return fmt.Errorf("failed to parse payload: %w", err)
	}

	// Decrypt/deobfuscate the WireGuard packet
	wgPacket, err := p.crypto.DeobfuscatePacket(payload)
	if err != nil {
		return fmt.Errorf("deobfuscation failed: %w", err)
	}

	// Forward packet to WireGuard interface via tunnel manager
	session, err := p.tunnel.GetOrCreateSession(user.UserID, string(models.ProtocolTeams))
	if err != nil {
		return fmt.Errorf("failed to get session: %w", err)
	}

	responsePacket, err := session.RouteData(wgPacket)
	if err != nil {
		return fmt.Errorf("routing failed: %w", err)
	}

	// Obfuscate response packet
	var obfuscated []byte
	if responsePacket != nil {
		obfuscated, err = p.crypto.ObfuscatePacket(responsePacket)
		if err != nil {
			return fmt.Errorf("obfuscation failed: %w", err)
		}
	} else {
		obfuscated = []byte{} // Empty response for handshake packets
	}

	// Send Teams-like response
	return p.sendResponse(w, obfuscated)
}

// parsePayload extracts WireGuard packet from Teams-like request
func (p *Protocol) parsePayload(r *http.Request) ([]byte, error) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()

	// Teams-like JSON structure
	var teamsMsg struct {
		Type      string `json:"type"`
		Content   string `json:"content"` // Base64 encoded WireGuard packet
		Timestamp int64  `json:"timestamp"`
		ClientID  string `json:"clientId"`
		Sequence  int    `json:"sequence"`
	}

	if err := json.Unmarshal(body, &teamsMsg); err != nil {
		return nil, fmt.Errorf("invalid teams message: %w", err)
	}

	// Decode base64 content (contains encrypted WireGuard packet)
	data, err := base64.StdEncoding.DecodeString(teamsMsg.Content)
	if err != nil {
		return nil, fmt.Errorf("failed to decode content: %w", err)
	}

	return data, nil
}

// sendResponse sends a Teams-like response with WireGuard packet
func (p *Protocol) sendResponse(w http.ResponseWriter, data []byte) error {
	// Create Teams-like response
	response := map[string]interface{}{
		"type":      "message",
		"content":   base64.StdEncoding.EncodeToString(data),
		"timestamp": time.Now().UnixMilli(),
		"serverId":  "teams-gateway-01",
		"status":    "delivered",
		"messageId": generateMessageID(),
	}

	jsonData, err := json.Marshal(response)
	if err != nil {
		return err
	}

	// Set authentic Teams headers
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Ms-Server-Version", "27/1.0.0.2024")
	w.Header().Set("X-Ms-Correlation-Id", generateCorrelationID())
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Ms-Request-Id", generateRequestID())
	w.Header().Set("Cache-Control", "no-store, no-cache")
	w.Header().Set("Pragma", "no-cache")

	w.WriteHeader(http.StatusOK)
	_, err = w.Write(jsonData)
	return err
}

// Helper functions for authentic Teams headers
func generateMessageID() string {
	return fmt.Sprintf("msg_%d_%s", time.Now().UnixNano(), randString(16))
}

func generateCorrelationID() string {
	return fmt.Sprintf("%d-%s", time.Now().UnixNano(), randString(16))
}

func generateRequestID() string {
	return fmt.Sprintf("req_%d_%s", time.Now().UnixNano(), randString(12))
}

func randString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[time.Now().UnixNano()%int64(len(letters))]
	}
	return string(b)
}
