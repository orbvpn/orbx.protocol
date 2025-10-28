package teams

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
	return "teams"
}

// Validate checks if the request should be handled by Teams protocol
func (p *Protocol) Validate(r *http.Request) bool {
	// 🔓 PERMISSIVE MODE: Accept any request with valid Bearer token
	// This allows testing and development while still requiring authentication
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") && len(auth) > 10 {
		return true
	}

	// 🔒 STRICT MODE: Validate Teams-specific characteristics
	ua := r.Header.Get("User-Agent")

	// Check for Teams user agents
	if strings.Contains(ua, "Teams/") ||
		strings.Contains(ua, "SkypeSpaces") ||
		strings.Contains(ua, "Microsoft Teams") {
		return true
	}

	// Check for Teams-specific headers
	if r.Header.Get("X-Teams-Version") != "" ||
		r.Header.Get("X-Teams-Session-Id") != "" {
		return true
	}

	return false
}

// Handle processes Teams protocol requests
func (p *Protocol) Handle(w http.ResponseWriter, r *http.Request) error {
	// Get authenticated user from context
	user, err := auth.GetUserFromContext(r.Context())
	if err != nil {
		return fmt.Errorf("user not found: %w", err)
	}

	// Parse Teams payload
	payload, err := p.parseTeamsPayload(r)
	if err != nil {
		return fmt.Errorf("failed to parse payload: %w", err)
	}

	// Deobfuscate the packet data
	data, err := p.crypto.DeobfuscatePacket(payload)
	if err != nil {
		return fmt.Errorf("deobfuscation failed: %w", err)
	}

	// Get or create tunnel session
	session, err := p.tunnel.GetOrCreateSession(user.UserID, string(models.ProtocolTeams))
	if err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}

	// Route data through VPN tunnel
	response, err := session.RouteData(data)
	if err != nil {
		return fmt.Errorf("routing failed: %w", err)
	}

	// Obfuscate response data
	obfuscated, err := p.crypto.ObfuscatePacket(response)
	if err != nil {
		return fmt.Errorf("obfuscation failed: %w", err)
	}

	// Send Teams-like response
	return p.sendTeamsResponse(w, obfuscated)
}

// TeamsMessage represents a Microsoft Teams message payload
type TeamsMessage struct {
	Type      string `json:"type"`
	Content   string `json:"content"` // Base64-encoded packet data
	Timestamp int64  `json:"timestamp"`
	ClientID  string `json:"clientId,omitempty"`
	Sequence  int    `json:"sequence,omitempty"`
}

// parseTeamsPayload extracts packet data from Teams-formatted request
func (p *Protocol) parseTeamsPayload(r *http.Request) ([]byte, error) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, fmt.Errorf("read body failed: %w", err)
	}
	defer r.Body.Close()

	// Try to parse as JSON (our Flutter client sends JSON)
	var teamsMsg TeamsMessage
	if err := json.Unmarshal(body, &teamsMsg); err != nil {
		// Not JSON, treat as raw data
		return body, nil
	}

	// Extract base64-encoded content
	if teamsMsg.Content == "" {
		return nil, fmt.Errorf("empty content in Teams message")
	}

	// Content is already base64-encoded by Flutter client
	// The crypto manager will handle decoding
	return []byte(teamsMsg.Content), nil
}

// sendTeamsResponse sends a Teams-formatted response
func (p *Protocol) sendTeamsResponse(w http.ResponseWriter, data []byte) error {
	// Create Teams-like response
	response := TeamsMessage{
		Type:      "response",
		Content:   string(data), // Already base64-encoded by crypto manager
		Timestamp: time.Now().Unix(),
	}

	// Set Teams-like headers
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Teams-Version", "1.5.00.32283")
	w.Header().Set("X-Response-Time", fmt.Sprintf("%d", time.Now().UnixMilli()))

	// Send JSON response
	w.WriteHeader(http.StatusOK)
	return json.NewEncoder(w).Encode(response)
}
