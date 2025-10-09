// internal/protocol/teams/handler.go
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

// Protocol implements Microsoft Teams protocol mimicry
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

// Handle processes Teams protocol requests
func (p *Protocol) Handle(w http.ResponseWriter, r *http.Request) error {
	// Get user from context
	user, err := auth.GetUserFromContext(r.Context())
	if err != nil {
		return fmt.Errorf("user not found: %w", err) // ✓ lowercase
	}

	// Parse Teams-like request
	payload, err := p.parseTeamsPayload(r)
	if err != nil {
		return fmt.Errorf("failed to parse payload: %w", err) // ✓ lowercase
	}

	// Deobfuscate data
	data, err := p.crypto.DeobfuscatePacket(payload)
	if err != nil {
		return fmt.Errorf("deobfuscation failed: %w", err) // ✓ lowercase
	}

	// Create tunnel session if needed
	session, err := p.tunnel.GetOrCreateSession(user.UserID, models.ProtocolTeams)
	if err != nil {
		return fmt.Errorf("failed to create session: %w", err) // ✓ lowercase
	}

	// Route data through tunnel
	response, err := session.RouteData(data)
	if err != nil {
		return fmt.Errorf("routing failed: %w", err) // ✓ lowercase
	}

	// Obfuscate response
	obfuscated, err := p.crypto.ObfuscatePacket(response)
	if err != nil {
		return fmt.Errorf("obfuscation failed: %w", err) // ✓ lowercase
	}

	// Send Teams-like response
	return p.sendTeamsResponse(w, obfuscated)
}

// parseTeamsPayload extracts data from Teams-like request
func (p *Protocol) parseTeamsPayload(r *http.Request) ([]byte, error) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()

	// Teams uses JSON payloads
	var teamsMsg struct {
		Type      string `json:"type"`
		Content   string `json:"content"` // Base64 encoded data
		Timestamp int64  `json:"timestamp"`
		ClientID  string `json:"clientId"`
	}

	if err := json.Unmarshal(body, &teamsMsg); err != nil {
		return nil, fmt.Errorf("invalid teams message: %w", err) // ✓ lowercase (Teams is proper noun but in middle)
	}

	// Decode base64 content
	return []byte(teamsMsg.Content), nil
}

// sendTeamsResponse sends a Teams-like response
func (p *Protocol) sendTeamsResponse(w http.ResponseWriter, data []byte) error {
	// Create Teams-like response
	response := map[string]interface{}{
		"type":      "message",
		"content":   string(data), // Base64 encode in production
		"timestamp": time.Now().Unix(),
		"serverId":  "teams-gateway-01",
		"status":    "delivered",
	}

	jsonData, err := json.Marshal(response)
	if err != nil {
		return err
	}

	// Set Teams-like headers
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Ms-Server-Version", "27/1.0.0.2024")
	w.Header().Set("X-Ms-Correlation-Id", generateCorrelationID())
	w.Header().Set("X-Content-Type-Options", "nosniff")

	w.WriteHeader(http.StatusOK)
	_, err = w.Write(jsonData)
	return err
}

// generateCorrelationID generates a Teams-like correlation ID
func generateCorrelationID() string {
	return fmt.Sprintf("%d-%s", time.Now().UnixNano(), randString(16))
}

func randString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[time.Now().UnixNano()%int64(len(letters))]
	}
	return string(b)
}
