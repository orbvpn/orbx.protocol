package google

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
	return "google"
}

// Validate checks if the request should be handled by Google protocol
func (p *Protocol) Validate(r *http.Request) bool {
	// 🔓 PERMISSIVE MODE: Accept any request with valid Bearer token
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") && len(auth) > 10 {
		return true
	}

	// 🔒 STRICT MODE: Validate Google-specific characteristics
	ua := r.Header.Get("User-Agent")

	// Check for Google Workspace user agents
	if strings.Contains(ua, "Google") ||
		strings.Contains(ua, "Drive") ||
		strings.Contains(ua, "Docs") ||
		strings.Contains(ua, "Workspace") {
		return true
	}

	// Check for Google API client headers
	if r.Header.Get("X-Goog-Api-Client") != "" ||
		r.Header.Get("X-Goog-Request-Id") != "" {
		return true
	}

	return false
}

// Handle processes Google protocol requests
func (p *Protocol) Handle(w http.ResponseWriter, r *http.Request) error {
	// Get authenticated user
	user, err := auth.GetUserFromContext(r.Context())
	if err != nil {
		return fmt.Errorf("user not found: %w", err)
	}

	// Parse Google payload
	payload, err := p.parseGooglePayload(r)
	if err != nil {
		return fmt.Errorf("failed to parse payload: %w", err)
	}

	// Deobfuscate packet data
	data, err := p.crypto.DeobfuscatePacket(payload)
	if err != nil {
		return fmt.Errorf("deobfuscation failed: %w", err)
	}

	// Get or create tunnel session
	session, err := p.tunnel.GetOrCreateSession(user.UserID, string(models.ProtocolGoogle))
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

	// Send Google-like response
	return p.sendGoogleResponse(w, obfuscated)
}

// GooglePayload represents Google Workspace API payload
type GooglePayload struct {
	Kind      string `json:"kind"`
	Data      string `json:"data"` // Base64-encoded packet data
	Timestamp string `json:"timestamp"`
	RequestID string `json:"requestId,omitempty"`
}

// parseGooglePayload extracts packet data from Google-formatted request
func (p *Protocol) parseGooglePayload(r *http.Request) ([]byte, error) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, fmt.Errorf("read body failed: %w", err)
	}
	defer r.Body.Close()

	// Try to parse as JSON
	var googleMsg GooglePayload
	if err := json.Unmarshal(body, &googleMsg); err != nil {
		// Not JSON, treat as raw data
		return body, nil
	}

	// Extract base64-encoded data
	if googleMsg.Data == "" {
		return nil, fmt.Errorf("empty data in Google payload")
	}

	return []byte(googleMsg.Data), nil
}

// sendGoogleResponse sends a Google-formatted response
func (p *Protocol) sendGoogleResponse(w http.ResponseWriter, data []byte) error {
	response := GooglePayload{
		Kind:      "drive#file",
		Data:      string(data), // Already base64-encoded
		Timestamp: time.Now().Format(time.RFC3339),
		RequestID: fmt.Sprintf("req_%d", time.Now().UnixMilli()),
	}

	// Set Google-like headers
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Goog-Api-Version", "v3")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-cache, no-store, max-age=0, must-revalidate")

	w.WriteHeader(http.StatusOK)
	return json.NewEncoder(w).Encode(response)
}
