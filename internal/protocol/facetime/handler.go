package facetime

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
	return "facetime"
}

// Validate checks if the request should be handled by FaceTime protocol
func (p *Protocol) Validate(r *http.Request) bool {
	// 🔓 PERMISSIVE MODE: Accept any request with valid Bearer token
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") && len(authHeader) > 10 {
		return true
	}

	// 🔒 STRICT MODE: Validate FaceTime-specific characteristics
	ua := r.Header.Get("User-Agent")

	// Check for FaceTime/Apple user agents
	if strings.Contains(ua, "FaceTime") ||
		strings.Contains(ua, "AppleWebKit") ||
		strings.Contains(ua, "CFNetwork") {

		// Also check for Apple-specific headers
		if r.Header.Get("X-Apple-Device-Id") != "" ||
			r.Header.Get("X-Apple-Request-UUID") != "" {
			return true
		}
	}

	return false
}

// Handle processes FaceTime protocol requests
func (p *Protocol) Handle(w http.ResponseWriter, r *http.Request) error {
	// Get authenticated user
	user, err := auth.GetUserFromContext(r.Context())
	if err != nil {
		return fmt.Errorf("user not found: %w", err)
	}

	// Parse FaceTime payload
	payload, err := p.parseFaceTimePayload(r)
	if err != nil {
		return fmt.Errorf("failed to parse payload: %w", err)
	}

	// Deobfuscate packet data
	data, err := p.crypto.DeobfuscatePacket(payload)
	if err != nil {
		return fmt.Errorf("deobfuscation failed: %w", err)
	}

	// Get or create tunnel session
	session, err := p.tunnel.GetOrCreateSession(user.UserID, string(models.ProtocolFaceTime))
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

	// Send FaceTime-like response
	return p.sendFaceTimeResponse(w, obfuscated)
}

// FaceTimeMessage represents a FaceTime message payload
type FaceTimeMessage struct {
	Type      string `json:"type"`
	CallID    string `json:"call_id,omitempty"`
	Data      string `json:"data"` // Base64-encoded packet data
	Timestamp int64  `json:"timestamp"`
	DeviceID  string `json:"device_id,omitempty"`
}

// parseFaceTimePayload extracts packet data from FaceTime-formatted request
func (p *Protocol) parseFaceTimePayload(r *http.Request) ([]byte, error) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, fmt.Errorf("read body failed: %w", err)
	}
	defer r.Body.Close()

	// Try to parse as JSON
	var ftMsg FaceTimeMessage
	if err := json.Unmarshal(body, &ftMsg); err != nil {
		// Not JSON, treat as raw data
		return body, nil
	}

	// Extract base64-encoded data
	if ftMsg.Data == "" {
		return nil, fmt.Errorf("empty data in FaceTime message")
	}

	return []byte(ftMsg.Data), nil
}

// sendFaceTimeResponse sends a FaceTime-formatted response
func (p *Protocol) sendFaceTimeResponse(w http.ResponseWriter, data []byte) error {
	response := FaceTimeMessage{
		Type:      "response",
		Data:      string(data), // Already base64-encoded
		Timestamp: time.Now().Unix(),
	}

	// Set Apple/FaceTime-like headers
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Apple-Service", "facetime")
	w.Header().Set("Server", "Apple")

	w.WriteHeader(http.StatusOK)
	return json.NewEncoder(w).Encode(response)
}
