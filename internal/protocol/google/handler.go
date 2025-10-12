// internal/protocol/google/handler.go
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
	// Check for Google-like User-Agent
	ua := r.Header.Get("User-Agent")
	if !strings.Contains(ua, "Google") &&
		!strings.Contains(ua, "Drive") &&
		!strings.Contains(ua, "Meet") {
		return false
	}

	// Check for Google-specific headers
	if r.Header.Get("X-Goog-Api-Client") == "" &&
		r.Header.Get("X-Goog-AuthUser") == "" {
		return false
	}

	// Check path for Google services
	path := r.URL.Path
	if !strings.Contains(path, "/drive/") &&
		!strings.Contains(path, "/meet/") &&
		!strings.Contains(path, "/calendar/") {
		return false
	}

	return true
}

// Handle processes Google protocol requests
func (p *Protocol) Handle(w http.ResponseWriter, r *http.Request) error {
	// Get user from context
	user, err := auth.GetUserFromContext(r.Context())
	if err != nil {
		return fmt.Errorf("user not found: %w", err)
	}

	// Determine which Google service based on path
	service := p.detectService(r.URL.Path)

	// Parse Google-like request
	payload, err := p.parseGooglePayload(r, service)
	if err != nil {
		return fmt.Errorf("failed to parse payload: %w", err)
	}

	// Deobfuscate data
	data, err := p.crypto.DeobfuscatePacket(payload)
	if err != nil {
		return fmt.Errorf("deobfuscation failed: %w", err)
	}

	// Create tunnel session
	session, err := p.tunnel.GetOrCreateSession(user.UserID, string(models.ProtocolGoogle))
	if err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}

	// Route data through tunnel
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
	return p.sendGoogleResponse(w, obfuscated, service)
}

// detectService determines which Google service from the path
func (p *Protocol) detectService(path string) string {
	if strings.Contains(path, "/drive/") {
		return "drive"
	} else if strings.Contains(path, "/meet/") {
		return "meet"
	} else if strings.Contains(path, "/calendar/") {
		return "calendar"
	}
	return "unknown"
}

// parseGooglePayload extracts data from Google-like request
func (p *Protocol) parseGooglePayload(r *http.Request, service string) ([]byte, error) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()

	// Google uses JSON payloads
	var googleMsg struct {
		Kind      string `json:"kind"`
		Data      string `json:"data"` // Base64 encoded data
		Timestamp string `json:"timestamp"`
		RequestID string `json:"requestId"`
	}

	if err := json.Unmarshal(body, &googleMsg); err != nil {
		return nil, fmt.Errorf("invalid google message: %w", err)
	}

	// Decode base64 content
	return []byte(googleMsg.Data), nil
}

// sendGoogleResponse sends a Google-like response
func (p *Protocol) sendGoogleResponse(w http.ResponseWriter, data []byte, service string) error {
	// Create Google-like response
	response := map[string]interface{}{
		"kind":      fmt.Sprintf("workspace#%s", service),
		"data":      string(data), // Base64 encode in production
		"timestamp": time.Now().Format(time.RFC3339),
		"requestId": generateRequestID(),
	}

	jsonData, err := json.Marshal(response)
	if err != nil {
		return err
	}

	// Set Google-like headers
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.Header().Set("X-Goog-Api-Version", "v1")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "SAMEORIGIN")
	w.Header().Set("Cache-Control", "no-cache, no-store, max-age=0, must-revalidate")

	w.WriteHeader(http.StatusOK)
	_, err = w.Write(jsonData)
	return err
}

// generateRequestID generates a Google-like request ID
func generateRequestID() string {
	return fmt.Sprintf("req_%d_%s", time.Now().UnixNano(), randString(16))
}

func randString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[time.Now().UnixNano()%int64(len(letters))]
	}
	return string(b)
}
