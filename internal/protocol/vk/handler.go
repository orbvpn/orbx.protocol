// internal/protocol/vk/handler.go
package vk

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
	return "vk"
}

// Validate checks if the request should be handled by VK protocol
func (p *Protocol) Validate(r *http.Request) bool {
	// 🔓 PERMISSIVE MODE: Accept any request with valid Bearer token
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") && len(authHeader) > 10 {
		return true
	}

	// 🔒 STRICT MODE: Validate VK-specific characteristics
	ua := r.Header.Get("User-Agent")

	// Check for VK user agents
	if strings.Contains(ua, "VKAndroidApp") ||
		strings.Contains(ua, "VKiOSApp") ||
		strings.Contains(ua, "vk.com") {
		return true
	}

	// Check for VK-specific headers
	if r.Header.Get("X-VK-Android-Client") != "" ||
		r.Header.Get("X-VK-Client-Version") != "" ||
		r.Header.Get("X-VK-App-Id") != "" {
		return true
	}

	return false
}

// Handle processes VK protocol requests
func (p *Protocol) Handle(w http.ResponseWriter, r *http.Request) error {
	// Get authenticated user
	user, err := auth.GetUserFromContext(r.Context())
	if err != nil {
		return fmt.Errorf("user not found: %w", err)
	}

	// Parse VK payload
	payload, err := p.parseVKPayload(r)
	if err != nil {
		return fmt.Errorf("failed to parse payload: %w", err)
	}

	// Deobfuscate packet data
	data, err := p.crypto.DeobfuscatePacket(payload)
	if err != nil {
		return fmt.Errorf("deobfuscation failed: %w", err)
	}

	// Get or create tunnel session
	session, err := p.tunnel.GetOrCreateSession(user.UserID, string(models.ProtocolVK))
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

	// Send VK-like response
	return p.sendVKResponse(w, obfuscated)
}

// VKMessage represents a VK API message payload
type VKMessage struct {
	Method    string                 `json:"method"`
	Version   string                 `json:"v"`
	Data      string                 `json:"data"` // Base64-encoded packet data
	Params    map[string]interface{} `json:"params,omitempty"`
	Timestamp int64                  `json:"timestamp"`
}

// parseVKPayload extracts packet data from VK-formatted request
func (p *Protocol) parseVKPayload(r *http.Request) ([]byte, error) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, fmt.Errorf("read body failed: %w", err)
	}
	defer r.Body.Close()

	// Try to parse as JSON
	var vkMsg VKMessage
	if err := json.Unmarshal(body, &vkMsg); err != nil {
		// Not JSON, treat as raw data
		return body, nil
	}

	// Extract base64-encoded data
	if vkMsg.Data == "" {
		return nil, fmt.Errorf("empty data in VK message")
	}

	return []byte(vkMsg.Data), nil
}

// sendVKResponse sends a VK-formatted response
func (p *Protocol) sendVKResponse(w http.ResponseWriter, data []byte) error {
	response := map[string]interface{}{
		"response": map[string]interface{}{
			"data":      string(data), // Already base64-encoded
			"timestamp": time.Now().Unix(),
		},
	}

	// Set VK-like headers
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-VK-Response-Time", fmt.Sprintf("%d", time.Now().UnixMilli()))

	w.WriteHeader(http.StatusOK)
	return json.NewEncoder(w).Encode(response)
}
