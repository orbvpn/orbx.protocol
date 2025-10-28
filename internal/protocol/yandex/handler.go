package yandex

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
	return "yandex"
}

// Validate checks if the request should be handled by Yandex protocol
func (p *Protocol) Validate(r *http.Request) bool {
	// 🔓 PERMISSIVE MODE: Accept any request with valid Bearer token
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") && len(authHeader) > 10 {
		return true
	}

	// 🔒 STRICT MODE: Validate Yandex-specific characteristics
	ua := r.Header.Get("User-Agent")

	// Check for Yandex user agents
	if strings.Contains(ua, "YaBrowser") ||
		strings.Contains(ua, "Yandex") ||
		strings.Contains(ua, "YandexSearch") ||
		strings.Contains(ua, "YandexBot") {
		return true
	}

	// Check for Yandex-specific headers
	if r.Header.Get("X-Yandex-Client-Id") != "" ||
		r.Header.Get("X-Yandex-Request-Id") != "" {
		return true
	}

	return false
}

// Handle processes Yandex protocol requests
func (p *Protocol) Handle(w http.ResponseWriter, r *http.Request) error {
	// Get authenticated user
	user, err := auth.GetUserFromContext(r.Context())
	if err != nil {
		return fmt.Errorf("user not found: %w", err)
	}

	// Parse Yandex payload
	payload, err := p.parseYandexPayload(r)
	if err != nil {
		return fmt.Errorf("failed to parse payload: %w", err)
	}

	// Deobfuscate packet data
	data, err := p.crypto.DeobfuscatePacket(payload)
	if err != nil {
		return fmt.Errorf("deobfuscation failed: %w", err)
	}

	// Get or create tunnel session
	session, err := p.tunnel.GetOrCreateSession(user.UserID, string(models.ProtocolYandex))
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

	// Send Yandex-like response
	return p.sendYandexResponse(w, obfuscated)
}

// YandexMessage represents a Yandex service message payload
type YandexMessage struct {
	Query     string                 `json:"query,omitempty"`
	Service   string                 `json:"service,omitempty"` // "search", "mail", "disk", etc.
	Data      string                 `json:"data"`              // Base64-encoded packet data
	Params    map[string]interface{} `json:"params,omitempty"`
	Timestamp int64                  `json:"timestamp"`
}

// parseYandexPayload extracts packet data from Yandex-formatted request
func (p *Protocol) parseYandexPayload(r *http.Request) ([]byte, error) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, fmt.Errorf("read body failed: %w", err)
	}
	defer r.Body.Close()

	// Try to parse as JSON
	var yandexMsg YandexMessage
	if err := json.Unmarshal(body, &yandexMsg); err != nil {
		// Not JSON, treat as raw data
		return body, nil
	}

	// Extract base64-encoded data
	if yandexMsg.Data == "" {
		return nil, fmt.Errorf("empty data in Yandex message")
	}

	return []byte(yandexMsg.Data), nil
}

// sendYandexResponse sends a Yandex-formatted response
func (p *Protocol) sendYandexResponse(w http.ResponseWriter, data []byte) error {
	response := YandexMessage{
		Service:   "response",
		Data:      string(data), // Already base64-encoded
		Timestamp: time.Now().Unix(),
	}

	// Set Yandex-like headers
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Yandex-Response-Time", fmt.Sprintf("%d", time.Now().UnixMilli()))
	w.Header().Set("Server", "Yandex")

	w.WriteHeader(http.StatusOK)
	return json.NewEncoder(w).Encode(response)
}
