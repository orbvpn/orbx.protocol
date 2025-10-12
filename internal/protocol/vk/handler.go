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

func (p *Protocol) Validate(r *http.Request) bool {
	ua := r.Header.Get("User-Agent")

	// VK mobile apps and web
	if !strings.Contains(ua, "VKAndroidApp") &&
		!strings.Contains(ua, "VKiOSApp") &&
		!strings.Contains(ua, "vk.com") {
		return false
	}

	// VK-specific headers
	if r.Header.Get("X-VK-Android-Client") == "" &&
		r.Header.Get("X-VK-Client-Version") == "" {
		return false
	}

	return true
}

func (p *Protocol) Handle(w http.ResponseWriter, r *http.Request) error {
	user, err := auth.GetUserFromContext(r.Context())
	if err != nil {
		return fmt.Errorf("user not found: %w", err)
	}

	payload, err := p.parseVKPayload(r)
	if err != nil {
		return fmt.Errorf("failed to parse payload: %w", err)
	}

	data, err := p.crypto.DeobfuscatePacket(payload)
	if err != nil {
		return fmt.Errorf("deobfuscation failed: %w", err)
	}

	session, err := p.tunnel.GetOrCreateSession(user.UserID, string(models.ProtocolVK))
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

	return p.sendVKResponse(w, obfuscated)
}

func (p *Protocol) parseVKPayload(r *http.Request) ([]byte, error) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()

	var vkMsg struct {
		Method  string                 `json:"method"` // API method
		Params  map[string]interface{} `json:"params"`
		Version string                 `json:"v"`
		Data    string                 `json:"data"` // Encoded payload
	}

	if err := json.Unmarshal(body, &vkMsg); err != nil {
		return nil, fmt.Errorf("invalid vk message: %w", err)
	}

	return []byte(vkMsg.Data), nil
}

func (p *Protocol) sendVKResponse(w http.ResponseWriter, data []byte) error {
	response := map[string]interface{}{
		"response": map[string]interface{}{
			"data":      string(data),
			"timestamp": time.Now().Unix(),
		},
	}

	jsonData, err := json.Marshal(response)
	if err != nil {
		return err
	}

	// VK-specific headers
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-VK-Server", "api-gateway-01")
	w.Header().Set("X-VK-Response-Time", fmt.Sprintf("%d", time.Now().UnixMilli()))

	w.WriteHeader(http.StatusOK)
	_, err = w.Write(jsonData)
	return err
}
