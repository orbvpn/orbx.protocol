// internal/protocol/yandex/handler.go
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

func (p *Protocol) Validate(r *http.Request) bool {
	ua := r.Header.Get("User-Agent")

	// Yandex Browser and apps
	if !strings.Contains(ua, "YaBrowser") &&
		!strings.Contains(ua, "Yandex") &&
		!strings.Contains(ua, "YandexSearch") {
		return false
	}

	// Yandex-specific headers
	if r.Header.Get("X-Yandex-Client-Id") == "" {
		return false
	}

	return true
}

func (p *Protocol) Handle(w http.ResponseWriter, r *http.Request) error {
	user, err := auth.GetUserFromContext(r.Context())
	if err != nil {
		return fmt.Errorf("user not found: %w", err)
	}

	payload, err := p.parseYandexPayload(r)
	if err != nil {
		return fmt.Errorf("failed to parse payload: %w", err)
	}

	data, err := p.crypto.DeobfuscatePacket(payload)
	if err != nil {
		return fmt.Errorf("deobfuscation failed: %w", err)
	}

	session, err := p.tunnel.GetOrCreateSession(user.UserID, string(models.ProtocolYandex))
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

	return p.sendYandexResponse(w, obfuscated)
}

func (p *Protocol) parseYandexPayload(r *http.Request) ([]byte, error) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()

	var yandexMsg struct {
		Query     string `json:"query"`
		Service   string `json:"service"` // "search", "mail", "disk", etc.
		Data      string `json:"data"`
		RequestID string `json:"requestId"`
	}

	if err := json.Unmarshal(body, &yandexMsg); err != nil {
		return nil, fmt.Errorf("invalid yandex message: %w", err)
	}

	return []byte(yandexMsg.Data), nil
}

func (p *Protocol) sendYandexResponse(w http.ResponseWriter, data []byte) error {
	response := map[string]interface{}{
		"status": "ok",
		"data":   string(data),
		"reqid":  generateRequestID(),
		"time":   time.Now().Unix(),
	}

	jsonData, err := json.Marshal(response)
	if err != nil {
		return err
	}

	// Yandex-specific headers
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Yandex-Server-Name", "yandex-api-gateway")
	w.Header().Set("X-Yandex-Request-Id", generateRequestID())

	w.WriteHeader(http.StatusOK)
	_, err = w.Write(jsonData)
	return err
}

func generateRequestID() string {
	return fmt.Sprintf("yandex-%d", time.Now().UnixNano())
}
