// internal/protocol/yandex/handler.go
package yandex

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
)

// Protocol implements Yandex protocol mimicry
type Protocol struct {
	crypto *crypto.Manager
	tunnel *tunnel.Manager
}

// NewProtocol creates a new Yandex protocol handler
func NewProtocol(cryptoMgr *crypto.Manager, tunnelMgr *tunnel.Manager) *Protocol {
	return &Protocol{
		crypto: cryptoMgr,
		tunnel: tunnelMgr,
	}
}

// Name returns the protocol name
func (p *Protocol) Name() string {
	return "yandex"
}

// Validate checks if the request looks like Yandex traffic
func (p *Protocol) Validate(r *http.Request) bool {
	ua := r.Header.Get("User-Agent")
	return strings.Contains(ua, "YaBrowser") ||
		strings.Contains(ua, "Yandex") ||
		strings.Contains(ua, "yandex")
}

// Handle processes Yandex protocol requests
func (p *Protocol) Handle(w http.ResponseWriter, r *http.Request) error {
	user, err := auth.GetUserFromContext(r.Context())
	if err != nil {
		return fmt.Errorf("user not found: %w", err)
	}

	payload, err := p.parsePayload(r)
	if err != nil {
		return fmt.Errorf("failed to parse payload: %w", err)
	}

	wgPacket, err := p.crypto.DeobfuscatePacket(payload)
	if err != nil {
		return fmt.Errorf("deobfuscation failed: %w", err)
	}

	session, err := p.tunnel.GetOrCreateSession(user.UserID, "yandex")
	if err != nil {
		return fmt.Errorf("failed to get session: %w", err)
	}

	responsePacket, err := session.RouteData(wgPacket)
	if err != nil {
		return fmt.Errorf("routing failed: %w", err)
	}

	var obfuscated []byte
	if responsePacket != nil {
		obfuscated, err = p.crypto.ObfuscatePacket(responsePacket)
		if err != nil {
			return fmt.Errorf("obfuscation failed: %w", err)
		}
	} else {
		obfuscated = []byte{}
	}

	return p.sendResponse(w, obfuscated)
}

func (p *Protocol) parsePayload(r *http.Request) ([]byte, error) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()

	var msg struct {
		Action string `json:"action"`
		Data   string `json:"data"`
		Token  string `json:"token"`
	}

	if err := json.Unmarshal(body, &msg); err != nil {
		return nil, fmt.Errorf("invalid yandex message: %w", err)
	}

	data, err := base64.StdEncoding.DecodeString(msg.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to decode data: %w", err)
	}

	return data, nil
}

func (p *Protocol) sendResponse(w http.ResponseWriter, data []byte) error {
	response := map[string]interface{}{
		"status": "ok",
		"data":   base64.StdEncoding.EncodeToString(data),
		"time":   time.Now().Unix(),
	}

	jsonData, err := json.Marshal(response)
	if err != nil {
		return err
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Yandex-Server-Time", fmt.Sprintf("%d", time.Now().Unix()))
	w.Header().Set("Cache-Control", "no-cache")

	w.WriteHeader(http.StatusOK)
	_, err = w.Write(jsonData)
	return err
}
