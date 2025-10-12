// internal/protocol/wechat/handler.go
package wechat

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
	return "wechat"
}

func (p *Protocol) Validate(r *http.Request) bool {
	ua := r.Header.Get("User-Agent")

	// WeChat user agents
	if !strings.Contains(ua, "MicroMessenger") && !strings.Contains(ua, "WeChat") {
		return false
	}

	// WeChat-specific headers
	if r.Header.Get("X-WECHAT-UIN") == "" && r.Header.Get("X-WECHAT-KEY") == "" {
		return false
	}

	return true
}

func (p *Protocol) Handle(w http.ResponseWriter, r *http.Request) error {
	user, err := auth.GetUserFromContext(r.Context())
	if err != nil {
		return fmt.Errorf("user not found: %w", err)
	}

	payload, err := p.parseWeChatPayload(r)
	if err != nil {
		return fmt.Errorf("failed to parse payload: %w", err)
	}

	data, err := p.crypto.DeobfuscatePacket(payload)
	if err != nil {
		return fmt.Errorf("deobfuscation failed: %w", err)
	}

	session, err := p.tunnel.GetOrCreateSession(user.UserID, string(models.ProtocolWeChat))
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

	return p.sendWeChatResponse(w, obfuscated)
}

func (p *Protocol) parseWeChatPayload(r *http.Request) ([]byte, error) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()

	var wcMsg struct {
		MsgType int    `json:"msgType"` // WeChat message types
		Content string `json:"content"` // Base64 encoded
		ToUser  string `json:"toUser"`
		Scene   int    `json:"scene"`
	}

	if err := json.Unmarshal(body, &wcMsg); err != nil {
		return nil, fmt.Errorf("invalid wechat message: %w", err)
	}

	return []byte(wcMsg.Content), nil
}

func (p *Protocol) sendWeChatResponse(w http.ResponseWriter, data []byte) error {
	response := map[string]interface{}{
		"ret":     0,
		"msg":     "success",
		"content": string(data),
		"time":    time.Now().Unix(),
	}

	jsonData, err := json.Marshal(response)
	if err != nil {
		return err
	}

	// WeChat-specific headers
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-WECHAT-Server", "sz-gateway-01")
	w.Header().Set("X-WECHAT-Version", "8.0.38")

	w.WriteHeader(http.StatusOK)
	_, err = w.Write(jsonData)
	return err
}
