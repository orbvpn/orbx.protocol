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

func (p *Protocol) Validate(r *http.Request) bool {
	ua := r.Header.Get("User-Agent")

	// FaceTime uses Apple user agents
	if !strings.Contains(ua, "FaceTime") && !strings.Contains(ua, "AppleWebKit") {
		return false
	}

	// FaceTime-specific headers
	if r.Header.Get("X-Apple-Session-ID") == "" && r.Header.Get("X-Apple-Device-ID") == "" {
		return false
	}

	return true
}

func (p *Protocol) Handle(w http.ResponseWriter, r *http.Request) error {
	user, err := auth.GetUserFromContext(r.Context())
	if err != nil {
		return fmt.Errorf("user not found: %w", err)
	}

	payload, err := p.parseFaceTimePayload(r)
	if err != nil {
		return fmt.Errorf("failed to parse payload: %w", err)
	}

	data, err := p.crypto.DeobfuscatePacket(payload)
	if err != nil {
		return fmt.Errorf("deobfuscation failed: %w", err)
	}

	session, err := p.tunnel.GetOrCreateSession(user.UserID, string(models.ProtocolFaceTime))
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

	return p.sendFaceTimeResponse(w, obfuscated)
}

func (p *Protocol) parseFaceTimePayload(r *http.Request) ([]byte, error) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()

	var ftMsg struct {
		Type       string `json:"type"`       // "audio", "video", "control"
		StreamData string `json:"streamData"` // Base64 encoded
		SessionID  string `json:"sessionId"`
		DeviceID   string `json:"deviceId"`
	}

	if err := json.Unmarshal(body, &ftMsg); err != nil {
		return nil, fmt.Errorf("invalid facetime message: %w", err)
	}

	return []byte(ftMsg.StreamData), nil
}

func (p *Protocol) sendFaceTimeResponse(w http.ResponseWriter, data []byte) error {
	response := map[string]interface{}{
		"type":       "video",
		"streamData": string(data),
		"sessionId":  generateAppleSessionID(),
		"timestamp":  time.Now().Unix(),
	}

	jsonData, err := json.Marshal(response)
	if err != nil {
		return err
	}

	// Apple-specific headers
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Apple-Session-ID", generateAppleSessionID())
	w.Header().Set("X-Apple-Server-Version", "17.5.1")
	w.Header().Set("X-Apple-Request-UUID", generateUUID())

	w.WriteHeader(http.StatusOK)
	_, err = w.Write(jsonData)
	return err
}

func generateAppleSessionID() string {
	return fmt.Sprintf("ft-%d", time.Now().UnixNano())
}

func generateUUID() string {
	return fmt.Sprintf("%d-%d-%d", time.Now().Unix(), time.Now().UnixNano(), time.Now().UnixMilli())
}
