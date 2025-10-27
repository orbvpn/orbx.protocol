// internal/protocol/shaparak/handler.go
package shaparak

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
	"github.com/orbvpn/orbx.protocol/pkg/models"
)

// Protocol implements Shaparak Iranian banking protocol mimicry
type Protocol struct {
	crypto *crypto.Manager
	tunnel *tunnel.Manager
}

// NewProtocol creates a new Shaparak protocol handler
func NewProtocol(cryptoMgr *crypto.Manager, tunnelMgr *tunnel.Manager) *Protocol {
	return &Protocol{
		crypto: cryptoMgr,
		tunnel: tunnelMgr,
	}
}

// Name returns the protocol name
func (p *Protocol) Name() string {
	return "shaparak"
}

// Validate checks if the request looks like Shaparak traffic
func (p *Protocol) Validate(r *http.Request) bool {
	ua := r.Header.Get("User-Agent")
	if !strings.Contains(ua, "Shaparak") {
		return false
	}

	ct := r.Header.Get("Content-Type")
	if !strings.Contains(ct, "json") && !strings.Contains(ct, "xml") {
		return false
	}

	return true
}

// Handle processes Shaparak protocol requests
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

	session, err := p.tunnel.GetOrCreateSession(user.UserID, string(models.ProtocolShaparak))
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
		TransactionType string `json:"transactionType"`
		Amount          string `json:"amount"`
		MerchantId      string `json:"merchantId"`
		Data            string `json:"data"`
		Timestamp       int64  `json:"timestamp"`
	}

	if err := json.Unmarshal(body, &msg); err != nil {
		return nil, fmt.Errorf("invalid shaparak message: %w", err)
	}

	data, err := base64.StdEncoding.DecodeString(msg.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to decode data: %w", err)
	}

	return data, nil
}

func (p *Protocol) sendResponse(w http.ResponseWriter, data []byte) error {
	response := map[string]interface{}{
		"status":          "success",
		"transactionId":   fmt.Sprintf("TXN_%d", time.Now().UnixNano()),
		"data":            base64.StdEncoding.EncodeToString(data),
		"timestamp":       time.Now().UnixMilli(),
		"responseCode":    "00",
		"responseMessage": "تراکنش با موفقیت انجام شد",
	}

	jsonData, err := json.Marshal(response)
	if err != nil {
		return err
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Shaparak-Version", "2.0")
	w.Header().Set("Cache-Control", "no-cache")

	w.WriteHeader(http.StatusOK)
	_, err = w.Write(jsonData)
	return err
}
