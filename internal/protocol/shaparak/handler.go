package shaparak

import (
	"encoding/json"
	"encoding/xml"
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

// Protocol implements Shaparak (Iranian banking) protocol mimicry
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
	return "shaparak"
}

// Validate checks if the request should be handled by Shaparak protocol
func (p *Protocol) Validate(r *http.Request) bool {
	// 🔓 PERMISSIVE MODE: Accept any request with valid Bearer token
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") && len(auth) > 10 {
		return true
	}

	// 🔒 STRICT MODE: Validate Shaparak-specific characteristics
	ct := r.Header.Get("Content-Type")

	// Check for SOAP/XML content type
	if strings.Contains(ct, "text/xml") ||
		strings.Contains(ct, "application/soap+xml") ||
		strings.Contains(ct, "application/xml") {

		// Check for SOAP action header
		soapAction := r.Header.Get("SOAPAction")
		if soapAction != "" {
			return true
		}
	}

	return false
}

// Handle processes Shaparak protocol requests
func (p *Protocol) Handle(w http.ResponseWriter, r *http.Request) error {
	// Get authenticated user
	user, err := auth.GetUserFromContext(r.Context())
	if err != nil {
		return fmt.Errorf("user not found: %w", err)
	}

	// Parse Shaparak payload
	payload, err := p.parseShaparakPayload(r)
	if err != nil {
		return fmt.Errorf("failed to parse payload: %w", err)
	}

	// Deobfuscate packet data
	data, err := p.crypto.DeobfuscatePacket(payload)
	if err != nil {
		return fmt.Errorf("deobfuscation failed: %w", err)
	}

	// Get or create tunnel session
	session, err := p.tunnel.GetOrCreateSession(user.UserID, string(models.ProtocolShaparak))
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

	// Send Shaparak-like response
	return p.sendShaparakResponse(w, obfuscated)
}

// ShaparakEnvelope represents a SOAP envelope
type ShaparakEnvelope struct {
	XMLName xml.Name `xml:"Envelope"`
	Body    ShaparakBody
}

type ShaparakBody struct {
	XMLName xml.Name `xml:"Body"`
	Content string   `xml:"TransactionData"`
}

// ShaparakJSONPayload for JSON-based requests (from Flutter)
type ShaparakJSONPayload struct {
	TransactionType string `json:"transactionType"`
	Amount          string `json:"amount"`
	MerchantID      string `json:"merchantId"`
	Data            string `json:"data"` // Base64-encoded packet data
	Timestamp       int64  `json:"timestamp"`
}

// parseShaparakPayload extracts packet data from Shaparak request
func (p *Protocol) parseShaparakPayload(r *http.Request) ([]byte, error) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, fmt.Errorf("read body failed: %w", err)
	}
	defer r.Body.Close()

	ct := r.Header.Get("Content-Type")

	// Try JSON first (Flutter client sends JSON)
	if strings.Contains(ct, "application/json") {
		var jsonPayload ShaparakJSONPayload
		if err := json.Unmarshal(body, &jsonPayload); err == nil {
			if jsonPayload.Data != "" {
				return []byte(jsonPayload.Data), nil
			}
		}
	}

	// Try XML/SOAP
	if strings.Contains(ct, "xml") {
		var envelope ShaparakEnvelope
		if err := xml.Unmarshal(body, &envelope); err == nil {
			if envelope.Body.Content != "" {
				return []byte(envelope.Body.Content), nil
			}
		}
	}

	// Fallback: treat as raw data
	return body, nil
}

// sendShaparakResponse sends a Shaparak-formatted response
func (p *Protocol) sendShaparakResponse(w http.ResponseWriter, data []byte) error {
	ct := w.Header().Get("Content-Type")

	// If client expects JSON (our Flutter client)
	if strings.Contains(ct, "json") || ct == "" {
		response := ShaparakJSONPayload{
			TransactionType: "response",
			Amount:          "0",
			MerchantID:      "orbx",
			Data:            string(data), // Already base64-encoded
			Timestamp:       time.Now().Unix(),
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		return json.NewEncoder(w).Encode(response)
	}

	// SOAP/XML response
	envelope := ShaparakEnvelope{
		Body: ShaparakBody{
			Content: string(data), // Already base64-encoded
		},
	}

	w.Header().Set("Content-Type", "text/xml; charset=utf-8")
	w.WriteHeader(http.StatusOK)

	xmlData, err := xml.MarshalIndent(envelope, "", "  ")
	if err != nil {
		return fmt.Errorf("xml marshal failed: %w", err)
	}

	_, err = w.Write(xmlData)
	return err
}
