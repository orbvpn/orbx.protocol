// internal/protocol/shaparak/handler.go
package shaparak

import (
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
	// Check for Shaparak-like content type
	ct := r.Header.Get("Content-Type")
	if !strings.Contains(ct, "text/xml") && !strings.Contains(ct, "application/soap+xml") {
		return false
	}

	// Check for SOAP action header
	soapAction := r.Header.Get("SOAPAction")
	if soapAction == "" {
		return false
	}

	return true
}

// Handle processes Shaparak protocol requests
func (p *Protocol) Handle(w http.ResponseWriter, r *http.Request) error {
	// Get user from context
	user, err := auth.GetUserFromContext(r.Context())
	if err != nil {
		return fmt.Errorf("user not found: %w", err)
	}

	// Parse Shaparak SOAP request
	payload, err := p.parseShaparakPayload(r)
	if err != nil {
		return fmt.Errorf("failed to parse payload: %w", err)
	}

	// Deobfuscate data
	data, err := p.crypto.DeobfuscatePacket(payload)
	if err != nil {
		return fmt.Errorf("deobfuscation failed: %w", err)
	}

	// Create tunnel session
	session, err := p.tunnel.GetOrCreateSession(user.UserID, string(models.ProtocolShaparak))
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

// parseShaparakPayload extracts data from Shaparak SOAP request
func (p *Protocol) parseShaparakPayload(r *http.Request) ([]byte, error) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()

	var envelope ShaparakEnvelope
	if err := xml.Unmarshal(body, &envelope); err != nil {
		return nil, fmt.Errorf("invalid SOAP envelope: %w", err)
	}

	// Extract transaction data (contains our tunneled data)
	return []byte(envelope.Body.Content), nil
}

// sendShaparakResponse sends a Shaparak SOAP response
func (p *Protocol) sendShaparakResponse(w http.ResponseWriter, data []byte) error {
	// Create SOAP response envelope
	response := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
    <soap:Header>
        <TransactionID>%s</TransactionID>
        <Timestamp>%s</Timestamp>
    </soap:Header>
    <soap:Body>
        <TransactionResponse>
            <Status>Success</Status>
            <Data>%s</Data>
            <ReferenceNumber>%d</ReferenceNumber>
        </TransactionResponse>
    </soap:Body>
</soap:Envelope>`,
		generateTransactionID(),
		time.Now().Format(time.RFC3339),
		string(data), // Base64 encode in production
		time.Now().Unix(),
	)

	// Set Shaparak-like headers
	w.Header().Set("Content-Type", "text/xml; charset=utf-8")
	w.Header().Set("SOAPAction", "TransactionResponse")
	w.Header().Set("X-Shaparak-Version", "2.0")

	w.WriteHeader(http.StatusOK)
	_, err := w.Write([]byte(response))
	return err
}

func generateTransactionID() string {
	return fmt.Sprintf("TXN%d%06d", time.Now().Unix(), time.Now().Nanosecond()%1000000)
}
