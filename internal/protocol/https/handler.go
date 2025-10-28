package https

import (
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/orbvpn/orbx.protocol/internal/auth"
	"github.com/orbvpn/orbx.protocol/internal/crypto"
	"github.com/orbvpn/orbx.protocol/internal/tunnel"
	"github.com/orbvpn/orbx.protocol/pkg/models"
)

// Protocol implements fragmented HTTPS
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
	return "https"
}

// Validate checks if the request should be handled by HTTPS protocol
func (p *Protocol) Validate(r *http.Request) bool {
	// 🔓 PERMISSIVE MODE: Accept any request with valid Bearer token
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") && len(authHeader) > 10 {
		return true
	}

	// 🔒 STRICT MODE: Accept all HTTPS requests as fallback
	// This is the catch-all protocol for generic HTTPS traffic
	return r.TLS != nil
}

// Handle processes fragmented HTTPS requests
func (p *Protocol) Handle(w http.ResponseWriter, r *http.Request) error {
	// Get authenticated user
	user, err := auth.GetUserFromContext(r.Context())
	if err != nil {
		return fmt.Errorf("user not found: %w", err)
	}

	// Read request body (potentially fragmented)
	payload, err := p.readFragmentedRequest(r)
	if err != nil {
		return fmt.Errorf("failed to read request: %w", err)
	}

	// Deobfuscate packet data
	data, err := p.crypto.DeobfuscatePacket(payload)
	if err != nil {
		return fmt.Errorf("deobfuscation failed: %w", err)
	}

	// Get or create tunnel session
	session, err := p.tunnel.GetOrCreateSession(user.UserID, string(models.ProtocolHTTPS))
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

	// Send fragmented response
	return p.sendFragmentedResponse(w, obfuscated)
}

// readFragmentedRequest reads potentially fragmented HTTP request
func (p *Protocol) readFragmentedRequest(r *http.Request) ([]byte, error) {
	// Check if request indicates fragmentation
	fragmentTotal := r.Header.Get("X-Fragment-Total")
	if fragmentTotal != "" {
		return p.reassembleFragments(r)
	}

	// Not fragmented, read normally
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, fmt.Errorf("read body failed: %w", err)
	}
	defer r.Body.Close()

	return body, nil
}

// reassembleFragments reassembles fragmented request
func (p *Protocol) reassembleFragments(r *http.Request) ([]byte, error) {
	// TODO: Implement proper fragment reassembly
	// For now, just read the body as a single fragment
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, fmt.Errorf("read body failed: %w", err)
	}
	defer r.Body.Close()

	return body, nil
}

// sendFragmentedResponse sends response in fragments
func (p *Protocol) sendFragmentedResponse(w http.ResponseWriter, data []byte) error {
	// Check if we should fragment the response
	shouldFragment := len(data) > 1024 && p.crypto.Timing != nil

	if !shouldFragment {
		// Send as single response
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		_, err := w.Write(data)
		return err
	}

	// TODO: Implement proper response fragmentation
	// For now, send as single response
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	_, err := w.Write(data)
	return err
}
