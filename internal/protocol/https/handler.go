// internal/protocol/https/handler.go
package https

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"time"

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

// NewProtocol creates a new HTTPS protocol handler
func NewProtocol(cryptoMgr *crypto.Manager, tunnelMgr *tunnel.Manager) *Protocol {
	return &Protocol{
		crypto: cryptoMgr,
		tunnel: tunnelMgr,
	}
}

// Name returns the protocol name
func (p *Protocol) Name() string {
	return "https"
}

// Validate checks if the request is HTTPS
func (p *Protocol) Validate(r *http.Request) bool {
	// Accept all HTTPS requests as fallback
	return r.TLS != nil
}

// Handle processes fragmented HTTPS requests
func (p *Protocol) Handle(w http.ResponseWriter, r *http.Request) error {
	// Get user from context
	user, err := auth.GetUserFromContext(r.Context())
	if err != nil {
		return fmt.Errorf("user not found: %w", err)
	}

	// Read request body (potentially fragmented)
	payload, err := p.readFragmentedRequest(r)
	if err != nil {
		return fmt.Errorf("failed to read request: %w", err)
	}

	// Deobfuscate data
	data, err := p.crypto.DeobfuscatePacket(payload)
	if err != nil {
		return fmt.Errorf("deobfuscation failed: %w", err)
	}

	// Create tunnel session
	session, err := p.tunnel.GetOrCreateSession(user.UserID, string(models.ProtocolHTTPS))
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

	// Send fragmented response
	return p.sendFragmentedResponse(w, obfuscated)
}

// readFragmentedRequest reads potentially fragmented HTTP request
func (p *Protocol) readFragmentedRequest(r *http.Request) ([]byte, error) {
	// Check if request indicates fragmentation
	if r.Header.Get("X-Fragment-Total") != "" {
		return p.reassembleFragments(r)
	}

	// Not fragmented, read normally
	return io.ReadAll(r.Body)
}

// reassembleFragments reassembles fragmented request
func (p *Protocol) reassembleFragments(r *http.Request) ([]byte, error) {
	// In production, implement proper fragment reassembly
	// For now, just read the body
	return io.ReadAll(r.Body)
}

// sendFragmentedResponse sends response in fragments
func (p *Protocol) sendFragmentedResponse(w http.ResponseWriter, data []byte) error {
	// Check if we should fragment
	shouldFragment := len(data) > 1024 && p.crypto.Timing != nil

	if !shouldFragment {
		// Send as single response
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		_, err := w.Write(data)
		return err
	}

	// Fragment the response
	fragments := p.fragmentData(data)

	// Set headers
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-Fragment-Total", fmt.Sprintf("%d", len(fragments)))
	w.Header().Set("Transfer-Encoding", "chunked")
	w.WriteHeader(http.StatusOK)

	// Get flusher
	flusher, ok := w.(http.Flusher)
	if !ok {
		return fmt.Errorf("response writer doesn't support flushing")
	}

	// Send fragments with timing obfuscation
	writer := bufio.NewWriter(w)
	for i, fragment := range fragments {
		// Write fragment
		if _, err := writer.Write(fragment); err != nil {
			return err
		}

		// Flush
		if err := writer.Flush(); err != nil {
			return err
		}
		flusher.Flush()

		// Add timing delay between fragments (except last)
		if i < len(fragments)-1 && p.crypto.Timing != nil {
			delay := p.crypto.Timing.GetRandomDelay()
			time.Sleep(delay)
		}
	}

	return nil
}

// fragmentData splits data into fragments
func (p *Protocol) fragmentData(data []byte) [][]byte {
	if p.crypto.Timing == nil {
		return [][]byte{data}
	}

	// Get fragment sizes
	sizes := p.crypto.Timing.GetSplitSizes(len(data))
	fragments := make([][]byte, len(sizes))

	offset := 0
	for i, size := range sizes {
		end := offset + size
		if end > len(data) {
			end = len(data)
		}
		fragments[i] = data[offset:end]
		offset = end
	}

	return fragments
}
