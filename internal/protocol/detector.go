// internal/protocol/detector.go
package protocol

import (
	"bytes"

	"github.com/orbvpn/orbx.protocol/pkg/models"
)

// Detector identifies which VPN protocol is inside the disguise
type Detector struct{}

// NewDetector creates a new protocol detector
func NewDetector() *Detector {
	return &Detector{}
}

// DetectVPNProtocol identifies the VPN protocol from packet data
func (d *Detector) DetectVPNProtocol(data []byte) models.VPNProtocolType {
	if len(data) == 0 {
		return ""
	}

	// OrbX Native: Custom magic bytes "ORBX" (future)
	if bytes.HasPrefix(data, []byte{0x4F, 0x52, 0x42, 0x58}) {
		return models.VPNProtocolOrbX
	}

	// WireGuard: Message type indicators
	// Type 1: Handshake Initiation
	// Type 2: Handshake Response
	// Type 4: Transport Data
	if len(data) >= 4 {
		messageType := data[0]
		if messageType == 0x01 || messageType == 0x02 || messageType == 0x04 {
			// Additional validation: check reserved bytes
			reserved := data[1:4]
			if bytes.Equal(reserved, []byte{0x00, 0x00, 0x00}) {
				return models.VPNProtocolWireGuard
			}
		}
	}

	// VLESS: Version byte + UUID (future)
	if data[0] == 0x00 && len(data) > 17 {
		return models.VPNProtocolVLESS
	}

	// REALITY: TLS ClientHello (future)
	if data[0] == 0x16 && len(data) > 1 && data[1] == 0x03 {
		return models.VPNProtocolREALITY
	}

	// OpenConnect: DTLS (future)
	if data[0] >= 0x14 && data[0] <= 0x17 {
		return models.VPNProtocolOpenConnect
	}

	return ""
}
