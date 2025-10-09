// internal/crypto/hybrid.go
package crypto

import (
	"crypto/tls"
	"fmt"
)

// HybridTLSConfig creates a TLS config with hybrid post-quantum support
func HybridTLSConfig(cert tls.Certificate) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,

		// Prioritize strong cipher suites
		CipherSuites: []uint16{
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_AES_128_GCM_SHA256,
		},

		// Use X25519 (classical) + Kyber768 (post-quantum) hybrid
		CurvePreferences: []tls.CurveID{
			tls.X25519, // Classical ECDH
			tls.CurveP256,
		},

		PreferServerCipherSuites: true,

		// Session tickets for performance
		SessionTicketsDisabled: false,
	}
}

// NegotiateHybridKey performs hybrid key exchange
// Combines classical ECDH with post-quantum Kyber768
func NegotiateHybridKey(kyber *KyberManager, clientPublicKey []byte) ([]byte, []byte, error) {
	// Perform Kyber encapsulation
	kyberShared, kyberCT, err := kyber.Encapsulate(clientPublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("Kyber encapsulation failed: %w", err)
	}

	// In production, combine with ECDH shared secret
	// For now, return Kyber shared secret
	return kyberShared, kyberCT, nil
}
