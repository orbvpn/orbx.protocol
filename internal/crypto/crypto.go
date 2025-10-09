// internal/crypto/crypto.go
package crypto

import (
	"fmt"
	"time"

	"github.com/orbvpn/orbx.protocol/internal/config"
)

// Manager handles all cryptographic operations
type Manager struct {
	Kyber   *KyberManager
	Lattice *LatticeObfuscator
	Timing  *TimingObfuscator

	quantumSafe    bool
	latticeEnabled bool
	timingEnabled  bool
}

// NewManager creates a new crypto manager
func NewManager(cfg config.CryptoConfig) (*Manager, error) {
	manager := &Manager{
		quantumSafe:    cfg.QuantumSafe,
		latticeEnabled: cfg.LatticeEnabled,
		timingEnabled:  cfg.TimingEnabled,
	}

	// Initialize Kyber768 if quantum-safe is enabled
	if cfg.QuantumSafe {
		manager.Kyber = NewKyberManager()
	}

	// Initialize lattice obfuscation
	if cfg.LatticeEnabled {
		manager.Lattice = NewLatticeObfuscator(128) // 128-bit security
	}

	// Initialize timing obfuscation
	if cfg.TimingEnabled {
		manager.Timing = NewTimingObfuscator(
			5*time.Millisecond,  // min delay
			50*time.Millisecond, // max delay
		)
	}

	return manager, nil
}

// ObfuscatePacket applies all enabled obfuscation techniques
func (m *Manager) ObfuscatePacket(data []byte) ([]byte, error) {
	result := data

	// Apply lattice obfuscation
	if m.latticeEnabled && m.Lattice != nil {
		obfuscated, err := m.Lattice.Obfuscate(result)
		if err != nil {
			return nil, fmt.Errorf("lattice obfuscation failed: %w", err)
		}
		result = obfuscated
	}

	// Apply timing obfuscation (adds delay)
	if m.timingEnabled && m.Timing != nil {
		m.Timing.ObfuscatePacketTiming()
	}

	return result, nil
}

// DeobfuscatePacket removes obfuscation
func (m *Manager) DeobfuscatePacket(data []byte) ([]byte, error) {
	result := data

	// Remove lattice obfuscation
	if m.latticeEnabled && m.Lattice != nil {
		deobfuscated, err := m.Lattice.Deobfuscate(result)
		if err != nil {
			return nil, fmt.Errorf("lattice deobfuscation failed: %w", err)
		}
		result = deobfuscated
	}

	return result, nil
}

// GenerateKeyPair generates a Kyber768 key pair
func (m *Manager) GenerateKeyPair() (*KyberKeyPair, error) {
	if !m.quantumSafe || m.Kyber == nil {
		return nil, fmt.Errorf("quantum-safe crypto not enabled")
	}
	return m.Kyber.GenerateKeyPair()
}

// PerformKeyExchange performs hybrid key exchange
func (m *Manager) PerformKeyExchange(clientPublicKey []byte) (sharedSecret, ciphertext []byte, err error) {
	if !m.quantumSafe || m.Kyber == nil {
		return nil, nil, fmt.Errorf("quantum-safe crypto not enabled")
	}

	return NegotiateHybridKey(m.Kyber, clientPublicKey)
}
