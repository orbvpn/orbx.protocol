// internal/crypto/kyber.go
package crypto

import (
	"encoding/base64"
	"fmt"

	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/kyber/kyber768"
)

// KyberKeyPair represents a Kyber768 key pair
type KyberKeyPair struct {
	PublicKey  []byte
	PrivateKey []byte
}

// KyberManager handles Kyber768 post-quantum key exchange
type KyberManager struct {
	scheme kem.Scheme // Changed from *kyber768.Scheme to kem.Scheme
}

// NewKyberManager creates a new Kyber manager
func NewKyberManager() *KyberManager {
	return &KyberManager{
		scheme: kyber768.Scheme(), // Call the function to get the scheme
	}
}

// GenerateKeyPair generates a new Kyber768 key pair
func (k *KyberManager) GenerateKeyPair() (*KyberKeyPair, error) {
	publicKey, privateKey, err := k.scheme.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate key pair: %w", err)
	}

	pubBytes, err := publicKey.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	privBytes, err := privateKey.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}

	return &KyberKeyPair{
		PublicKey:  pubBytes,
		PrivateKey: privBytes,
	}, nil
}

// Encapsulate generates a shared secret and ciphertext using the public key
func (k *KyberManager) Encapsulate(publicKeyBytes []byte) (sharedSecret, ciphertext []byte, err error) {
	publicKey, err := k.scheme.UnmarshalBinaryPublicKey(publicKeyBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal public key: %w", err)
	}

	ct, ss, err := k.scheme.Encapsulate(publicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("encapsulation failed: %w", err)
	}

	return ss, ct, nil
}

// Decapsulate recovers the shared secret using the private key and ciphertext
func (k *KyberManager) Decapsulate(privateKeyBytes, ciphertext []byte) ([]byte, error) {
	privateKey, err := k.scheme.UnmarshalBinaryPrivateKey(privateKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal private key: %w", err)
	}

	ss, err := k.scheme.Decapsulate(privateKey, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decapsulation failed: %w", err)
	}

	return ss, nil
}

// EncodePublicKey encodes a public key to base64
func (k *KyberManager) EncodePublicKey(publicKey []byte) string {
	return base64.StdEncoding.EncodeToString(publicKey)
}

// DecodePublicKey decodes a base64 public key
func (k *KyberManager) DecodePublicKey(encoded string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(encoded)
}
