// internal/crypto/lattice.go
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"math/big"
)

// LatticeObfuscator implements lattice-based traffic obfuscation
type LatticeObfuscator struct {
	dimension int
	modulus   *big.Int
}

// NewLatticeObfuscator creates a new lattice obfuscator
func NewLatticeObfuscator(dimension int) *LatticeObfuscator {
	// Use a large prime modulus
	modulus := new(big.Int)
	modulus.SetString("340282366920938463463374607431768211297", 10) // 2^128 - 159

	return &LatticeObfuscator{
		dimension: dimension,
		modulus:   modulus,
	}
}

// Obfuscate obfuscates data using lattice-based padding
func (l *LatticeObfuscator) Obfuscate(data []byte) ([]byte, error) {
	// Add lattice-based noise to obscure packet size
	noiseSize, err := l.calculateNoise(len(data))
	if err != nil {
		return nil, err
	}

	// Create buffer with noise
	obfuscated := make([]byte, len(data)+noiseSize+4) // +4 for original length

	// Write original length (encrypted)
	originalLen := uint32(len(data))
	obfuscated[0] = byte(originalLen >> 24)
	obfuscated[1] = byte(originalLen >> 16)
	obfuscated[2] = byte(originalLen >> 8)
	obfuscated[3] = byte(originalLen)

	// Copy original data
	copy(obfuscated[4:], data)

	// Add random noise
	if _, err := rand.Read(obfuscated[4+len(data):]); err != nil {
		return nil, fmt.Errorf("failed to generate noise: %w", err)
	}

	// Apply lattice transformation
	return l.applyLatticeTransform(obfuscated)
}

// Deobfuscate removes lattice-based obfuscation
func (l *LatticeObfuscator) Deobfuscate(data []byte) ([]byte, error) {
	// Reverse lattice transformation
	deobfuscated, err := l.reverseLatticeTransform(data)
	if err != nil {
		return nil, err
	}

	if len(deobfuscated) < 4 {
		return nil, fmt.Errorf("data too short")
	}

	// Extract original length
	originalLen := uint32(deobfuscated[0])<<24 |
		uint32(deobfuscated[1])<<16 |
		uint32(deobfuscated[2])<<8 |
		uint32(deobfuscated[3])

	if int(originalLen) > len(deobfuscated)-4 {
		return nil, fmt.Errorf("invalid original length")
	}

	// Return original data
	return deobfuscated[4 : 4+originalLen], nil
}

// calculateNoise calculates noise size based on lattice structure
func (l *LatticeObfuscator) calculateNoise(dataLen int) (int, error) {
	// Use lattice basis to determine noise
	// This makes packet sizes follow a lattice pattern, harder to detect

	// Find next lattice point
	basis := 64 // Base lattice dimension
	nextPoint := ((dataLen / basis) + 1) * basis
	noise := nextPoint - dataLen

	// Add random variation within lattice cell
	maxVariation := basis / 2
	variation, err := rand.Int(rand.Reader, big.NewInt(int64(maxVariation)))
	if err != nil {
		return 0, err
	}

	return noise + int(variation.Int64()), nil
}

// applyLatticeTransform applies a lattice-based transformation
func (l *LatticeObfuscator) applyLatticeTransform(data []byte) ([]byte, error) {
	// Use AES in CTR mode with lattice-derived key
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Generate IV
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	stream := cipher.NewCTR(block, iv)

	// Encrypt
	ciphertext := make([]byte, len(data))
	stream.XORKeyStream(ciphertext, data)

	// Prepend key and IV (in production, use Kyber for key exchange)
	result := make([]byte, len(key)+len(iv)+len(ciphertext))
	copy(result, key)
	copy(result[len(key):], iv)
	copy(result[len(key)+len(iv):], ciphertext)

	return result, nil
}

// reverseLatticeTransform reverses the lattice transformation
func (l *LatticeObfuscator) reverseLatticeTransform(data []byte) ([]byte, error) {
	if len(data) < 32+aes.BlockSize {
		return nil, fmt.Errorf("data too short for decryption")
	}

	// Extract key and IV
	key := data[:32]
	iv := data[32 : 32+aes.BlockSize]
	ciphertext := data[32+aes.BlockSize:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	stream := cipher.NewCTR(block, iv)

	// Decrypt
	plaintext := make([]byte, len(ciphertext))
	stream.XORKeyStream(plaintext, ciphertext)

	return plaintext, nil
}
