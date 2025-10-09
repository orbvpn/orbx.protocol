// internal/crypto/timing.go
package crypto

import (
	"crypto/rand"
	"math/big"
	"time"
)

// TimingObfuscator implements timing channel obfuscation
type TimingObfuscator struct {
	minDelay time.Duration
	maxDelay time.Duration
}

// NewTimingObfuscator creates a new timing obfuscator
func NewTimingObfuscator(minDelay, maxDelay time.Duration) *TimingObfuscator {
	return &TimingObfuscator{
		minDelay: minDelay,
		maxDelay: maxDelay,
	}
}

// GetRandomDelay returns a random delay to obfuscate timing
func (t *TimingObfuscator) GetRandomDelay() time.Duration {
	if t.maxDelay <= t.minDelay {
		return t.minDelay
	}

	// Generate random delay between min and max
	delta := int64(t.maxDelay - t.minDelay)
	randomDelta, err := rand.Int(rand.Reader, big.NewInt(delta))
	if err != nil {
		// Fallback to minDelay on error
		return t.minDelay
	}

	return t.minDelay + time.Duration(randomDelta.Int64())
}

// ObfuscatePacketTiming adds random delay to packet transmission
func (t *TimingObfuscator) ObfuscatePacketTiming() {
	delay := t.GetRandomDelay()
	time.Sleep(delay)
}

// GenerateJitter generates timing jitter for protocol obfuscation
func (t *TimingObfuscator) GenerateJitter(baseInterval time.Duration) time.Duration {
	// Add ±20% jitter to base interval
	maxJitter := baseInterval / 5 // 20%

	jitter, err := rand.Int(rand.Reader, big.NewInt(int64(maxJitter)*2))
	if err != nil {
		return baseInterval
	}

	return baseInterval - maxJitter + time.Duration(jitter.Int64())
}

// SplitPacket determines if a packet should be split for timing obfuscation
func (t *TimingObfuscator) SplitPacket(packetSize int, threshold int) bool {
	if packetSize < threshold {
		return false
	}

	// Randomly decide to split large packets
	split, err := rand.Int(rand.Reader, big.NewInt(100))
	if err != nil {
		return false
	}

	// 70% chance to split packets larger than threshold
	return split.Int64() < 70
}

// GetSplitSizes returns sizes for packet splitting
func (t *TimingObfuscator) GetSplitSizes(totalSize int) []int {
	if totalSize < 100 {
		return []int{totalSize}
	}

	// Split into 2-4 parts
	numParts, err := rand.Int(rand.Reader, big.NewInt(3))
	if err != nil {
		return []int{totalSize}
	}
	parts := int(numParts.Int64()) + 2

	sizes := make([]int, parts)
	remaining := totalSize

	for i := 0; i < parts-1; i++ {
		// Random size between 20% and 40% of remaining
		minSize := remaining / 5
		maxSize := (remaining * 2) / 5

		if maxSize <= minSize {
			sizes[i] = remaining / (parts - i)
		} else {
			size, err := rand.Int(rand.Reader, big.NewInt(int64(maxSize-minSize)))
			if err != nil {
				sizes[i] = minSize
			} else {
				sizes[i] = minSize + int(size.Int64())
			}
		}
		remaining -= sizes[i]
	}

	sizes[parts-1] = remaining
	return sizes
}
