// internal/auth/ratelimit.go
package auth

import (
	"net/http"
	"sync"
	"time"
)

// RateLimiter implements a token bucket rate limiter
type RateLimiter struct {
	mu       sync.Mutex
	buckets  map[string]*bucket
	rate     int           // tokens per interval
	interval time.Duration // interval duration
	capacity int           // max tokens
}

type bucket struct {
	tokens   int
	lastFill time.Time
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(rate int, interval time.Duration, capacity int) *RateLimiter {
	rl := &RateLimiter{
		buckets:  make(map[string]*bucket),
		rate:     rate,
		interval: interval,
		capacity: capacity,
	}

	// Start cleanup goroutine
	go rl.cleanup()

	return rl
}

// Allow checks if a request from the given key is allowed
func (rl *RateLimiter) Allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	// Get or create bucket
	b, exists := rl.buckets[key]
	if !exists {
		b = &bucket{
			tokens:   rl.capacity,
			lastFill: time.Now(),
		}
		rl.buckets[key] = b
	}

	// Refill tokens
	now := time.Now()
	elapsed := now.Sub(b.lastFill)
	tokensToAdd := int(elapsed / rl.interval * time.Duration(rl.rate))

	if tokensToAdd > 0 {
		b.tokens = min(b.tokens+tokensToAdd, rl.capacity)
		b.lastFill = now
	}

	// Check if tokens available
	if b.tokens > 0 {
		b.tokens--
		return true
	}

	return false
}

// cleanup removes old buckets periodically
func (rl *RateLimiter) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		rl.mu.Lock()
		now := time.Now()
		for key, b := range rl.buckets {
			if now.Sub(b.lastFill) > 10*time.Minute {
				delete(rl.buckets, key)
			}
		}
		rl.mu.Unlock()
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// RateLimitMiddleware creates middleware for rate limiting
func RateLimitMiddleware(limiter *RateLimiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Use IP address as key
			ip := r.RemoteAddr
			if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
				ip = xff
			}

			if !limiter.Allow(ip) {
				http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
