// pkg/models/types.go
package models

import "time"

// UserClaims represents JWT token claims from OrbNet
type UserClaims struct {
	UserID           int       `json:"user_id"`
	Username         string    `json:"username"`
	Email            string    `json:"email"`
	SubscriptionTier string    `json:"subscription_tier"`
	ExpiresAt        time.Time `json:"exp"`
	IssuedAt         time.Time `json:"iat"`
}

// UsageMetrics represents connection usage data
type UsageMetrics struct {
	UserID       int           `json:"userId"`
	ServerID     int64         `json:"serverId"`
	SessionID    string        `json:"sessionId"`
	BytesSent    int64         `json:"bytesSent"`
	BytesRecv    int64         `json:"bytesReceived"`
	Duration     time.Duration `json:"duration"`
	Protocol     string        `json:"protocol"`
	DisconnectAt time.Time     `json:"disconnectedAt"`
}

// ServerConfig represents OrbX server configuration from OrbNet
type ServerConfig struct {
	ServerID       int64    `json:"serverId"`
	Endpoint       string   `json:"endpoint"`
	Port           int      `json:"port"`
	PublicKey      string   `json:"publicKey"`
	Protocols      []string `json:"protocols"`
	TLSFingerprint string   `json:"tlsFingerprint"`
	QuantumSafe    bool     `json:"quantumSafe"`
	Region         string   `json:"region"`
}

// Protocol types
const (
	ProtocolTeams    = "teams"
	ProtocolShaparak = "shaparak"
	ProtocolDoH      = "doh"
	ProtocolHTTPS    = "https"
)

// Subscription tiers
const (
	TierBasic   = "basic"
	TierPro     = "pro"
	TierPremium = "premium"
)
