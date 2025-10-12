// pkg/models/protocol.go
package models

// ProtocolType represents the mimicry protocol type
type ProtocolType string

const (
	ProtocolTeams    ProtocolType = "teams"
	ProtocolShaparak ProtocolType = "shaparak"
	ProtocolDoH      ProtocolType = "doh"
	ProtocolHTTPS    ProtocolType = "https"
	ProtocolGoogle   ProtocolType = "google"
)

// VPNProtocolType represents the actual VPN protocol inside the disguise
type VPNProtocolType string

const (
	VPNProtocolOrbX        VPNProtocolType = "orbx"        // Native (future)
	VPNProtocolWireGuard   VPNProtocolType = "wireguard"   // NEW
	VPNProtocolVLESS       VPNProtocolType = "vless"       // Future
	VPNProtocolREALITY     VPNProtocolType = "reality"     // Future
	VPNProtocolOpenConnect VPNProtocolType = "openconnect" // Future
)

// WireGuardConfig holds WireGuard-specific configuration
type WireGuardConfig struct {
	Enabled             bool     `yaml:"enabled" json:"enabled"` // NEW: Enable/disable WireGuard
	InterfaceName       string   `yaml:"interface_name" json:"interfaceName"`
	ListenPort          int      `yaml:"listen_port" json:"listenPort"`
	PrivateKey          string   `yaml:"private_key" json:"privateKey"`
	IPPool              string   `yaml:"ip_pool" json:"ipPool"`
	DNS                 []string `yaml:"dns" json:"dns"`
	MTU                 int      `yaml:"mtu" json:"mtu"`
	PersistentKeepalive int      `yaml:"persistent_keepalive" json:"persistentKeepalive"`
	PublicInterface     string   `yaml:"public_interface" json:"publicInterface"` // NEW: For NAT
}

// WireGuardPeer represents a connected WireGuard client
type WireGuardPeer struct {
	PublicKey           string   `json:"publicKey"`
	AllowedIPs          []string `json:"allowedIPs"`
	Endpoint            string   `json:"endpoint,omitempty"`
	PersistentKeepalive int      `json:"persistentKeepalive,omitempty"`
}
