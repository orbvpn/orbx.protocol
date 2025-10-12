// pkg/models/protocol.go
package models

// ProtocolType represents the mimicry protocol type
type ProtocolType string

const (
	// Existing
	ProtocolTeams    ProtocolType = "teams"
	ProtocolShaparak ProtocolType = "shaparak"
	ProtocolDoH      ProtocolType = "doh"
	ProtocolHTTPS    ProtocolType = "https"
	ProtocolGoogle   ProtocolType = "google"

	// NEW - Video/Conferencing
	ProtocolZoom     ProtocolType = "zoom"
	ProtocolFaceTime ProtocolType = "facetime"

	// NEW - Russia
	ProtocolVK     ProtocolType = "vk"
	ProtocolYandex ProtocolType = "yandex"

	// NEW - China
	ProtocolWeChat ProtocolType = "wechat"
)

type VPNProtocolType string

const (
	VPNProtocolWireGuard   VPNProtocolType = "wireguard"
	VPNProtocolOrbX        VPNProtocolType = "orbx"
	VPNProtocolVLESS       VPNProtocolType = "vless"
	VPNProtocolREALITY     VPNProtocolType = "reality"
	VPNProtocolOpenConnect VPNProtocolType = "openconnect"
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
