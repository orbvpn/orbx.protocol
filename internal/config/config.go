// internal/config/config.go
package config

import (
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config represents the complete server configuration
type Config struct {
	Server    ServerConfig    `yaml:"server"`
	JWT       JWTConfig       `yaml:"jwt"`
	OrbNet    OrbNetConfig    `yaml:"orbnet"`
	Crypto    CryptoConfig    `yaml:"crypto"`
	Azure     AzureConfig     `yaml:"azure"`
	Logging   LoggingConfig   `yaml:"logging"`
	WireGuard WireGuardConfig `yaml:"wireguard"` // ✅ ADDED
}

// ServerConfig contains server-specific settings
type ServerConfig struct {
	Port         string        `yaml:"port"`
	Host         string        `yaml:"host"`
	CertFile     string        `yaml:"cert_file"`
	KeyFile      string        `yaml:"key_file"`
	ReadTimeout  time.Duration `yaml:"read_timeout"`
	WriteTimeout time.Duration `yaml:"write_timeout"`
	IdleTimeout  time.Duration `yaml:"idle_timeout"`
}

// JWTConfig contains JWT validation settings
type JWTConfig struct {
	Secret string `yaml:"secret"`
}

// OrbNetConfig contains OrbNet API settings
type OrbNetConfig struct {
	Endpoint string `yaml:"endpoint"`
	APIKey   string `yaml:"api_key"`
	ServerID string `yaml:"server_id"` // ✅ ADDED for heartbeat
}

// CryptoConfig contains cryptography settings
type CryptoConfig struct {
	QuantumSafe    bool `yaml:"quantum_safe"`
	LatticeEnabled bool `yaml:"lattice_enabled"`
	TimingEnabled  bool `yaml:"timing_enabled"`
}

// AzureConfig contains Azure-specific settings
type AzureConfig struct {
	KeyVaultURL string `yaml:"keyvault_url"`
	TenantID    string `yaml:"tenant_id"`
	ClientID    string `yaml:"client_id"`
}

// LoggingConfig contains logging settings
type LoggingConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}

// WireGuardConfig contains WireGuard settings
type WireGuardConfig struct {
	Enabled    bool   `yaml:"enabled"`
	Interface  string `yaml:"interface"`
	Address    string `yaml:"address"`     // e.g., "10.8.0.1/24"
	ListenPort int    `yaml:"listen_port"` // e.g., 51820
	PrivateKey string `yaml:"private_key"` // Optional, will generate if empty
	PublicKey  string `yaml:"public_key"`  // Optional, will generate if empty
	MTU        int    `yaml:"mtu"`         // Default: 1420
}

// Load reads configuration from file and environment variables
func Load(path string) (*Config, error) {
	// Read config file
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	// Parse YAML
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	// Override with environment variables
	if secret := os.Getenv("JWT_SECRET"); secret != "" {
		cfg.JWT.Secret = secret
	}
	if endpoint := os.Getenv("ORBNET_ENDPOINT"); endpoint != "" {
		cfg.OrbNet.Endpoint = endpoint
	}
	if apiKey := os.Getenv("ORBNET_API_KEY"); apiKey != "" {
		cfg.OrbNet.APIKey = apiKey
	}
	if serverID := os.Getenv("ORBNET_SERVER_ID"); serverID != "" {
		cfg.OrbNet.ServerID = serverID
	}
	if kvURL := os.Getenv("AZURE_KEYVAULT_URL"); kvURL != "" {
		cfg.Azure.KeyVaultURL = kvURL
	}

	// WireGuard environment variables
	if wgEnabled := os.Getenv("WIREGUARD_ENABLED"); wgEnabled != "" {
		cfg.WireGuard.Enabled = wgEnabled == "true"
	}
	if wgPrivKey := os.Getenv("WG_PRIVATE_KEY"); wgPrivKey != "" {
		cfg.WireGuard.PrivateKey = wgPrivKey
	}
	if wgPubKey := os.Getenv("WG_PUBLIC_KEY"); wgPubKey != "" {
		cfg.WireGuard.PublicKey = wgPubKey
	}

	// Set defaults
	if cfg.Server.Port == "" {
		cfg.Server.Port = "8443"
	}
	if cfg.Server.Host == "" {
		cfg.Server.Host = "0.0.0.0"
	}
	if cfg.Server.ReadTimeout == 0 {
		cfg.Server.ReadTimeout = 30 * time.Second
	}
	if cfg.Server.WriteTimeout == 0 {
		cfg.Server.WriteTimeout = 30 * time.Second
	}
	if cfg.Server.IdleTimeout == 0 {
		cfg.Server.IdleTimeout = 120 * time.Second
	}
	if cfg.Logging.Level == "" {
		cfg.Logging.Level = "info"
	}
	if cfg.Logging.Format == "" {
		cfg.Logging.Format = "json"
	}

	// WireGuard defaults
	if cfg.WireGuard.Interface == "" {
		cfg.WireGuard.Interface = "wg0"
	}
	if cfg.WireGuard.Address == "" {
		cfg.WireGuard.Address = "10.8.0.1/24"
	}
	if cfg.WireGuard.ListenPort == 0 {
		cfg.WireGuard.ListenPort = 51820
	}
	if cfg.WireGuard.MTU == 0 {
		cfg.WireGuard.MTU = 1420
	}

	return &cfg, nil
}

// Validate checks if the configuration is valid
func (c *Config) Validate() error {
	if c.JWT.Secret == "" {
		return ErrMissingJWTSecret
	}
	if c.OrbNet.Endpoint == "" {
		return ErrMissingOrbNetEndpoint
	}
	if c.Server.CertFile == "" {
		return ErrMissingCertFile
	}
	if c.Server.KeyFile == "" {
		return ErrMissingKeyFile
	}
	return nil
}

// Errors
var (
	ErrMissingJWTSecret      = &ConfigError{"JWT secret is required"}
	ErrMissingOrbNetEndpoint = &ConfigError{"OrbNet endpoint is required"}
	ErrMissingCertFile       = &ConfigError{"TLS certificate file is required"}
	ErrMissingKeyFile        = &ConfigError{"TLS key file is required"}
)

// ConfigError represents a configuration error
type ConfigError struct {
	Message string
}

func (e *ConfigError) Error() string {
	return "config error: " + e.Message
}
