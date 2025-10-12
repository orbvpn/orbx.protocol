# OrbX Server

Post-quantum VPN obfuscation server with protocol mimicry for censorship circumvention.

## Features

- 🔐 **Post-Quantum Cryptography**: Kyber768 key exchange + hybrid TLS
- 🎭 **Protocol Mimicry**:

  - Microsoft Teams
  - Google Workspace (Drive, Meet, Calendar)
  - Shaparak (Iranian Banking)
  - DNS over HTTPS (DoH)
  - Fragmented HTTPS

- 🌐 **Lattice-Based Obfuscation**: Traffic pattern obfuscation
- ⏱️ **Timing Channel Protection**: Random delays and packet splitting
- 📊 **Usage Tracking**: Integrated with OrbNet GraphQL API
- 🚀 **High Performance**: Efficient Go implementation

## Architecture

┌─────────────┐
│ Clients │
└──────┬──────┘
│
│ (TLS 1.3 + Kyber768)
│
┌──────▼──────────────────────┐
│ OrbX Server │
│ ┌──────────────────────┐ │
│ │ Protocol Router │ │
│ ├──────────────────────┤ │
│ │ • Teams Handler │ │
│ │ • Shaparak Handler │ │
│ │ • DoH Handler │ │
│ │ • HTTPS Handler │ │
│ └──────────────────────┘ │
│ │ │
│ ┌────────▼────────────┐ │
│ │ Crypto Manager │ │
│ │ • Kyber768 │ │
│ │ • Lattice Obfusc. │ │
│ │ • Timing Obfusc. │ │
│ └─────────────────────┘ │
│ │ │
│ ┌────────▼────────────┐ │
│ │ Tunnel Manager │ │
│ │ • Session Mgmt │ │
│ │ • Packet Routing │ │
│ │ • Metrics │ │
│ └─────────────────────┘ │
│ │ │
│ ┌────────▼────────────┐ │
│ │ OrbNet Client │ │
│ │ • Usage Reporting │ │
│ │ • User Validation │ │
│ │ • Config Sync │ │
│ └─────────────────────┘ │
└─────────────────────────────┘
│
│ (GraphQL)
│
┌──────▼──────┐
│ OrbNet │
│ API │
└─────────────┘

## Quick Start

### Prerequisites

- Go 1.21 or higher
- TLS certificates
- OrbNet API access

### Installation

```bash
# Clone repository
git clone https://github.com/orbvpn/orbx.protocol
cd orbx.protocol

# Install dependencies
go mod tidy

# Build
go build -o orbx.protocol ./cmd/server
Configuration

Copy example config:

bashcp configs/config.yaml.example configs/config.yaml

Edit configs/config.yaml:

yamlserver:
  port: "8443"
  cert_file: "/path/to/cert.pem"
  key_file: "/path/to/key.pem"

jwt:
  secret: "your-jwt-secret"

orbnet:
  endpoint: "https://api.orbvpn.com/graphql"
  api_key: "your-api-key"

Set environment variables:

bashexport JWT_SECRET="your-jwt-secret"
export ORBNET_API_KEY="your-api-key"
Running
bash# Run server
./orbx.protocol -config configs/config.yaml

# Or with custom config
./orbx.protocol -config /path/to/config.yaml
API Endpoints
Health Check
bashGET /health
Metrics
bashGET /metrics
Protocol Endpoints
Teams Protocol
bashPOST /teams/messages
Authorization: Bearer <jwt-token>
Content-Type: application/json
X-Ms-Client-Version: 27/1.0.0.2024
POST /drive/files
POST /meet/join
POST /calendar/events
Authorization: Bearer <jwt-token>
Content-Type: application/json
X-Goog-Api-Client: gl-go/1.20.0 gdcl/0.110.0
Shaparak Protocol
bashPOST /shaparak/transaction
Authorization: Bearer <jwt-token>
Content-Type: text/xml
SOAPAction: ProcessTransaction
DNS over HTTPS
bashGET /dns-query?dns=<base64url>
Authorization: Bearer <jwt-token>

POST /dns-query
Authorization: Bearer <jwt-token>
Content-Type: application/dns-message
Fragmented HTTPS
bashPOST /tunnel
Authorization: Bearer <jwt-token>
Content-Type: application/octet-stream
Development
Project Structure
orbx.protocol/
├── cmd/
│   └── server/          # Main entry point
├── internal/
│   ├── auth/            # JWT authentication
│   ├── config/          # Configuration
│   ├── crypto/          # Cryptography
│   ├── protocol/        # Protocol handlers
│   ├── tunnel/          # Tunnel management
│   └── orbnet/          # OrbNet client
├── pkg/
│   └── models/          # Shared types
├── configs/             # Configuration files
└── deployments/         # Deployment scripts
Building
bash# Build for current platform
go build -o orbx.protocol ./cmd/server

# Build for Linux
GOOS=linux GOARCH=amd64 go build -o orbx.protocol-linux ./cmd/server

# Build for Windows
GOOS=windows GOARCH=amd64 go build -o orbx.protocol.exe ./cmd/server
Testing
bash# Run tests
go test ./...

# Run with coverage
go test -cover ./...

# Run specific package
go test ./internal/crypto
Deployment
Docker
dockerfile# Dockerfile included in project
docker build -t orbx.protocol .
docker run -p 8443:8443 -v /path/to/config:/etc/orbx orbx.protocol
Azure
bash# Deploy to Azure
./deployments/azure/scripts/deploy.sh
Security

TLS 1.3 required
Post-quantum key exchange (Kyber768)
JWT authentication
Rate limiting
Traffic obfuscation

License
Proprietary - OrbVPN
Support
For support, contact: support@orbvpn.com
```
