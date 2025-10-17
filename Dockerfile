# Build stage
FROM golang:1.24-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates wireguard-tools iptables

WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build with optimizations
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s -X main.version=1.0.0 -X main.buildTime=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    -a -installsuffix cgo \
    -o orbx-protocol \
    ./cmd/server

# Final stage
FROM alpine:latest

# Install runtime dependencies
RUN apk --no-cache add \
    ca-certificates \
    tzdata \
    wireguard-tools \
    iptables \
    iproute2 \
    openssl \
    bash

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/orbx-protocol .

# Copy configuration template
COPY configs/config.yaml /etc/orbx/config.yaml

# Create directories with proper permissions
RUN mkdir -p /etc/orbx/certs && \
    chmod 755 /etc/orbx && \
    chmod 700 /etc/orbx/certs

# Create entrypoint script
RUN cat > /app/entrypoint.sh <<'EOF'
#!/bin/bash
set -e

# Setup TLS certificates from environment variables
if [ -n "$TLS_CERT" ] && [ -n "$TLS_KEY" ]; then
    echo "Setting up TLS certificates..."
    echo "$TLS_CERT" | base64 -d > /etc/orbx/certs/cert.pem
    echo "$TLS_KEY" | base64 -d > /etc/orbx/certs/key.pem
    chmod 600 /etc/orbx/certs/*.pem
    echo "✓ TLS certificates configured"
else
    echo "WARNING: TLS_CERT or TLS_KEY not provided"
    exit 1
fi

# Setup WireGuard
if [ "$WIREGUARD_ENABLED" = "true" ]; then
    echo "Configuring WireGuard..."
    
    # Enable IP forwarding
    echo 1 > /proc/sys/net/ipv4/ip_forward
    
    # Setup WireGuard interface
    ip link add dev wg0 type wireguard || true
    ip address add dev wg0 10.8.0.1/24 || true
    
    # Configure WireGuard with private key from environment
    if [ -n "$WG_PRIVATE_KEY" ]; then
        echo "$WG_PRIVATE_KEY" | wg set wg0 private-key /dev/stdin
        ip link set up dev wg0
        echo "✓ WireGuard configured (Public Key: $(wg show wg0 public-key))"
    else
        echo "WARNING: WG_PRIVATE_KEY not provided"
    fi
    
    # Setup NAT for VPN traffic
    iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE || true
    iptables -A FORWARD -i wg0 -j ACCEPT || true
    iptables -A FORWARD -o wg0 -j ACCEPT || true
fi

# Print configuration
echo "========================================"
echo "OrbX Protocol Server"
echo "========================================"
echo "Version: 1.0.0"
echo "Protocols: WireGuard, Teams, Google, Shaparak, DoH, HTTPS"
echo "Quantum-Safe: Enabled"
echo "WireGuard: $WIREGUARD_ENABLED"
if [ "$WIREGUARD_ENABLED" = "true" ] && [ -n "$WG_PUBLIC_KEY" ]; then
    echo "WireGuard Public Key: $WG_PUBLIC_KEY"
fi
echo "========================================"

# Start OrbX server
exec /app/orbx-protocol -config /etc/orbx/config.yaml
EOF

RUN chmod +x /app/entrypoint.sh

# Expose ports
EXPOSE 8443 51820/udp

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider https://localhost:8443/health || exit 1

# Run as root (required for WireGuard)
# Security note: WireGuard requires NET_ADMIN capability
ENTRYPOINT ["/app/entrypoint.sh"]