#!/bin/bash

set -e

# Go to project root
cd /Users/nima/Developments/orbx-protocol

echo "🏗️  Building production image with embedded certificates..."

# Build production image with embedded certs
docker build -f - -t orbxregistry.azurecr.io/orbx-protocol:prod . << 'EOF'
FROM orbxregistry.azurecr.io/orbx-protocol:latest

# Copy certificates from local context
COPY deployments/azure/scripts/certs/cert.pem /etc/orbx/certs/cert.pem
COPY deployments/azure/scripts/certs/key.pem /etc/orbx/certs/key.pem
RUN chmod 600 /etc/orbx/certs/*.pem

# Simplified entrypoint that doesn't decode from env vars
RUN cat > /app/entrypoint-prod.sh <<'ENTRY'
#!/bin/bash
set -e

echo "========================================"
echo "OrbX Protocol Server"
echo "========================================"

# Verify certs exist
if [ ! -f /etc/orbx/certs/cert.pem ] || [ ! -f /etc/orbx/certs/key.pem ]; then
    echo "ERROR: TLS certificates not found!"
    exit 1
fi
echo "✓ TLS certificates found"

# Setup WireGuard if enabled
if [ "$WIREGUARD_ENABLED" = "true" ] && [ -n "$WG_PRIVATE_KEY" ]; then
    echo "Configuring WireGuard..."
    echo 1 > /proc/sys/net/ipv4/ip_forward || true
    ip link add dev wg0 type wireguard 2>/dev/null || true
    ip address add dev wg0 10.8.0.1/24 2>/dev/null || true
    echo "$WG_PRIVATE_KEY" | wg set wg0 private-key /dev/stdin 2>/dev/null || true
    ip link set up dev wg0 2>/dev/null || true
    if [ $? -eq 0 ]; then
        echo "✓ WireGuard configured"
    else
        echo "⚠ WireGuard setup failed (may need privileged mode)"
    fi
fi

echo "Starting OrbX Protocol Server..."
echo "========================================"
exec /app/orbx-protocol -config /etc/orbx/config.yaml
ENTRY

RUN chmod +x /app/entrypoint-prod.sh

ENTRYPOINT ["/app/entrypoint-prod.sh"]
EOF

echo "✅ Image built!"
echo "📤 Pushing to registry..."

# Push to registry
docker push orbxregistry.azurecr.io/orbx-protocol:prod

echo "✅ Production image with embedded certificates is ready!"
echo "You can now deploy with: ./deploy-single-region.sh eastus"
