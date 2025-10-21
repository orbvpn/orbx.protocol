#!/bin/bash

# Fixed deployment script with proper secret injection
# Location: deployments/azure/scripts/deploy-container.sh

set -e

# Configuration
RESOURCE_GROUP="orbx-production-rg"
ACR_NAME="orbxregistry"
KEYVAULT_NAME="orbx-vault"
CONTAINER_NAME="orbx-protocol"
DNS_NAME="orbx-protocol"
LOCATION="eastus"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}☁️  Deploying OrbX Protocol to Azure${NC}"
echo "=============================================="

# Get all secrets from Key Vault
echo -e "\n${YELLOW}🔑 Retrieving secrets from Key Vault...${NC}"
JWT_SECRET=$(az keyvault secret show --vault-name $KEYVAULT_NAME --name "JWT-SECRET" --query value -o tsv)
ORBNET_API_KEY=$(az keyvault secret show --vault-name $KEYVAULT_NAME --name "ORBNET-API-KEY" --query value -o tsv)
ORBNET_ENDPOINT=$(az keyvault secret show --vault-name $KEYVAULT_NAME --name "ORBNET-ENDPOINT" --query value -o tsv)
ACR_USERNAME=$(az keyvault secret show --vault-name $KEYVAULT_NAME --name "ACR-USERNAME" --query value -o tsv)
ACR_PASSWORD=$(az keyvault secret show --vault-name $KEYVAULT_NAME --name "ACR-PASSWORD" --query value -o tsv)
WG_PRIVATE_KEY=$(az keyvault secret show --vault-name $KEYVAULT_NAME --name "WG-PRIVATE-KEY" --query value -o tsv)
WG_PUBLIC_KEY=$(az keyvault secret show --vault-name $KEYVAULT_NAME --name "WG-PUBLIC-KEY" --query value -o tsv)
TLS_CERT=$(az keyvault secret show --vault-name $KEYVAULT_NAME --name "TLS-CERT" --query value -o tsv)
TLS_KEY=$(az keyvault secret show --vault-name $KEYVAULT_NAME --name "TLS-KEY" --query value -o tsv)

# Decode TLS cert and key from base64
TLS_CERT_DECODED=$(echo "$TLS_CERT" | base64 -d)
TLS_KEY_DECODED=$(echo "$TLS_KEY" | base64 -d)

# Create config file with embedded secrets
echo -e "\n${YELLOW}📝 Creating configuration...${NC}"
cat >/tmp/orbx-config.yaml <<EOF
server:
  host: "0.0.0.0"
  port: "8443"
  cert_file: "/etc/orbx/certs/cert.pem"
  key_file: "/etc/orbx/certs/key.pem"
  read_timeout: 30s
  write_timeout: 30s
  idle_timeout: 120s

jwt:
  secret: "$JWT_SECRET"

orbnet:
  endpoint: "$ORBNET_ENDPOINT"
  api_key: "$ORBNET_API_KEY"

crypto:
  quantum_safe: true
  lattice_enabled: true
  timing_enabled: true

wireguard:
  enabled: true
  interface_name: "wg0"
  listen_port: 51820
  private_key: "$WG_PRIVATE_KEY"
  ip_pool: "10.8.0.0/24"
  dns:
    - "1.1.1.1"
    - "1.0.0.1"
  mtu: 1420
  persistent_keepalive: 25
  public_interface: "eth0"

logging:
  level: "info"
  format: "json"
EOF

# Create init script to setup certs
echo -e "\n${YELLOW}📜 Creating initialization script...${NC}"
cat >/tmp/init.sh <<'INITEOF'
#!/bin/sh
mkdir -p /etc/orbx/certs
echo "$TLS_CERT" | base64 -d > /etc/orbx/certs/cert.pem
echo "$TLS_KEY" | base64 -d > /etc/orbx/certs/key.pem
chmod 600 /etc/orbx/certs/*.pem
exec /app/orbx-protocol -config /etc/orbx/config.yaml
INITEOF

# Deploy container with proper configuration
echo -e "\n${YELLOW}🚀 Deploying container...${NC}"
az container create \
	--resource-group $RESOURCE_GROUP \
	--name $CONTAINER_NAME \
	--image $ACR_NAME.azurecr.io/orbx-protocol:latest \
	--dns-name-label $DNS_NAME \
	--ports 8443 51820 \
	--protocol TCP UDP \
	--cpu 2 \
	--memory 4 \
	--registry-login-server $ACR_NAME.azurecr.io \
	--registry-username $ACR_USERNAME \
	--registry-password $ACR_PASSWORD \
	--environment-variables \
	ORBNET_ENDPOINT="$ORBNET_ENDPOINT" \
	WIREGUARD_ENABLED="true" \
	--secure-environment-variables \
	JWT_SECRET="$JWT_SECRET" \
	ORBNET_API_KEY="$ORBNET_API_KEY" \
	WG_PRIVATE_KEY="$WG_PRIVATE_KEY" \
	WG_PUBLIC_KEY="$WG_PUBLIC_KEY" \
	TLS_CERT="$TLS_CERT" \
	TLS_KEY="$TLS_KEY" \
	--restart-policy Always \
	--command-line "/bin/sh -c 'mkdir -p /etc/orbx/certs && echo $TLS_CERT | base64 -d > /etc/orbx/certs/cert.pem && echo $TLS_KEY | base64 -d > /etc/orbx/certs/key.pem && chmod 600 /etc/orbx/certs/*.pem && /app/orbx-protocol -config /etc/orbx/config.yaml'"

echo -e "${GREEN}✅ Container deployed successfully${NC}"

# Get container details
echo -e "\n${YELLOW}📊 Container Status:${NC}"
az container show \
	--resource-group $RESOURCE_GROUP \
	--name $CONTAINER_NAME \
	--query "{FQDN:ipAddress.fqdn,IP:ipAddress.ip,ProvisioningState:provisioningState}" \
	--output table

# Get FQDN
FQDN=$(az container show \
	--resource-group $RESOURCE_GROUP \
	--name $CONTAINER_NAME \
	--query "ipAddress.fqdn" \
	--output tsv)

echo -e "\n${GREEN}============================================${NC}"
echo -e "${GREEN}🎉 Deployment Complete!${NC}"
echo -e "${GREEN}============================================${NC}"
echo -e "Server URL: ${YELLOW}https://$FQDN:8443${NC}"
echo -e "WireGuard: ${YELLOW}$FQDN:51820${NC}"
echo -e "Public Key: ${YELLOW}$WG_PUBLIC_KEY${NC}"
echo -e "\nTest endpoints:"
echo -e "${YELLOW}curl -k https://$FQDN:8443/health${NC}"
echo -e "${YELLOW}curl -k https://$FQDN:8443/metrics${NC}"
