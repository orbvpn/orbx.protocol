#!/bin/bash

# Deploy OrbX server to a single region with automatic OrbNet registration
# Usage: ./deploy-single-region.sh <region> [resource-group-name]

set -e

# Configuration
REGION=${1:-eastus}
RESOURCE_GROUP=${2:-"orbx-${REGION}-rg"}
ACR_NAME="orbxregistry"
KEYVAULT_NAME="orbx-vault"
CONTAINER_NAME="orbx-${REGION}"
DNS_NAME="orbx-${REGION}"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}☁️  Deploying OrbX Protocol to ${REGION}${NC}"
echo "=============================================="

# ============================================
# Step 1: Get shared secrets from Key Vault
# ============================================
echo -e "\n${YELLOW}🔑 Retrieving shared secrets from Key Vault...${NC}"
ORBNET_ENDPOINT=$(az keyvault secret show --vault-name $KEYVAULT_NAME --name "ORBNET-ENDPOINT" --query value -o tsv)
ACR_USERNAME=$(az keyvault secret show --vault-name $KEYVAULT_NAME --name "ACR-USERNAME" --query value -o tsv)
ACR_PASSWORD=$(az keyvault secret show --vault-name $KEYVAULT_NAME --name "ACR-PASSWORD" --query value -o tsv)
WG_PRIVATE_KEY=$(az keyvault secret show --vault-name $KEYVAULT_NAME --name "WG-PRIVATE-KEY" --query value -o tsv)
WG_PUBLIC_KEY=$(az keyvault secret show --vault-name $KEYVAULT_NAME --name "WG-PUBLIC-KEY" --query value -o tsv)
TLS_CERT=$(az keyvault secret show --vault-name $KEYVAULT_NAME --name "TLS-CERT" --query value -o tsv)
TLS_KEY=$(az keyvault secret show --vault-name $KEYVAULT_NAME --name "TLS-KEY" --query value -o tsv)

# Get auth token from Key Vault (stored during setup)
ORBNET_AUTH_TOKEN=$(az keyvault secret show --vault-name $KEYVAULT_NAME --name "ORBNET-AUTH-TOKEN" --query value -o tsv)

# ============================================
# Step 2: Register this server with OrbNet API
# ============================================
echo -e "\n${YELLOW}📝 Registering server with OrbNet API...${NC}"

# Generate the endpoint URL
ENDPOINT_URL="https://${DNS_NAME}.${REGION}.azurecontainer.io:8443"

# Register server via GraphQL
REGISTER_RESPONSE=$(curl -s -X POST "$ORBNET_ENDPOINT" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ORBNET_AUTH_TOKEN" \
  -d '{
    "query": "mutation RegisterOrbxServer($input: OrbxServerInput!) { registerOrbxServer(input: $input) { id name region endpoint apiKey jwtSecret publicKey status } }",
    "variables": {
      "input": {
        "name": "OrbX - '"${REGION}"'",
        "region": "'"${REGION}"'",
        "endpoint": "'"${ENDPOINT_URL}"'",
        "publicKey": "'"${WG_PUBLIC_KEY}"'",
        "status": "PROVISIONING"
      }
    }
  }')

# Extract credentials
ORBNET_API_KEY=$(echo $REGISTER_RESPONSE | jq -r '.data.registerOrbxServer.apiKey')
JWT_SECRET=$(echo $REGISTER_RESPONSE | jq -r '.data.registerOrbxServer.jwtSecret')
ORBNET_SERVER_ID=$(echo $REGISTER_RESPONSE | jq -r '.data.registerOrbxServer.id')

if [ "$ORBNET_API_KEY" = "null" ] || [ -z "$ORBNET_API_KEY" ]; then
  echo -e "${RED}❌ Failed to register server with OrbNet API${NC}"
  echo "Response: $REGISTER_RESPONSE"
  exit 1
fi

echo -e "${GREEN}✅ Server registered with OrbNet${NC}"
echo -e "${GREEN}Server ID: ${ORBNET_SERVER_ID}${NC}"
echo -e "${GREEN}Region: ${REGION}${NC}"

# ============================================
# Step 3: Create resource group for this region
# ============================================
echo -e "\n${YELLOW}📦 Creating resource group for ${REGION}...${NC}"
az group create \
  --name $RESOURCE_GROUP \
  --location $REGION \
  --tags Environment=Production Application=OrbX Region=$REGION

# ============================================
# Step 4: Deploy container
# ============================================
echo -e "\n${YELLOW}🚀 Deploying container to ${REGION}...${NC}"
az container create \
  --resource-group $RESOURCE_GROUP \
  --name $CONTAINER_NAME \
  --image $ACR_NAME.azurecr.io/orbx-protocol:latest \
  --dns-name-label $DNS_NAME \
  --location $REGION \
  --ports 8443 51820 \
  --protocol TCP UDP \
  --cpu 2 \
  --memory 4 \
  --registry-login-server $ACR_NAME.azurecr.io \
  --registry-username $ACR_USERNAME \
  --registry-password $ACR_PASSWORD \
  --environment-variables \
    ORBNET_ENDPOINT="$ORBNET_ENDPOINT" \
    ORBNET_SERVER_ID="$ORBNET_SERVER_ID" \
    WIREGUARD_ENABLED="true" \
  --secure-environment-variables \
    JWT_SECRET="$JWT_SECRET" \
    ORBNET_API_KEY="$ORBNET_API_KEY" \
    WG_PRIVATE_KEY="$WG_PRIVATE_KEY" \
    WG_PUBLIC_KEY="$WG_PUBLIC_KEY" \
    TLS_CERT="$TLS_CERT" \
    TLS_KEY="$TLS_KEY" \
  --restart-policy Always \
  --command-line "/bin/sh -c 'mkdir -p /etc/orbx/certs && echo \$TLS_CERT | base64 -d > /etc/orbx/certs/cert.pem && echo \$TLS_KEY | base64 -d > /etc/orbx/certs/key.pem && chmod 600 /etc/orbx/certs/*.pem && /app/orbx-protocol -config /etc/orbx/config.yaml'"

echo -e "${GREEN}✅ Container deployed${NC}"

# ============================================
# Step 5: Wait for container to start
# ============================================
echo -e "\n${YELLOW}⏳ Waiting for container to start...${NC}"
sleep 30

# Get FQDN
FQDN=$(az container show \
  --resource-group $RESOURCE_GROUP \
  --name $CONTAINER_NAME \
  --query "ipAddress.fqdn" \
  --output tsv)

# ============================================
# Step 6: Health check
# ============================================
echo -e "\n${YELLOW}🔍 Running health check...${NC}"
HEALTH_RESPONSE=$(curl -k -s "https://$FQDN:8443/health" || echo "failed")

if echo "$HEALTH_RESPONSE" | grep -q "healthy"; then
  echo -e "${GREEN}✅ Health check PASSED${NC}"
  
  # Update server status in OrbNet to ONLINE
  curl -s -X POST "$ORBNET_ENDPOINT" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $ORBNET_AUTH_TOKEN" \
    -d '{
      "query": "mutation UpdateOrbxServerStatus($id: ID!, $status: ServerStatus!) { updateOrbxServerStatus(id: $id, status: $status) { id status } }",
      "variables": {
        "id": "'"$ORBNET_SERVER_ID"'",
        "status": "ONLINE"
      }
    }' > /dev/null
  
  echo -e "${GREEN}✅ Server status updated to ONLINE in OrbNet${NC}"
else
  echo -e "${RED}❌ Health check FAILED${NC}"
  echo "Response: $HEALTH_RESPONSE"
  
  # Update server status to ERROR
  curl -s -X POST "$ORBNET_ENDPOINT" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $ORBNET_AUTH_TOKEN" \
    -d '{
      "query": "mutation UpdateOrbxServerStatus($id: ID!, $status: ServerStatus!) { updateOrbxServerStatus(id: $id, status: $status) { id status } }",
      "variables": {
        "id": "'"$ORBNET_SERVER_ID"'",
        "status": "ERROR"
      }
    }' > /dev/null
fi

# ============================================
# Summary
# ============================================
echo -e "\n${GREEN}============================================${NC}"
echo -e "${GREEN}🎉 Deployment Complete!${NC}"
echo -e "${GREEN}============================================${NC}"
echo -e "Region: ${YELLOW}${REGION}${NC}"
echo -e "Server ID: ${YELLOW}${ORBNET_SERVER_ID}${NC}"
echo -e "Server URL: ${YELLOW}https://$FQDN:8443${NC}"
echo -e "WireGuard: ${YELLOW}$FQDN:51820${NC}"
echo -e "Public Key: ${YELLOW}$WG_PUBLIC_KEY${NC}"
echo -e "\nTest endpoints:"
echo -e "${YELLOW}curl -k https://$FQDN:8443/health${NC}"
echo -e "${YELLOW}curl -k https://$FQDN:8443/metrics${NC}"

# Save deployment info
echo "$FQDN|$ORBNET_SERVER_ID|$REGION|$WG_PUBLIC_KEY" >> deployed-servers.txt