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
TLS_CERT=$(az keyvault secret show --vault-name $KEYVAULT_NAME --name "TLS-CERT" --query value -o tsv)
TLS_KEY=$(az keyvault secret show --vault-name $KEYVAULT_NAME --name "TLS-KEY" --query value -o tsv)

# Get auth token from Key Vault (stored during setup)
ORBNET_AUTH_TOKEN=$(az keyvault secret show --vault-name $KEYVAULT_NAME --name "ORBNET-AUTH-TOKEN" --query value -o tsv)

# Generate UNIQUE WireGuard keys for this region
echo -e "\n${YELLOW}🔑 Generating unique WireGuard keys for ${REGION}...${NC}"
WG_PRIVATE_KEY=$(wg genkey)
WG_PUBLIC_KEY=$(echo "$WG_PRIVATE_KEY" | wg pubkey)
echo -e "${GREEN}✓ WireGuard keys generated for this region${NC}"
echo -e "${GREEN}Public Key: ${WG_PUBLIC_KEY}${NC}"

# ============================================
# Step 2: Register this server with OrbNet API
# ============================================
echo -e "\n${YELLOW}📝 Registering server with OrbNet API...${NC}"

# Generate hostname (without https:// or port)
HOSTNAME="${DNS_NAME}.${REGION}.azurecontainer.io"

# Map Azure region to country code
case $REGION in
  eastus|eastus2|westus|westus2|westus3|centralus|northcentralus|southcentralus|westcentralus)
    COUNTRY_CODE="US"
    LOCATION_NAME="United States"
    ;;
  canadacentral|canadaeast)
    COUNTRY_CODE="CA"
    LOCATION_NAME="Canada"
    ;;
  brazilsouth)
    COUNTRY_CODE="BR"
    LOCATION_NAME="Brazil"
    ;;
  northeurope)
    COUNTRY_CODE="IE"
    LOCATION_NAME="Ireland"
    ;;
  westeurope)
    COUNTRY_CODE="NL"
    LOCATION_NAME="Netherlands"
    ;;
  uksouth|ukwest)
    COUNTRY_CODE="GB"
    LOCATION_NAME="United Kingdom"
    ;;
  francecentral)
    COUNTRY_CODE="FR"
    LOCATION_NAME="France"
    ;;
  germanywestcentral)
    COUNTRY_CODE="DE"
    LOCATION_NAME="Germany"
    ;;
  norwayeast)
    COUNTRY_CODE="NO"
    LOCATION_NAME="Norway"
    ;;
  switzerlandnorth)
    COUNTRY_CODE="CH"
    LOCATION_NAME="Switzerland"
    ;;
  swedencentral)
    COUNTRY_CODE="SE"
    LOCATION_NAME="Sweden"
    ;;
  eastasia)
    COUNTRY_CODE="HK"
    LOCATION_NAME="Hong Kong"
    ;;
  southeastasia)
    COUNTRY_CODE="SG"
    LOCATION_NAME="Singapore"
    ;;
  japaneast|japanwest)
    COUNTRY_CODE="JP"
    LOCATION_NAME="Japan"
    ;;
  australiaeast|australiasoutheast)
    COUNTRY_CODE="AU"
    LOCATION_NAME="Australia"
    ;;
  centralindia|southindia)
    COUNTRY_CODE="IN"
    LOCATION_NAME="India"
    ;;
  uaenorth)
    COUNTRY_CODE="AE"
    LOCATION_NAME="UAE"
    ;;
  *)
    COUNTRY_CODE="US"
    LOCATION_NAME="Unknown"
    ;;
esac

# Register server via GraphQL (using correct schema)
# Add timestamp to make name unique
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
SERVER_NAME="OrbX-${COUNTRY_CODE}-${REGION}-${TIMESTAMP}"

REGISTER_RESPONSE=$(curl -s -X POST "$ORBNET_ENDPOINT" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ORBNET_AUTH_TOKEN" \
  -d '{
    "query": "mutation RegisterOrbXServer($input: OrbXServerInput!) { registerOrbXServer(input: $input) { server { id name region hostname } apiKey jwtSecret } }",
    "variables": {
      "input": {
        "name": "'"${SERVER_NAME}"'",
        "region": "'"${REGION}"'",
        "hostname": "'"${HOSTNAME}"'",
        "ipAddress": "'"${HOSTNAME}"'",
        "port": 8443,
        "location": "'"${LOCATION_NAME}"'",
        "country": "'"${COUNTRY_CODE}"'",
        "protocols": ["wireguard", "teams", "google-meet", "shaparak", "doh", "https"],
        "maxConnections": 1000,
        "publicKey": "'"${WG_PUBLIC_KEY}"'"
      }
    }
  }')

# Extract credentials
ORBNET_API_KEY=$(echo $REGISTER_RESPONSE | jq -r '.data.registerOrbXServer.apiKey')
JWT_SECRET=$(echo $REGISTER_RESPONSE | jq -r '.data.registerOrbXServer.jwtSecret')
ORBNET_SERVER_ID=$(echo $REGISTER_RESPONSE | jq -r '.data.registerOrbXServer.server.id')

if [ "$ORBNET_API_KEY" = "null" ] || [ -z "$ORBNET_API_KEY" ]; then
  # Check if error is because server already exists
  if echo "$REGISTER_RESPONSE" | grep -q "already exists"; then
    echo -e "${YELLOW}⚠️  Server name conflict detected${NC}"
    echo -e "${YELLOW}Creating server with unique timestamp...${NC}"
    
# Add more unique timestamp with process ID
    TIMESTAMP=$(date +%Y%m%d-%H%M%S)-$$
    SERVER_NAME="OrbX-${COUNTRY_CODE}-${REGION}-${TIMESTAMP}"
    
    # Try registering again with more unique name
    REGISTER_RESPONSE=$(curl -s -X POST "$ORBNET_ENDPOINT" \
      -H "Content-Type: application/json" \
      -H "Authorization: Bearer $ORBNET_AUTH_TOKEN" \
      -d '{
        "query": "mutation RegisterOrbXServer($input: OrbXServerInput!) { registerOrbXServer(input: $input) { server { id name region hostname } apiKey jwtSecret } }",
        "variables": {
          "input": {
            "name": "'"${SERVER_NAME}"'",
            "region": "'"${REGION}"'",
            "hostname": "'"${HOSTNAME}"'",
            "ipAddress": "'"${HOSTNAME}"'",
            "port": 8443,
            "location": "'"${LOCATION_NAME}"'",
            "country": "'"${COUNTRY_CODE}"'",
            "protocols": ["wireguard", "teams", "google-meet", "shaparak", "doh", "https"],
            "maxConnections": 1000,
            "publicKey": "'"${WG_PUBLIC_KEY}"'"
          }
        }
      }')
    
    ORBNET_API_KEY=$(echo $REGISTER_RESPONSE | jq -r '.data.registerOrbXServer.apiKey')
    JWT_SECRET=$(echo $REGISTER_RESPONSE | jq -r '.data.registerOrbXServer.jwtSecret')
    ORBNET_SERVER_ID=$(echo $REGISTER_RESPONSE | jq -r '.data.registerOrbXServer.server.id')
    
# DEBUG: Print what we got
echo -e "\n${YELLOW}=== DEBUG: API Response ===${NC}"
echo "Full response:"
echo $REGISTER_RESPONSE | jq '.'
echo ""
echo "Extracted values:"
echo "  ORBNET_API_KEY: ${ORBNET_API_KEY:0:20}... (length: ${#ORBNET_API_KEY})"
echo "  JWT_SECRET: ${JWT_SECRET:0:20}... (length: ${#JWT_SECRET})"
echo "  ORBNET_SERVER_ID: $ORBNET_SERVER_ID"
echo -e "${YELLOW}=========================${NC}\n"

    if [ "$ORBNET_API_KEY" = "null" ] || [ -z "$ORBNET_API_KEY" ]; then
      echo -e "${RED}❌ Still failed to register server${NC}"
      echo "Response: $REGISTER_RESPONSE"
      exit 1
    fi

    if [ -z "$JWT_SECRET" ] || [ "$JWT_SECRET" = "null" ]; then
      echo -e "${RED}❌ JWT Secret is empty or null!${NC}"
      echo "Full response: $REGISTER_RESPONSE"
      exit 1
    fi
    
    echo -e "${GREEN}✅ Server registered with unique name${NC}"
  else
    echo -e "${RED}❌ Failed to register server with OrbNet API${NC}"
    echo "Response: $REGISTER_RESPONSE"
    exit 1
  fi
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
# Step 4: Create YAML deployment file
# ============================================
echo -e "\n${YELLOW}📝 Creating deployment configuration...${NC}"

cat > /tmp/orbx-${REGION}-deploy.yaml <<EOF
apiVersion: '2021-09-01'
location: ${REGION}
name: ${CONTAINER_NAME}
properties:
  containers:
  - name: ${CONTAINER_NAME}
    properties:
      image: ${ACR_NAME}.azurecr.io/orbx-protocol:prod
      resources:
        requests:
          cpu: 2
          memoryInGB: 4
      ports:
      - port: 8443
        protocol: TCP
      - port: 51820
        protocol: TCP
      environmentVariables:
      - name: 'ORBNET_ENDPOINT'
        value: '${ORBNET_ENDPOINT}'
      - name: 'ORBNET_SERVER_ID'
        value: '${ORBNET_SERVER_ID}'
      - name: 'WIREGUARD_ENABLED'
        value: 'true'
      - name: 'JWT_SECRET'
        secureValue: '${JWT_SECRET}'
      - name: 'ORBNET_API_KEY'
        secureValue: '${ORBNET_API_KEY}'
      - name: 'WG_PRIVATE_KEY'
        secureValue: '${WG_PRIVATE_KEY}'
      - name: 'WG_PUBLIC_KEY'
        secureValue: '${WG_PUBLIC_KEY}'
      - name: 'TLS_CERT'
        secureValue: '${TLS_CERT}'
      - name: 'TLS_KEY'
        secureValue: '${TLS_KEY}'

  osType: Linux
  restartPolicy: Always
  ipAddress:
    type: Public
    dnsNameLabel: ${DNS_NAME}
    ports:
    - protocol: TCP
      port: 8443
    - protocol: TCP
      port: 51820
  imageRegistryCredentials:
  - server: ${ACR_NAME}.azurecr.io
    username: ${ACR_USERNAME}
    password: ${ACR_PASSWORD}
tags: {}
type: Microsoft.ContainerInstance/containerGroups
EOF

# ============================================
# Step 5: Deploy container using YAML
# ============================================
echo -e "\n${YELLOW}🚀 Deploying container to ${REGION}...${NC}"
az container create \
  --resource-group $RESOURCE_GROUP \
  --file /tmp/orbx-${REGION}-deploy.yaml

echo -e "${GREEN}✅ Container deployed${NC}"

# Cleanup temp file
rm -f /tmp/orbx-${REGION}-deploy.yaml

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
      "query": "mutation UpdateOrbXServerStatus($serverId: ID!, $online: Boolean!) { updateOrbXServerStatus(serverId: $serverId, online: $online) { id online } }",
      "variables": {
        "serverId": "'"$ORBNET_SERVER_ID"'",
        "online": true
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
      "query": "mutation UpdateOrbXServerStatus($serverId: ID!, $online: Boolean!) { updateOrbXServerStatus(serverId: $serverId, online: $online) { id online } }",
      "variables": {
        "serverId": "'"$ORBNET_SERVER_ID"'",
        "online": false
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