#!/bin/bash

set -e

# ============================================
# Configuration Variables
# ============================================
RESOURCE_GROUP="orbx-production-rg"
LOCATION="eastus"
ACR_NAME="orbxregistry"
KEYVAULT_NAME="orbx-vault"
APP_NAME="orbx-protocol"
VNET_NAME="orbx-vnet"
SUBNET_NAME="orbx-subnet"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}🚀 Starting Azure Deployment for OrbX Server${NC}"
echo "=============================================="

# ============================================
# Step 1: Create Resource Group
# ============================================
echo -e "\n${YELLOW}📦 Step 1: Creating Resource Group...${NC}"
az group create \
  --name $RESOURCE_GROUP \
  --location $LOCATION \
  --tags Environment=Production Application=OrbX

echo -e "${GREEN}✅ Resource Group created${NC}"

# ============================================
# Step 2: Create Azure Container Registry
# ============================================
echo -e "\n${YELLOW}🐳 Step 2: Creating Container Registry...${NC}"
az acr create \
  --resource-group $RESOURCE_GROUP \
  --name $ACR_NAME \
  --sku Standard \
  --admin-enabled true

echo -e "${GREEN}✅ Container Registry created${NC}"

# Get ACR credentials
ACR_USERNAME=$(az acr credential show --name $ACR_NAME --query username -o tsv)
ACR_PASSWORD=$(az acr credential show --name $ACR_NAME --query passwords[0].value -o tsv)
ACR_LOGIN_SERVER="$ACR_NAME.azurecr.io"

echo -e "${GREEN}Registry: $ACR_LOGIN_SERVER${NC}"

# ============================================
# Step 3: Create Key Vault with proper permissions
# ============================================
echo -e "\n${YELLOW}🔐 Step 3: Creating Key Vault...${NC}"

# Get current user's object ID
USER_OBJECT_ID=$(az ad signed-in-user show --query id -o tsv)
echo "Current user object ID: $USER_OBJECT_ID"

# Create Key Vault
az keyvault create \
  --name $KEYVAULT_NAME \
  --resource-group $RESOURCE_GROUP \
  --location $LOCATION \
  --enable-rbac-authorization false \
  --enabled-for-deployment true \
  --enabled-for-template-deployment true

# Set access policy for current user
echo -e "\n${YELLOW}Setting Key Vault access policy...${NC}"
az keyvault set-policy \
  --name $KEYVAULT_NAME \
  --object-id $USER_OBJECT_ID \
  --secret-permissions get list set delete \
  --certificate-permissions get list create delete

echo -e "${GREEN}✅ Key Vault created with proper permissions${NC}"

# ============================================
# Step 4: Get OrbNet credentials
# ============================================
echo -e "\n${YELLOW}🔑 Step 4: OrbNet API Configuration...${NC}"
echo -e "${YELLOW}We'll register this server with OrbNet API and get credentials automatically${NC}"

# Prompt for OrbNet admin credentials (used once to register the server)
read -p "Enter OrbNet admin email: " ORBNET_ADMIN_EMAIL
read -sp "Enter OrbNet admin password: " ORBNET_ADMIN_PASSWORD
echo ""
read -p "Enter OrbNet API endpoint (default: https://api.orbvpn.com/graphql): " ORBNET_ENDPOINT
ORBNET_ENDPOINT=${ORBNET_ENDPOINT:-https://api.orbvpn.com/graphql}

# Login to OrbNet and get authentication token
echo -e "\n${YELLOW}Authenticating with OrbNet API...${NC}"
AUTH_RESPONSE=$(curl -s -X POST "$ORBNET_ENDPOINT" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "mutation Login($email: String!, $password: String!) { login(email: $email, password: $password) { token user { id email role } } }",
    "variables": {
      "email": "'"$ORBNET_ADMIN_EMAIL"'",
      "password": "'"$ORBNET_ADMIN_PASSWORD"'"
    }
  }')

# Extract token
AUTH_TOKEN=$(echo $AUTH_RESPONSE | jq -r '.data.login.token')

if [ "$AUTH_TOKEN" = "null" ] || [ -z "$AUTH_TOKEN" ]; then
  echo -e "${RED}❌ Failed to authenticate with OrbNet API${NC}"
  echo "Response: $AUTH_RESPONSE"
  exit 1
fi

echo -e "${GREEN}✅ Authenticated with OrbNet API${NC}"

# Register the server and get credentials
echo -e "\n${YELLOW}Registering OrbX server with OrbNet...${NC}"
REGISTER_RESPONSE=$(curl -s -X POST "$ORBNET_ENDPOINT" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $AUTH_TOKEN" \
  -d '{
    "query": "mutation RegisterOrbxServer($input: OrbxServerInput!) { registerOrbxServer(input: $input) { id name region endpoint apiKey jwtSecret publicKey status } }",
    "variables": {
      "input": {
        "name": "OrbX - East US",
        "region": "eastus",
        "endpoint": "https://orbx-eastus.azurecontainer.io:8443",
        "status": "PROVISIONING"
      }
    }
  }')

# Extract credentials from response
ORBNET_API_KEY=$(echo $REGISTER_RESPONSE | jq -r '.data.registerOrbxServer.apiKey')
JWT_SECRET=$(echo $REGISTER_RESPONSE | jq -r '.data.registerOrbxServer.jwtSecret')
ORBNET_SERVER_ID=$(echo $REGISTER_RESPONSE | jq -r '.data.registerOrbxServer.id')

if [ "$ORBNET_API_KEY" = "null" ] || [ -z "$ORBNET_API_KEY" ]; then
  echo -e "${RED}❌ Failed to register server with OrbNet API${NC}"
  echo "Response: $REGISTER_RESPONSE"
  exit 1
fi

echo -e "${GREEN}✅ Server registered with OrbNet API${NC}"
echo -e "${GREEN}Server ID: $ORBNET_SERVER_ID${NC}"

# ============================================
# Step 5: Store secrets in Key Vault
# ============================================
echo -e "\n${YELLOW}🔐 Step 5: Storing secrets in Key Vault...${NC}"

# Store JWT Secret
az keyvault secret set \
  --vault-name $KEYVAULT_NAME \
  --name "JWT-SECRET" \
  --value "$JWT_SECRET"

# Store OrbNet API Key
az keyvault secret set \
  --vault-name $KEYVAULT_NAME \
  --name "ORBNET-API-KEY" \
  --value "$ORBNET_API_KEY"

# Store OrbNet Endpoint
az keyvault secret set \
  --vault-name $KEYVAULT_NAME \
  --name "ORBNET-ENDPOINT" \
  --value "$ORBNET_ENDPOINT"

# Store OrbNet Server ID
az keyvault secret set \
  --vault-name $KEYVAULT_NAME \
  --name "ORBNET-SERVER-ID" \
  --value "$ORBNET_SERVER_ID"

# Store ACR credentials
az keyvault secret set \
  --vault-name $KEYVAULT_NAME \
  --name "ACR-USERNAME" \
  --value "$ACR_USERNAME"

az keyvault secret set \
  --vault-name $KEYVAULT_NAME \
  --name "ACR-PASSWORD" \
  --value "$ACR_PASSWORD"

echo -e "${GREEN}✅ Secrets stored in Key Vault${NC}"

# ============================================
# Step 6: Create Virtual Network
# ============================================
echo -e "\n${YELLOW}🌐 Step 6: Creating Virtual Network...${NC}"
az network vnet create \
  --resource-group $RESOURCE_GROUP \
  --name $VNET_NAME \
  --address-prefix 10.0.0.0/16 \
  --subnet-name $SUBNET_NAME \
  --subnet-prefix 10.0.1.0/24

echo -e "${GREEN}✅ Virtual Network created${NC}"

# ============================================
# Summary
# ============================================
echo -e "\n${GREEN}============================================${NC}"
echo -e "${GREEN}✅ Azure Setup Complete!${NC}"
echo -e "${GREEN}============================================${NC}"
echo -e "Resource Group: ${YELLOW}$RESOURCE_GROUP${NC}"
echo -e "Container Registry: ${YELLOW}$ACR_LOGIN_SERVER${NC}"
echo -e "Key Vault: ${YELLOW}$KEYVAULT_NAME${NC}"
echo -e "OrbNet Server ID: ${YELLOW}$ORBNET_SERVER_ID${NC}"
echo -e "\n${YELLOW}Next steps:${NC}"
echo -e "1. Generate TLS certificates: ${YELLOW}./generate-tls-certs.sh${NC}"
echo -e "2. Generate WireGuard keys: ${YELLOW}./generate-wireguard-keys.sh${NC}"
echo -e "3. Build Docker image: ${YELLOW}./build-and-push.sh${NC}"
echo -e "4. Deploy container: ${YELLOW}./deploy-container.sh${NC}"