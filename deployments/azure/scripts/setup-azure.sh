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
echo -e "${YELLOW}We'll authenticate with OrbNet API for server registration${NC}"

# Prompt for OrbNet admin credentials
read -p "Enter OrbNet admin email: " ORBNET_ADMIN_EMAIL
read -sp "Enter OrbNet admin password: " ORBNET_ADMIN_PASSWORD
echo ""
read -p "Enter OrbNet API endpoint (default: https://orbnet.xyz/graphql): " ORBNET_ENDPOINT
ORBNET_ENDPOINT=${ORBNET_ENDPOINT:-https://orbnet.xyz/graphql}

# Login to OrbNet and get authentication token
echo -e "\n${YELLOW}Authenticating with OrbNet API...${NC}"
AUTH_RESPONSE=$(curl -s -X POST "$ORBNET_ENDPOINT" \
	-H "Content-Type: application/json" \
	-d '{
    "query": "mutation Login($email: String!, $password: String!) { login(email: $email, password: $password) { accessToken user { id email role } } }",
    "variables": {
      "email": "'"$ORBNET_ADMIN_EMAIL"'",
      "password": "'"$ORBNET_ADMIN_PASSWORD"'"
    }
  }')

# Extract token
ORBNET_AUTH_TOKEN=$(echo $AUTH_RESPONSE | jq -r '.data.login.accessToken')

if [ "$ORBNET_AUTH_TOKEN" = "null" ] || [ -z "$ORBNET_AUTH_TOKEN" ]; then
	echo -e "${RED}❌ Failed to authenticate with OrbNet API${NC}"
	echo "Response: $AUTH_RESPONSE"
	exit 1
fi

echo -e "${GREEN}✅ Authenticated with OrbNet API${NC}"

# Store OrbNet credentials in Key Vault
az keyvault secret set \
	--vault-name $KEYVAULT_NAME \
	--name "ORBNET-ENDPOINT" \
	--value "$ORBNET_ENDPOINT" >/dev/null

az keyvault secret set \
	--vault-name $KEYVAULT_NAME \
	--name "ORBNET-AUTH-TOKEN" \
	--value "$ORBNET_AUTH_TOKEN" >/dev/null

echo -e "${GREEN}✅ OrbNet credentials stored in Key Vault${NC}"
echo -e "${YELLOW}These credentials will be used by deploy scripts to register servers${NC}"

# ============================================
# Step 5: Store secrets in Key Vault
# ============================================
echo -e "\n${YELLOW}🔐 Step 5: Storing secrets in Key Vault...${NC}"

# ============================================
# Get SHARED JWT secret from OrbNet
# ============================================
echo -e "\n${YELLOW}🔐 Configuring SHARED JWT secret...${NC}"

# Check if OrbNet is running and get its JWT secret
ORBNET_JWT_SECRET=""

# Try to get from OrbNet's environment/config
if command -v docker &>/dev/null; then
	echo -e "${YELLOW}Checking if OrbNet container is running...${NC}"
	ORBNET_JWT_SECRET=$(docker exec orbnet-api printenv JWT_SECRET 2>/dev/null || echo "")
fi

# If not found, prompt user
if [ -z "$ORBNET_JWT_SECRET" ]; then
	echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
	echo -e "${YELLOW}IMPORTANT: JWT Secret Configuration${NC}"
	echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
	echo -e "This JWT secret must be the SAME secret that OrbNet API uses."
	echo -e "It's in your OrbNet's application.yaml or .env file as: ${GREEN}jwt.secret${NC}"
	echo ""
	echo -e "If you don't have one yet, generate a new one:"
	echo -e "${GREEN}openssl rand -base64 64${NC}"
	echo ""
	read -sp "Enter your SHARED JWT secret: " ORBNET_JWT_SECRET
	echo ""
fi

if [ -z "$ORBNET_JWT_SECRET" ]; then
	echo -e "${RED}❌ JWT secret cannot be empty!${NC}"
	exit 1
fi

# Store JWT secret in Key Vault
az keyvault secret set \
	--vault-name $KEYVAULT_NAME \
	--name "JWT-SECRET" \
	--value "$ORBNET_JWT_SECRET" >/dev/null

echo -e "${GREEN}✅ Shared JWT secret stored in Key Vault${NC}"
echo -e "${YELLOW}⚠️  Make sure this SAME secret is in OrbNet's application.yaml!${NC}"

# Store ACR credentials (retrieved in Step 2)
echo -e "\n${YELLOW}Storing Container Registry credentials...${NC}"

az keyvault secret set \
	--vault-name $KEYVAULT_NAME \
	--name "ACR-USERNAME" \
	--value "$ACR_USERNAME" >/dev/null

az keyvault secret set \
	--vault-name $KEYVAULT_NAME \
	--name "ACR-PASSWORD" \
	--value "$ACR_PASSWORD" >/dev/null

echo -e "${GREEN}✅ All secrets stored in Key Vault${NC}"

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
