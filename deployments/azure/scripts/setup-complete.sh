#!/bin/bash

# Complete Azure + OrbNet setup with automatic registration
# This script handles everything from scratch

set -e

RESOURCE_GROUP="orbx-production-rg"
LOCATION="eastus"
ACR_NAME="orbxregistry"
KEYVAULT_NAME="orbx-vault"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}🚀 Complete OrbX Azure Setup${NC}"
echo "=============================================="

# ============================================
# Step 0: Cleanup any existing soft-deleted vault
# ============================================
echo -e "\n${YELLOW}🧹 Checking for existing Key Vault...${NC}"
VAULT_STATUS=$(az keyvault list-deleted --query "[?name=='$KEYVAULT_NAME'].name" -o tsv 2>/dev/null || echo "")

if [ ! -z "$VAULT_STATUS" ]; then
  echo -e "${YELLOW}Found soft-deleted Key Vault. Purging...${NC}"
  az keyvault purge --name $KEYVAULT_NAME || true
  sleep 10
  echo -e "${GREEN}✅ Old Key Vault purged${NC}"
fi

# ============================================
# Step 1: Create Resource Group
# ============================================
echo -e "\n${YELLOW}📦 Step 1: Creating Resource Group...${NC}"
az group create \
  --name $RESOURCE_GROUP \
  --location $LOCATION \
  --tags Environment=Production Application=OrbX \
  --output none

echo -e "${GREEN}✅ Resource Group created${NC}"

# ============================================
# Step 2: Create Container Registry
# ============================================
echo -e "\n${YELLOW}🐳 Step 2: Creating Container Registry...${NC}"
az acr create \
  --resource-group $RESOURCE_GROUP \
  --name $ACR_NAME \
  --sku Standard \
  --admin-enabled true \
  --output none

ACR_USERNAME=$(az acr credential show --name $ACR_NAME --query username -o tsv)
ACR_PASSWORD=$(az acr credential show --name $ACR_NAME --query passwords[0].value -o tsv)

echo -e "${GREEN}✅ Container Registry created: $ACR_NAME.azurecr.io${NC}"

# ============================================
# Step 3: Create Key Vault (with access policies)
# ============================================
echo -e "\n${YELLOW}🔐 Step 3: Creating Key Vault...${NC}"

USER_OBJECT_ID=$(az ad signed-in-user show --query id -o tsv)

az keyvault create \
  --name $KEYVAULT_NAME \
  --resource-group $RESOURCE_GROUP \
  --location $LOCATION \
  --enable-rbac-authorization false \
  --enabled-for-deployment true \
  --enabled-for-template-deployment true \
  --output none

# Set access policy immediately
az keyvault set-policy \
  --name $KEYVAULT_NAME \
  --object-id $USER_OBJECT_ID \
  --secret-permissions get list set delete purge recover \
  --certificate-permissions get list create delete \
  --output none

echo -e "${GREEN}✅ Key Vault created with permissions${NC}"

# ============================================
# Step 4: Store ACR credentials
# ============================================
echo -e "\n${YELLOW}💾 Storing ACR credentials...${NC}"
az keyvault secret set --vault-name $KEYVAULT_NAME --name "ACR-USERNAME" --value "$ACR_USERNAME" --output none
az keyvault secret set --vault-name $KEYVAULT_NAME --name "ACR-PASSWORD" --value "$ACR_PASSWORD" --output none

# ============================================
# Step 5: OrbNet API Integration
# ============================================
echo -e "\n${YELLOW}🔑 Step 5: OrbNet API Integration${NC}"
echo -e "${YELLOW}We need your OrbNet admin credentials to register servers${NC}"
echo ""

read -p "Enter OrbNet admin email: " ORBNET_ADMIN_EMAIL
read -sp "Enter OrbNet admin password: " ORBNET_ADMIN_PASSWORD
echo ""
read -p "Enter OrbNet API endpoint [https://api.orbvpn.com/graphql]: " ORBNET_ENDPOINT
ORBNET_ENDPOINT=${ORBNET_ENDPOINT:-https://api.orbvpn.com/graphql}

# Login to OrbNet API
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

AUTH_TOKEN=$(echo $AUTH_RESPONSE | jq -r '.data.login.token' 2>/dev/null || echo "null")

if [ "$AUTH_TOKEN" = "null" ] || [ -z "$AUTH_TOKEN" ]; then
  echo -e "${RED}❌ Authentication failed${NC}"
  echo "Response: $AUTH_RESPONSE"
  echo ""
  echo "Please check:"
  echo "1. Email and password are correct"
  echo "2. OrbNet API endpoint is accessible"
  echo "3. You have admin access in OrbNet"
  exit 1
fi

echo -e "${GREEN}✅ Authenticated with OrbNet API${NC}"

# Store auth token for later use
az keyvault secret set --vault-name $KEYVAULT_NAME --name "ORBNET-AUTH-TOKEN" --value "$AUTH_TOKEN" --output none
az keyvault secret set --vault-name $KEYVAULT_NAME --name "ORBNET-ENDPOINT" --value "$ORBNET_ENDPOINT" --output none

echo -e "${GREEN}✅ OrbNet credentials stored${NC}"

# ============================================
# Step 6: Create Virtual Network
# ============================================
echo -e "\n${YELLOW}🌐 Step 6: Creating Virtual Network...${NC}"
az network vnet create \
  --resource-group $RESOURCE_GROUP \
  --name orbx-vnet \
  --address-prefix 10.0.0.0/16 \
  --subnet-name orbx-subnet \
  --subnet-prefix 10.0.1.0/24 \
  --output none

echo -e "${GREEN}✅ Virtual Network created${NC}"

# ============================================
# Summary
# ============================================
echo -e "\n${GREEN}============================================${NC}"
echo -e "${GREEN}✅ Azure Setup Complete!${NC}"
echo -e "${GREEN}============================================${NC}"
echo ""
echo -e "📦 Resource Group: ${YELLOW}$RESOURCE_GROUP${NC}"
echo -e "🐳 Container Registry: ${YELLOW}$ACR_NAME.azurecr.io${NC}"
echo -e "🔐 Key Vault: ${YELLOW}$KEYVAULT_NAME${NC}"
echo -e "🔑 OrbNet: ${YELLOW}Connected${NC}"
echo ""
echo -e "${GREEN}Secrets stored in Key Vault:${NC}"
echo "  ✓ ACR-USERNAME"
echo "  ✓ ACR-PASSWORD"
echo "  ✓ ORBNET-AUTH-TOKEN"
echo "  ✓ ORBNET-ENDPOINT"
echo ""
echo -e "${YELLOW}Next steps:${NC}"
echo -e "1. Generate TLS certificates: ${YELLOW}./generate-tls-certs.sh${NC}"
echo -e "2. Generate WireGuard keys: ${YELLOW}./generate-wireguard-keys.sh${NC}"
echo -e "3. Build Docker image: ${YELLOW}./build-and-push.sh${NC}"
echo -e "4. Deploy to regions: ${YELLOW}./deploy-single-region.sh eastus${NC}"
echo ""
echo -e "${GREEN}Ready for deployment! 🚀${NC}"