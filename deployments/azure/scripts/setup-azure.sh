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
# Step 3: Create Key Vault
# ============================================
echo -e "\n${YELLOW}🔐 Step 3: Creating Key Vault...${NC}"
az keyvault create \
  --name $KEYVAULT_NAME \
  --resource-group $RESOURCE_GROUP \
  --location $LOCATION \
  --enabled-for-deployment true \
  --enabled-for-template-deployment true

echo -e "${GREEN}✅ Key Vault created${NC}"

# ============================================
# Step 4: Store Secrets in Key Vault
# ============================================
echo -e "\n${YELLOW}🔑 Step 4: Storing secrets...${NC}"

# Prompt for secrets
read -sp "Enter JWT_SECRET: " JWT_SECRET
echo
read -sp "Enter ORBNET_API_KEY: " ORBNET_API_KEY
echo
read -p "Enter ORBNET_ENDPOINT (default: https://orbnet.xyz/graphql): " ORBNET_ENDPOINT
ORBNET_ENDPOINT=${ORBNET_ENDPOINT:-https://orbnet.xyz/graphql}

# Store secrets
az keyvault secret set --vault-name $KEYVAULT_NAME --name "JWT-SECRET" --value "$JWT_SECRET"
az keyvault secret set --vault-name $KEYVAULT_NAME --name "ORBNET-API-KEY" --value "$ORBNET_API_KEY"
az keyvault secret set --vault-name $KEYVAULT_NAME --name "ORBNET-ENDPOINT" --value "$ORBNET_ENDPOINT"
az keyvault secret set --vault-name $KEYVAULT_NAME --name "ACR-USERNAME" --value "$ACR_USERNAME"
az keyvault secret set --vault-name $KEYVAULT_NAME --name "ACR-PASSWORD" --value "$ACR_PASSWORD"

echo -e "${GREEN}✅ Secrets stored in Key Vault${NC}"

# ============================================
# Step 5: Create Virtual Network
# ============================================
echo -e "\n${YELLOW}🌐 Step 5: Creating Virtual Network...${NC}"
az network vnet create \
  --resource-group $RESOURCE_GROUP \
  --name $VNET_NAME \
  --address-prefix 10.0.0.0/16 \
  --subnet-name $SUBNET_NAME \
  --subnet-prefix 10.0.1.0/24

echo -e "${GREEN}✅ Virtual Network created${NC}"

# ============================================
# Step 6: Generate TLS Certificate
# ============================================
echo -e "\n${YELLOW}🔒 Step 6: Generating TLS certificates...${NC}"

# Create local certs directory
mkdir -p certs

# Generate self-signed certificate (for testing)
# In production, use Azure App Service Certificate or Let's Encrypt
openssl req -x509 -newkey rsa:4096 -nodes \
  -keyout certs/key.pem \
  -out certs/cert.pem \
  -days 365 \
  -subj "/C=US/ST=State/L=City/O=OrbVPN/CN=orbx-protocol.eastus.azurecontainer.io"

# Upload certificates to Key Vault
CERT_BASE64=$(cat certs/cert.pem | base64)
KEY_BASE64=$(cat certs/key.pem | base64)

az keyvault secret set --vault-name $KEYVAULT_NAME --name "TLS-CERT" --value "$CERT_BASE64"
az keyvault secret set --vault-name $KEYVAULT_NAME --name "TLS-KEY" --value "$KEY_BASE64"

echo -e "${GREEN}✅ TLS certificates generated and stored${NC}"

# ============================================
# Output Summary
# ============================================
echo -e "\n${GREEN}============================================${NC}"
echo -e "${GREEN}🎉 Azure Setup Complete!${NC}"
echo -e "${GREEN}============================================${NC}"
echo -e "Resource Group: ${YELLOW}$RESOURCE_GROUP${NC}"
echo -e "Location: ${YELLOW}$LOCATION${NC}"
echo -e "Container Registry: ${YELLOW}$ACR_LOGIN_SERVER${NC}"
echo -e "Key Vault: ${YELLOW}$KEYVAULT_NAME${NC}"
echo -e "\n${YELLOW}Next steps:${NC}"
echo -e "1. Run: ${GREEN}./deployments/azure/scripts/build-and-push.sh${NC}"
echo -e "2. Run: ${GREEN}./deployments/azure/scripts/deploy-container.sh${NC}"