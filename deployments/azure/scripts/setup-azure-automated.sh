#!/bin/bash

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}🚀 Fully Automated Azure Setup for OrbX${NC}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/orbnet-api-client.sh"

ENV_FILE="$SCRIPT_DIR/../.env.deployment"
if [ ! -f "$ENV_FILE" ]; then
    echo -e "${RED}❌ $ENV_FILE not found!${NC}"
    echo "Create it: cp .env.deployment.template .env.deployment"
    exit 1
fi

source "$ENV_FILE"

if [ -z "$ORBNET_ADMIN_EMAIL" ] || [ -z "$ORBNET_ADMIN_PASSWORD" ]; then
    echo -e "${RED}❌ Missing credentials in $ENV_FILE${NC}"
    exit 1
fi

RESOURCE_GROUP="${RESOURCE_GROUP:-orbx-production-rg}"
LOCATION="${AZURE_LOCATION:-eastus}"
ACR_NAME="${ACR_NAME:-orbxregistry}"
KEYVAULT_NAME="${KEYVAULT_NAME:-orbx-vault}"
ORBNET_ENDPOINT="${ORBNET_ENDPOINT:-https://api.orbvpn.com/graphql}"

echo -e "${YELLOW}📂 Config: $RESOURCE_GROUP @ $LOCATION${NC}"

# Login to OrbNet
echo -e "${YELLOW}🔐 Logging into OrbNet...${NC}"
ADMIN_TOKEN=$(orbnet_login "$ORBNET_ADMIN_EMAIL" "$ORBNET_ADMIN_PASSWORD")
if [ -z "$ADMIN_TOKEN" ]; then
    echo -e "${RED}❌ Login failed${NC}"
    exit 1
fi

# Create Resource Group
echo -e "${YELLOW}📦 Creating Resource Group...${NC}"
az group create --name $RESOURCE_GROUP --location $LOCATION \
    --tags Environment=Production Application=OrbX --output none

# Create Container Registry
echo -e "${YELLOW}🐳 Creating Container Registry...${NC}"
az acr create --resource-group $RESOURCE_GROUP --name $ACR_NAME \
    --sku Standard --admin-enabled true --output none

ACR_USERNAME=$(az acr credential show --name $ACR_NAME --query username -o tsv)
ACR_PASSWORD=$(az acr credential show --name $ACR_NAME --query passwords[0].value -o tsv)

# Create Key Vault
echo -e "${YELLOW}🔐 Creating Key Vault...${NC}"
az keyvault create --resource-group $RESOURCE_GROUP --name $KEYVAULT_NAME \
    --location $LOCATION --enable-soft-delete true --output none

# Store Secrets
echo -e "${YELLOW}🔒 Storing secrets...${NC}"
az keyvault secret set --vault-name $KEYVAULT_NAME --name "ORBNET-ADMIN-EMAIL" --value "$ORBNET_ADMIN_EMAIL" --output none
az keyvault secret set --vault-name $KEYVAULT_NAME --name "ORBNET-ADMIN-PASSWORD" --value "$ORBNET_ADMIN_PASSWORD" --output none
az keyvault secret set --vault-name $KEYVAULT_NAME --name "ORBNET-ENDPOINT" --value "$ORBNET_ENDPOINT" --output none
az keyvault secret set --vault-name $KEYVAULT_NAME --name "ORBNET-ADMIN-TOKEN" --value "$ADMIN_TOKEN" --output none
az keyvault secret set --vault-name $KEYVAULT_NAME --name "ACR-USERNAME" --value "$ACR_USERNAME" --output none
az keyvault secret set --vault-name $KEYVAULT_NAME --name "ACR-PASSWORD" --value "$ACR_PASSWORD" --output none

# Create Virtual Network
echo -e "${YELLOW}🌐 Creating Virtual Network...${NC}"
az network vnet create --resource-group $RESOURCE_GROUP --name orbx-vnet \
    --address-prefix 10.0.0.0/16 --subnet-name orbx-subnet --subnet-prefix 10.0.1.0/24 --output none

# Generate TLS Certificate
echo -e "${YELLOW}🔒 Generating TLS certificates...${NC}"
mkdir -p certs
openssl req -x509 -newkey rsa:4096 -nodes -keyout certs/key.pem -out certs/cert.pem \
    -days 365 -subj "/C=US/O=OrbVPN/CN=*.azurecontainer.io" 2>/dev/null

CERT_BASE64=$(cat certs/cert.pem | base64 | tr -d '\n')
KEY_BASE64=$(cat certs/key.pem | base64 | tr -d '\n')

az keyvault secret set --vault-name $KEYVAULT_NAME --name "TLS-CERT" --value "$CERT_BASE64" --output none
az keyvault secret set --vault-name $KEYVAULT_NAME --name "TLS-KEY" --value "$KEY_BASE64" --output none

echo -e "\n${GREEN}🎉 Setup Complete!${NC}"
echo -e "Next: ./build-and-push.sh && ./deploy-single-test.sh"