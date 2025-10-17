#!/bin/bash

set -e

KEYVAULT_NAME="orbx-vault"
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}🔧 Fixing Key Vault Permissions${NC}"
echo "=============================================="

# Get current user's object ID
USER_OBJECT_ID=$(az ad signed-in-user show --query id -o tsv)
echo "Current user object ID: $USER_OBJECT_ID"

# Try to recover the soft-deleted vault
echo -e "\n${YELLOW}Attempting to recover soft-deleted Key Vault...${NC}"
az keyvault recover --name $KEYVAULT_NAME || true

# Wait for recovery
sleep 5

# Update Key Vault to disable RBAC and use access policies
echo -e "\n${YELLOW}Updating Key Vault to use access policies...${NC}"
az keyvault update \
  --name $KEYVAULT_NAME \
  --enable-rbac-authorization false

# Set access policy for current user
echo -e "\n${YELLOW}Setting access policy...${NC}"
az keyvault set-policy \
  --name $KEYVAULT_NAME \
  --object-id $USER_OBJECT_ID \
  --secret-permissions get list set delete purge recover backup restore \
  --certificate-permissions get list create delete purge recover backup restore

echo -e "\n${GREEN}✅ Key Vault permissions fixed!${NC}"
echo -e "${GREEN}You can now store secrets in the Key Vault${NC}"