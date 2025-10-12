#!/bin/bash

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/orbnet-api-client.sh"

TEST_REGION="${TEST_REGION:-eastus}"
ACR_NAME="orbxregistry"
IMAGE_NAME="orbx-protocol"
VERSION="latest"
KEYVAULT_NAME="orbx-vault"

echo -e "${BLUE}╔════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  Automated Test Deployment - $TEST_REGION           ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════╝${NC}"

# Get credentials
echo -e "${YELLOW}🔑 Getting credentials...${NC}"
ORBNET_ADMIN_EMAIL=$(az keyvault secret show --vault-name $KEYVAULT_NAME --name "ORBNET-ADMIN-EMAIL" --query value -o tsv)
ORBNET_ADMIN_PASSWORD=$(az keyvault secret show --vault-name $KEYVAULT_NAME --name "ORBNET-ADMIN-PASSWORD" --query value -o tsv)
ORBNET_ENDPOINT=$(az keyvault secret show --vault-name $KEYVAULT_NAME --name "ORBNET-ENDPOINT" --query value -o tsv)
ACR_USERNAME=$(az keyvault secret show --vault-name $KEYVAULT_NAME --name "ACR-USERNAME" --query value -o tsv)
ACR_PASSWORD=$(az keyvault secret show --vault-name $KEYVAULT_NAME --name "ACR-PASSWORD" --query value -o tsv)

# Login to OrbNet
echo -e "${YELLOW}🔐 Logging into OrbNet...${NC}"
ADMIN_TOKEN=$(orbnet_login "$ORBNET_ADMIN_EMAIL" "$ORBNET_ADMIN_PASSWORD")

# Prepare
RESOURCE_GROUP="orbx-${TEST_REGION}-test-rg"
CONTAINER_NAME="orbx-${TEST_REGION}-test"
DNS_NAME="orbx-test-${TEST_REGION}"
SERVER_NAME="OrbX Test - $TEST_REGION"

# Create resource group
echo -e "${YELLOW}📦 Creating resource group...${NC}"
az group create --name $RESOURCE_GROUP --location $TEST_REGION --tags Environment=Test --output none

# Register with OrbNet (auto-generates credentials!)
echo -e "${YELLOW}📝 Auto-registering with OrbNet...${NC}"
SERVER_ID=$(orbnet_check_server_exists "$ADMIN_TOKEN" "$SERVER_NAME" || echo "")

if [ -n "$SERVER_ID" ]; then
    CREDENTIALS=$(orbnet_regenerate_credentials "$ADMIN_TOKEN" "$SERVER_ID")
else
    CREDENTIALS=$(orbnet_register_server "$ADMIN_TOKEN" "$SERVER_NAME" "pending" 8443 "Test" "US" "$TEST_REGION")
    SERVER_ID=$(echo "$CREDENTIALS" | jq -r '.server_id')
fi

ORBNET_API_KEY=$(echo "$CREDENTIALS" | jq -r '.api_key')
JWT_SECRET=$(echo "$CREDENTIALS" | jq -r '.jwt_secret')

echo -e "${GREEN}✅ Credentials generated! (Key: ${ORBNET_API_KEY:0:20}...)${NC}"

# Deploy container
echo -e "${YELLOW}🚀 Deploying container...${NC}"
az container create \
    --resource-group $RESOURCE_GROUP \
    --name $CONTAINER_NAME \
    --image $ACR_NAME.azurecr.io/$IMAGE_NAME:$VERSION \
    --dns-name-label $DNS_NAME \
    --ports 8443 \
    --cpu 2 \
    --memory 4 \
    --registry-login-server $ACR_NAME.azurecr.io \
    --registry-username $ACR_USERNAME \
    --registry-password $ACR_PASSWORD \
    --environment-variables ORBNET_ENDPOINT="$ORBNET_ENDPOINT" \
    --secure-environment-variables JWT_SECRET="$JWT_SECRET" ORBNET_API_KEY="$ORBNET_API_KEY" \
    --restart-policy Always \
    --output none

# Get FQDN
FQDN=$(az container show --resource-group $RESOURCE_GROUP --name $CONTAINER_NAME --query "ipAddress.fqdn" -o tsv)

# Update OrbNet
orbnet_update_server "$ADMIN_TOKEN" "$SERVER_ID" "$FQDN"

# Wait and test
echo -e "${YELLOW}⏳ Waiting 30s...${NC}"
sleep 30

echo -e "${YELLOW}🔍 Testing health...${NC}"
for i in {1..5}; do
    if response=$(curl -k -s -m 10 "https://$FQDN:8443/health" 2>/dev/null); then
        if echo "$response" | grep -q "healthy"; then
            echo -e "${GREEN}✅ Health check PASSED!${NC}"
            echo -e "${GREEN}✅ Server: https://$FQDN:8443${NC}"
            echo -e "\n${YELLOW}Next: ./deploy-all-regions.sh${NC}"
            echo -e "${YELLOW}Cleanup: az group delete --name $RESOURCE_GROUP --yes${NC}"
            exit 0
        fi
    fi
    echo "   Attempt $i/5..."
    sleep 10
done

echo -e "${RED}❌ Health check failed${NC}"
exit 1