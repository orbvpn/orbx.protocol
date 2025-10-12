#!/bin/bash

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

# Get secrets from Key Vault
echo -e "\n${YELLOW}🔑 Retrieving secrets...${NC}"
JWT_SECRET=$(az keyvault secret show --vault-name $KEYVAULT_NAME --name "JWT-SECRET" --query value -o tsv)
ORBNET_API_KEY=$(az keyvault secret show --vault-name $KEYVAULT_NAME --name "ORBNET-API-KEY" --query value -o tsv)
ORBNET_ENDPOINT=$(az keyvault secret show --vault-name $KEYVAULT_NAME --name "ORBNET-ENDPOINT" --query value -o tsv)
ACR_USERNAME=$(az keyvault secret show --vault-name $KEYVAULT_NAME --name "ACR-USERNAME" --query value -o tsv)
ACR_PASSWORD=$(az keyvault secret show --vault-name $KEYVAULT_NAME --name "ACR-PASSWORD" --query value -o tsv)
TLS_CERT=$(az keyvault secret show --vault-name $KEYVAULT_NAME --name "TLS-CERT" --query value -o tsv)
TLS_KEY=$(az keyvault secret show --vault-name $KEYVAULT_NAME --name "TLS-KEY" --query value -o tsv)

# Deploy container
echo -e "\n${YELLOW}🚀 Deploying container...${NC}"
az container create \
  --resource-group $RESOURCE_GROUP \
  --name $CONTAINER_NAME \
  --image $ACR_NAME.azurecr.io/orbx-protocol:latest \
  --dns-name-label $DNS_NAME \
  --ports 8443 \
  --protocol TCP \
  --cpu 2 \
  --memory 4 \
  --registry-login-server $ACR_NAME.azurecr.io \
  --registry-username $ACR_USERNAME \
  --registry-password $ACR_PASSWORD \
  --environment-variables \
    ORBNET_ENDPOINT="$ORBNET_ENDPOINT" \
  --secure-environment-variables \
    JWT_SECRET="$JWT_SECRET" \
    ORBNET_API_KEY="$ORBNET_API_KEY" \
  --restart-policy Always

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
echo -e "Health Check: ${YELLOW}https://$FQDN:8443/health${NC}"
echo -e "\nTest with:"
echo -e "${YELLOW}curl -k https://$FQDN:8443/health${NC}"