#!/bin/bash

# Simple test deployment without TLS to verify the binary works
# This will help us isolate whether the issue is with env vars or the app itself

set -e

REGION="eastus"
RESOURCE_GROUP="orbx-eastus-test-rg"
CONTAINER_NAME="orbx-test"
ACR_NAME="orbxregistry"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}🧪 Simple Test Deployment${NC}"
echo "=============================================="

# Create test resource group
echo -e "\n${YELLOW}Creating test resource group...${NC}"
az group create \
  --name $RESOURCE_GROUP \
  --location $REGION \
  --output none

# Get ACR credentials
ACR_USERNAME=$(az acr credential show --name $ACR_NAME --query username -o tsv)
ACR_PASSWORD=$(az acr credential show --name $ACR_NAME --query passwords[0].value -o tsv)

# Create minimal YAML - just test if the binary runs
cat > /tmp/orbx-test.yaml <<EOF
apiVersion: '2021-09-01'
location: ${REGION}
name: ${CONTAINER_NAME}
properties:
  containers:
  - name: ${CONTAINER_NAME}
    properties:
      image: ${ACR_NAME}.azurecr.io/orbx-protocol:latest
      resources:
        requests:
          cpu: 1
          memoryInGB: 2
      ports:
      - port: 8443
        protocol: TCP
      environmentVariables:
      - name: 'TEST_MODE'
        value: 'true'
      command:
      - /bin/sh
      - -c
      - |
        echo "=== Testing OrbX Binary ==="
        echo "Checking if binary exists..."
        ls -la /app/orbx-protocol
        echo ""
        echo "Checking binary permissions..."
        file /app/orbx-protocol
        echo ""
        echo "Testing execution..."
        /app/orbx-protocol --help || echo "Help command failed"
        echo ""
        echo "Sleeping for 5 minutes to keep container alive..."
        sleep 300
  osType: Linux
  restartPolicy: Never
  ipAddress:
    type: Public
    ports:
    - protocol: TCP
      port: 8443
  imageRegistryCredentials:
  - server: ${ACR_NAME}.azurecr.io
    username: ${ACR_USERNAME}
    password: ${ACR_PASSWORD}
type: Microsoft.ContainerInstance/containerGroups
EOF

echo -e "\n${YELLOW}Deploying test container...${NC}"
az container create \
  --resource-group $RESOURCE_GROUP \
  --file /tmp/orbx-test.yaml

echo -e "\n${YELLOW}Waiting 30 seconds for container to run...${NC}"
sleep 30

echo -e "\n${YELLOW}Container logs:${NC}"
az container logs --resource-group $RESOURCE_GROUP --name $CONTAINER_NAME

echo -e "\n${GREEN}============================================${NC}"
echo -e "${GREEN}Test complete!${NC}"
echo -e "${GREEN}============================================${NC}"
echo ""
echo "If you see the binary info above, the image is fine."
echo "The issue is with environment variable passing in Azure."
echo ""
echo "Cleanup: az group delete --name $RESOURCE_GROUP --yes"

rm -f /tmp/orbx-test.yaml