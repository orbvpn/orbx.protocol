#!/bin/bash

set -e

RESOURCE_GROUP="orbx-production-rg"
WORKSPACE_NAME="orbx-logs"
CONTAINER_NAME="orbx-protocol"

# Create Log Analytics Workspace
az monitor log-analytics workspace create \
  --resource-group $RESOURCE_GROUP \
  --workspace-name $WORKSPACE_NAME

# Get workspace ID and key
WORKSPACE_ID=$(az monitor log-analytics workspace show \
  --resource-group $RESOURCE_GROUP \
  --workspace-name $WORKSPACE_NAME \
  --query customerId -o tsv)

WORKSPACE_KEY=$(az monitor log-analytics workspace get-shared-keys \
  --resource-group $RESOURCE_GROUP \
  --workspace-name $WORKSPACE_NAME \
  --query primarySharedKey -o tsv)

# Update container to send logs
az container create \
  --resource-group $RESOURCE_GROUP \
  --name $CONTAINER_NAME \
  --log-analytics-workspace $WORKSPACE_ID \
  --log-analytics-workspace-key $WORKSPACE_KEY

echo "Monitoring enabled. View logs at:"
echo "https://portal.azure.com"