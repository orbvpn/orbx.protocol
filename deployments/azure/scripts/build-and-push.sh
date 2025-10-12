#!/bin/bash

set -e

# Configuration
ACR_NAME="orbxregistry"
IMAGE_NAME="orbx-protocol"
VERSION="latest"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}🔨 Building and Pushing Docker Image${NC}"
echo "=============================================="

# Get ACR login server
ACR_LOGIN_SERVER="$ACR_NAME.azurecr.io"

# Login to ACR
echo -e "\n${YELLOW}🔐 Logging in to Azure Container Registry...${NC}"
az acr login --name $ACR_NAME

# Build multi-arch image (supports ARM and AMD64)
echo -e "\n${YELLOW}🏗️  Building Docker image...${NC}"
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t $ACR_LOGIN_SERVER/$IMAGE_NAME:$VERSION \
  -t $ACR_LOGIN_SERVER/$IMAGE_NAME:$(date +%Y%m%d-%H%M%S) \
  --push \
  -f Dockerfile \
  .

echo -e "${GREEN}✅ Image built and pushed: $ACR_LOGIN_SERVER/$IMAGE_NAME:$VERSION${NC}"

# List images in registry
echo -e "\n${YELLOW}📋 Images in registry:${NC}"
az acr repository show-tags \
  --name $ACR_NAME \
  --repository $IMAGE_NAME \
  --output table

echo -e "\n${GREEN}🎉 Build and push complete!${NC}"