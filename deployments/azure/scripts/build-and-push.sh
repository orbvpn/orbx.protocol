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

# Go to project root (three levels up from scripts directory)
# scripts -> azure -> deployments -> project-root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$SCRIPT_DIR/../../.."

echo -e "\n${YELLOW}📂 Navigating to project root...${NC}"
cd "$PROJECT_ROOT"

# Verify Dockerfile exists
if [ ! -f "Dockerfile" ]; then
	echo -e "${RED}❌ Dockerfile not found at: $(pwd)/Dockerfile${NC}"
	exit 1
fi

echo -e "${GREEN}✓ Found Dockerfile at: $(pwd)/Dockerfile${NC}"
echo -e "${YELLOW}📂 Building from: $(pwd)${NC}"

# Build for single platform (AMD64 - most common for Azure)
echo -e "\n${YELLOW}🏗️  Building Docker image for AMD64...${NC}"
docker build \
	--platform linux/amd64 \
	-t $ACR_LOGIN_SERVER/$IMAGE_NAME:$VERSION \
	-t $ACR_LOGIN_SERVER/$IMAGE_NAME:$(date +%Y%m%d-%H%M%S) \
	-f Dockerfile \
	.

echo -e "${GREEN}✅ Image built successfully${NC}"

# Push to registry
echo -e "\n${YELLOW}⬆️  Pushing to Azure Container Registry...${NC}"
docker push $ACR_LOGIN_SERVER/$IMAGE_NAME:$VERSION

echo -e "${GREEN}✅ Image pushed successfully${NC}"

# List images in registry
echo -e "\n${YELLOW}📋 Images in registry:${NC}"
az acr repository show-tags \
	--name $ACR_NAME \
	--repository $IMAGE_NAME \
	--output table

echo -e "\n${GREEN}🎉 Build and push complete!${NC}"
echo -e "${GREEN}Image: ${YELLOW}$ACR_LOGIN_SERVER/$IMAGE_NAME:$VERSION${NC}"
