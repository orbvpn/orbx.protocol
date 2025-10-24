#!/bin/bash

set -e

# Configuration
ACR_NAME="orbxregistry"
IMAGE_NAME="orbx-protocol"
VERSION="latest"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}🔨 Building and Pushing Multi-Platform Docker Image${NC}"
echo "=============================================="

# Get ACR login server
ACR_LOGIN_SERVER="$ACR_NAME.azurecr.io"

# Login to ACR
echo -e "\n${YELLOW}🔐 Logging in to Azure Container Registry...${NC}"
az acr login --name $ACR_NAME

# Go to project root
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

# Create or use existing buildx builder for multi-platform builds
echo -e "\n${YELLOW}🔧 Setting up Docker buildx...${NC}"
if ! docker buildx inspect orbx-builder &>/dev/null; then
	echo "Creating new buildx builder..."
	docker buildx create --name orbx-builder --driver docker-container --use
else
	echo "Using existing buildx builder..."
	docker buildx use orbx-builder
fi

# Build for BOTH AMD64 and ARM64 platforms
echo -e "\n${YELLOW}🏗️  Building for AMD64 and ARM64...${NC}"
docker buildx build \
	--platform linux/amd64,linux/arm64 \
	--push \
	-t $ACR_LOGIN_SERVER/$IMAGE_NAME:$VERSION \
	-t $ACR_LOGIN_SERVER/$IMAGE_NAME:prod \
	-t $ACR_LOGIN_SERVER/$IMAGE_NAME:$(date +%Y%m%d-%H%M%S) \
	-f Dockerfile \
	.

echo -e "${GREEN}✅ Multi-platform image built and pushed${NC}"

# List images in registry
echo -e "\n${YELLOW}📋 Images in registry:${NC}"
az acr repository show-tags \
	--name $ACR_NAME \
	--repository $IMAGE_NAME \
	--output table

echo -e "\n${GREEN}🎉 Build complete!${NC}"
echo -e "${GREEN}Image: ${YELLOW}$ACR_LOGIN_SERVER/$IMAGE_NAME:prod${NC}"
echo -e "${GREEN}Platforms: ${YELLOW}linux/amd64, linux/arm64${NC}"
