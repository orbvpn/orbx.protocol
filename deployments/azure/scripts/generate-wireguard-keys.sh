#!/bin/bash

# Generate WireGuard keys and store in Azure Key Vault
# Location: deployments/azure/scripts/generate-wireguard-keys.sh

set -e

KEYVAULT_NAME="orbx-vault"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}🔑 Generating WireGuard Keys${NC}"
echo "=============================================="

# Check if wg command exists
if ! command -v wg &>/dev/null; then
	echo -e "${YELLOW}WireGuard tools not found. Installing...${NC}"
	if [[ "$OSTYPE" == "darwin"* ]]; then
		brew install wireguard-tools
	elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
		sudo apt-get update && sudo apt-get install -y wireguard-tools
	else
		echo "Please install wireguard-tools manually"
		exit 1
	fi
fi

# Generate private key
echo -e "\n${YELLOW}Generating WireGuard private key...${NC}"
WG_PRIVATE_KEY=$(wg genkey)

# Generate public key from private key
echo -e "${YELLOW}Generating WireGuard public key...${NC}"
WG_PUBLIC_KEY=$(echo "$WG_PRIVATE_KEY" | wg pubkey)

# Store in Azure Key Vault
echo -e "\n${YELLOW}Storing keys in Azure Key Vault...${NC}"

az keyvault secret set \
	--vault-name $KEYVAULT_NAME \
	--name "WG-PRIVATE-KEY" \
	--value "$WG_PRIVATE_KEY"

az keyvault secret set \
	--vault-name $KEYVAULT_NAME \
	--name "WG-PUBLIC-KEY" \
	--value "$WG_PUBLIC_KEY"

echo -e "\n${GREEN}✅ WireGuard Keys Generated!${NC}"
echo -e "${GREEN}============================================${NC}"
echo -e "${YELLOW}Private Key:${NC} [HIDDEN - stored in Key Vault]"
echo -e "${YELLOW}Public Key:${NC} $WG_PUBLIC_KEY"
echo -e "\n${GREEN}Keys are securely stored in Azure Key Vault: $KEYVAULT_NAME${NC}"
echo -e "${GREEN}✅ Ready for WireGuard deployment!${NC}"
