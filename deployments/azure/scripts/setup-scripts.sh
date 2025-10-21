#!/bin/bash

# ============================================
# Make all deployment scripts executable
# Run this once before first deployment
# ============================================

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}Making all deployment scripts executable...${NC}\n"

SCRIPT_DIR="deployments/azure/scripts"

# List of all scripts
SCRIPTS=(
	"setup-azure.sh"
	"build-and-push.sh"
	"deploy-container.sh"
	"deploy-all-regions.sh"
	"test-all-regions.sh"
	"manage-all-regions.sh"
)

# Make each script executable
for script in "${SCRIPTS[@]}"; do
	if [ -f "$SCRIPT_DIR/$script" ]; then
		chmod +x "$SCRIPT_DIR/$script"
		echo -e "${GREEN}✅ Made executable: $script${NC}"
	else
		echo -e "${YELLOW}⚠️  Not found: $script${NC}"
	fi
done

echo -e "\n${GREEN}🎉 All scripts are now executable!${NC}"
echo -e "\nYou can now run:"
echo -e "  ${YELLOW}cd $SCRIPT_DIR${NC}"
echo -e "  ${YELLOW}./setup-azure.sh${NC}"
echo -e "  ${YELLOW}./build-and-push.sh${NC}"
echo -e "  ${YELLOW}./deploy-all-regions.sh${NC}"
