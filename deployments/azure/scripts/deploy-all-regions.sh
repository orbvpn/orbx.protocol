#!/bin/bash

# Deploy OrbX servers to all 30 Azure regions with automatic OrbNet registration
# Each server gets unique credentials from OrbNet API

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# All 30 Azure regions
REGIONS=(
	"eastus" "eastus2" "westus" "westus2" "westus3"
	"centralus" "northcentralus" "southcentralus" "westcentralus"
	"canadacentral" "canadaeast"
	"brazilsouth"
	"northeurope" "westeurope" "uksouth" "ukwest"
	"francecentral" "germanywestcentral" "norwayeast" "switzerlandnorth"
	"swedencentral"
	"eastasia" "southeastasia"
	"japaneast" "japanwest"
	"australiaeast" "australiasoutheast"
	"centralindia" "southindia"
	"uaenorth"
)

echo -e "${GREEN}🌍 OrbX Multi-Region Deployment${NC}"
echo -e "${GREEN}============================================${NC}"
echo -e "${YELLOW}Deploying to ${#REGIONS[@]} regions${NC}"
echo ""
echo "Regions:"
for region in "${REGIONS[@]}"; do
	echo "  - $region"
done
echo ""
read -p "Continue? (yes/no): " confirm

if [ "$confirm" != "yes" ]; then
	echo "Deployment cancelled"
	exit 0
fi

# Clear previous deployment log
>deployed-servers.txt
>deployment-errors.txt

echo -e "\n${GREEN}Starting deployments...${NC}"
echo -e "${YELLOW}This will take approximately 15-20 minutes${NC}\n"

# Deploy in batches of 5 for better progress tracking
BATCH_SIZE=5
TOTAL=${#REGIONS[@]}
SUCCESSFUL=0
FAILED=0

for ((i = 0; i < $TOTAL; i += $BATCH_SIZE)); do
	BATCH_END=$((i + BATCH_SIZE))
	if [ $BATCH_END -gt $TOTAL ]; then
		BATCH_END=$TOTAL
	fi

	BATCH_NUM=$((i / BATCH_SIZE + 1))
	TOTAL_BATCHES=$(((TOTAL + BATCH_SIZE - 1) / BATCH_SIZE))

	echo -e "${YELLOW}📦 Batch ${BATCH_NUM}/${TOTAL_BATCHES}${NC}"

	# Deploy regions in this batch in parallel
	for ((j = i; j < $BATCH_END; j++)); do
		region="${REGIONS[$j]}"
		echo -e "${YELLOW}  Deploying to ${region}...${NC}"

		# Run deployment in background
		(
			if ./deploy-vm-region.sh "$region" >"deploy-${region}.log" 2>&1; then
				echo "SUCCESS|${region}" >>deployment-status.tmp
			else
				echo "FAILED|${region}" >>deployment-status.tmp
				cat "deploy-${region}.log" >>deployment-errors.txt
			fi
		) &
	done

	# Wait for this batch to complete
	wait

	# Count successes and failures in this batch
	if [ -f deployment-status.tmp ]; then
		while IFS='|' read -r status region; do
			if [ "$status" = "SUCCESS" ]; then
				SUCCESSFUL=$((SUCCESSFUL + 1))
				echo -e "${GREEN}  ✓ ${region} deployed${NC}"
			else
				FAILED=$((FAILED + 1))
				echo -e "${RED}  ✗ ${region} failed${NC}"
			fi
		done <deployment-status.tmp
		rm deployment-status.tmp
	fi

	echo -e "${YELLOW}  Progress: ${SUCCESSFUL}/${TOTAL} successful, ${FAILED} failed${NC}\n"

	# Brief pause between batches
	if [ $BATCH_END -lt $TOTAL ]; then
		sleep 5
	fi
done

# ============================================
# Summary
# ============================================
echo -e "\n${GREEN}============================================${NC}"
echo -e "${GREEN}📊 Deployment Summary${NC}"
echo -e "${GREEN}============================================${NC}"
echo -e "Total Regions: ${YELLOW}${TOTAL}${NC}"
echo -e "Successful: ${GREEN}${SUCCESSFUL}${NC}"
echo -e "Failed: ${RED}${FAILED}${NC}"

if [ $FAILED -gt 0 ]; then
	echo -e "\n${RED}⚠️  Some deployments failed. Check deployment-errors.txt for details${NC}"
fi

# Display deployed servers
if [ -f deployed-servers.txt ] && [ -s deployed-servers.txt ]; then
	echo -e "\n${GREEN}Deployed Servers:${NC}"
	echo -e "${YELLOW}FQDN | Server ID | Region | WireGuard Public Key${NC}"
	cat deployed-servers.txt

	echo -e "\n${GREEN}Server list saved to: deployed-servers.txt${NC}"
fi

# Cleanup individual deployment logs
echo -e "\n${YELLOW}Cleaning up...${NC}"
rm -f deploy-*.log

echo -e "\n${GREEN}✅ Multi-region deployment complete!${NC}"
echo -e "\n${YELLOW}Next steps:${NC}"
echo -e "1. Test all servers: ${YELLOW}./test-all-regions.sh${NC}"
echo -e "2. View OrbNet dashboard to see all servers"
echo -e "3. Check server status: ${YELLOW}./manage-all-regions.sh status${NC}"
