#!/bin/bash
# interactive-cleanup.sh - Safely review and delete Azure resource groups

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}═══════════════════════════════════════${NC}"
echo -e "${BLUE}  Azure Resource Group Cleanup Tool${NC}"
echo -e "${BLUE}═══════════════════════════════════════${NC}\n"

# Get all resource groups
echo -e "${YELLOW}Analyzing resource groups...${NC}\n"

# Array to store groups to potentially delete
declare -a TO_DELETE

echo -e "${BLUE}ID  | Resource Group Name                | Resources | Location     | Status${NC}"
echo "---------------------------------------------------------------------------------"

counter=1
for rg in $(az group list --query "[].name" -o tsv); do
	count=$(az resource list --resource-group "$rg" --query "length(@)" -o tsv 2>/dev/null || echo "0")
	location=$(az group show --name "$rg" --query "location" -o tsv 2>/dev/null)
	state=$(az group show --name "$rg" --query "properties.provisioningState" -o tsv 2>/dev/null)

	# Color code based on resource count
	if [ "$count" -eq 0 ]; then
		color=$RED
		status="❌ EMPTY"
	elif [ "$count" -lt 3 ]; then
		color=$YELLOW
		status="⚠️  FEW"
	else
		color=$GREEN
		status="✓ IN USE"
	fi

	printf "${color}%-4s| %-35s | %-9s | %-12s | %s${NC}\n" "$counter" "$rg" "$count" "$location" "$status"

	TO_DELETE[$counter]=$rg
	((counter++))
done

echo ""
echo -e "${YELLOW}════════════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}Enter resource group numbers to DELETE (space-separated)${NC}"
echo -e "${YELLOW}Example: 1 3 5 or 'all-empty' or 'quit'${NC}"
echo -e "${YELLOW}════════════════════════════════════════════════════════════${NC}"
read -p "Your choice: " choices

if [ "$choices" == "quit" ]; then
	echo "Cancelled"
	exit 0
fi

# Handle 'all-empty' option
if [ "$choices" == "all-empty" ]; then
	echo -e "\n${RED}Deleting all EMPTY resource groups...${NC}\n"
	for rg in $(az group list --query "[].name" -o tsv); do
		count=$(az resource list --resource-group "$rg" --query "length(@)" -o tsv 2>/dev/null || echo "0")
		if [ "$count" -eq 0 ]; then
			echo -e "${YELLOW}Deleting: $rg${NC}"
			az group delete --name "$rg" --yes --no-wait
		fi
	done
	echo -e "\n${GREEN}Deletion initiated for all empty resource groups${NC}"
	exit 0
fi

# Delete selected resource groups
echo ""
for num in $choices; do
	if [ -n "${TO_DELETE[$num]}" ]; then
		rg="${TO_DELETE[$num]}"

		# Show what's inside before deleting
		echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
		echo -e "${YELLOW}Resources in: $rg${NC}"
		az resource list --resource-group "$rg" --query "[].{Name:name, Type:type}" -o table
		echo ""

		read -p "Really delete '$rg'? (yes/no): " confirm
		if [ "$confirm" == "yes" ]; then
			echo -e "${RED}Deleting $rg...${NC}"
			az group delete --name "$rg" --yes --no-wait
			echo -e "${GREEN}✓ Deletion initiated${NC}\n"
		else
			echo -e "${BLUE}Skipped${NC}\n"
		fi
	fi
done

echo -e "${GREEN}Done!${NC}"
