#!/bin/bash

set -e

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

REGIONS=(eastus westus centralus canadacentral northeurope westeurope uksouth francecentral germanywestcentral swedencentral switzerlandnorth italynorth southeastasia eastasia japaneast koreacentral australiaeast centralindia uaenorth southafricanorth qatarcentral israelcentral brazilsouth norwayeast polandcentral spaincentral mexicocentral southindia westus3 australiasoutheast)

case "${1:-}" in
status)
	echo -e "${YELLOW}Region Status Check${NC}\n"
	for region in "${REGIONS[@]}"; do
		if state=$(az container show \
			--resource-group "orbx-${region}-rg" \
			--name "orbx-${region}" \
			--query "instanceView.state" -o tsv 2>/dev/null); then
			[ "$state" == "Running" ] &&
				echo -e "$region: ${GREEN}✅ Running${NC}" ||
				echo -e "$region: ${RED}$state${NC}"
		else
			echo -e "$region: ${RED}Not Found${NC}"
		fi
	done
	;;

restart)
	echo -e "${YELLOW}Restarting all servers...${NC}"
	for region in "${REGIONS[@]}"; do
		echo -n "$region: "
		az container restart \
			--resource-group "orbx-${region}-rg" \
			--name "orbx-${region}" \
			--output none 2>/dev/null && echo "✅" || echo "❌"
	done
	;;

stop)
	echo -e "${YELLOW}Stopping all servers...${NC}"
	for region in "${REGIONS[@]}"; do
		echo -n "$region: "
		az container stop \
			--resource-group "orbx-${region}-rg" \
			--name "orbx-${region}" \
			--output none 2>/dev/null && echo "✅" || echo "❌"
	done
	;;

start)
	echo -e "${YELLOW}Starting all servers...${NC}"
	for region in "${REGIONS[@]}"; do
		echo -n "$region: "
		az container start \
			--resource-group "orbx-${region}-rg" \
			--name "orbx-${region}" \
			--output none 2>/dev/null && echo "✅" || echo "❌"
	done
	;;

delete)
	echo -e "${RED}⚠️  WARNING: This will DELETE all deployments!${NC}"
	read -p "Type 'DELETE' to confirm: " CONFIRM
	[ "$CONFIRM" != "DELETE" ] && echo "Cancelled" && exit 0

	echo -e "${RED}Deleting all resource groups...${NC}"
	for region in "${REGIONS[@]}"; do
		echo -n "$region: "
		az group delete \
			--name "orbx-${region}-rg" \
			--yes --no-wait 2>/dev/null && echo "✅" || echo "❌"
	done
	echo -e "${YELLOW}Deletion initiated (takes a few minutes)${NC}"
	;;

logs)
	region="${2:-eastus}"
	echo -e "${YELLOW}Viewing logs for $region...${NC}"
	az container logs \
		--resource-group "orbx-${region}-rg" \
		--name "orbx-${region}" \
		--follow
	;;

*)
	echo "OrbX Multi-Region Management"
	echo ""
	echo "Usage: $0 {status|start|stop|restart|delete|logs}"
	echo ""
	echo "Commands:"
	echo "  status   - Show status of all servers"
	echo "  start    - Start all servers"
	echo "  stop     - Stop all servers"
	echo "  restart  - Restart all servers"
	echo "  delete   - Delete all deployments"
	echo "  logs     - View logs (specify region as 2nd arg)"
	echo ""
	echo "Examples:"
	echo "  $0 status"
	echo "  $0 restart"
	echo "  $0 logs westus"
	exit 1
	;;
esac
