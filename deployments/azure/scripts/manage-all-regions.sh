#!/bin/bash

set -e

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

REGIONS=(eastus westus centralus canadacentral northeurope westeurope uksouth francecentral germanywestcentral swedencentral switzerlandnorth italynorth southeastasia eastasia japaneast koreacentral australiaeast centralindia uaenorth southafricanorth qatarcentral israelcentral brazilsouth norwayeast polandcentral spaincentral mexicocentral southindia westus3 australiasoutheast)

case "${1:-}" in
status)
	echo -e "${YELLOW}Region Status Check (VMs)${NC}\n"
	for region in "${REGIONS[@]}"; do
		if state=$(az vm get-instance-view \
			--resource-group "orbx-${region}-rg" \
			--name "orbx-${region}-vm" \
			--query "instanceView.statuses[?starts_with(code, 'PowerState/')].displayStatus" \
			-o tsv 2>/dev/null); then
			[ "$state" == "VM running" ] &&
				echo -e "$region: ${GREEN}✅ Running${NC}" ||
				echo -e "$region: ${YELLOW}$state${NC}"
		else
			echo -e "$region: ${RED}Not Found${NC}"
		fi
	done
	;;

restart)
	echo -e "${YELLOW}Restarting all VM servers...${NC}"
	for region in "${REGIONS[@]}"; do
		echo -n "$region: "
		az vm restart \
			--resource-group "orbx-${region}-rg" \
			--name "orbx-${region}-vm" \
			--no-wait 2>/dev/null && echo "✅" || echo "❌"
	done
	echo -e "${YELLOW}Restart initiated (takes a few minutes)${NC}"
	;;

stop)
	echo -e "${YELLOW}Stopping all VM servers...${NC}"
	for region in "${REGIONS[@]}"; do
		echo -n "$region: "
		az vm deallocate \
			--resource-group "orbx-${region}-rg" \
			--name "orbx-${region}-vm" \
			--no-wait 2>/dev/null && echo "✅" || echo "❌"
	done
	echo -e "${YELLOW}Stop initiated (saves money)${NC}"
	;;

start)
	echo -e "${YELLOW}Starting all VM servers...${NC}"
	for region in "${REGIONS[@]}"; do
		echo -n "$region: "
		az vm start \
			--resource-group "orbx-${region}-rg" \
			--name "orbx-${region}-vm" \
			--no-wait 2>/dev/null && echo "✅" || echo "❌"
	done
	echo -e "${YELLOW}Start initiated${NC}"
	;;

delete)
	echo -e "${RED}⚠️  WARNING: This will DELETE all VM deployments!${NC}"
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
	echo -e "${YELLOW}SSH into VM to view logs for $region...${NC}"
	echo -e "${YELLOW}Command: ssh azureuser@orbx-${region}-vm.${region}.cloudapp.azure.com${NC}"
	echo ""
	echo -e "${YELLOW}Once connected, run:${NC}"
	echo -e "  sudo docker logs -f orbx-server"
	;;

ssh)
	region="${2:-eastus}"
	echo -e "${YELLOW}Connecting to ${region} VM...${NC}"
	az vm show \
		--resource-group "orbx-${region}-rg" \
		--name "orbx-${region}-vm" \
		--show-details \
		--query "publicIps" -o tsv >/tmp/vm_ip.txt 2>/dev/null

	VM_IP=$(cat /tmp/vm_ip.txt)
	if [ -n "$VM_IP" ]; then
		ssh azureuser@$VM_IP
	else
		echo -e "${RED}Could not find VM IP${NC}"
	fi
	;;

*)
	echo "OrbX Multi-Region Management (VM Edition)"
	echo ""
	echo "Usage: $0 {status|start|stop|restart|delete|logs|ssh}"
	echo ""
	echo "Commands:"
	echo "  status   - Show status of all VM servers"
	echo "  start    - Start all VM servers"
	echo "  stop     - Stop all VM servers (deallocate to save money)"
	echo "  restart  - Restart all VM servers"
	echo "  delete   - Delete all VM deployments"
	echo "  logs     - Instructions to view logs (specify region as 2nd arg)"
	echo "  ssh      - SSH into a VM (specify region as 2nd arg)"
	echo ""
	echo "Examples:"
	echo "  $0 status"
	echo "  $0 restart"
	echo "  $0 ssh westus"
	echo "  $0 logs eastus"
	exit 1
	;;
esac
