#!/bin/bash

set -e

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}🔍 Testing All OrbX Servers${NC}\n"

REGIONS=(eastus westus centralus canadacentral northeurope westeurope uksouth francecentral germanywestcentral swedencentral switzerlandnorth italynorth southeastasia eastasia japaneast koreacentral australiaeast centralindia uaenorth southafricanorth qatarcentral israelcentral brazilsouth norwayeast polandcentral spaincentral mexicocentral southindia westus3 australiasoutheast)

TOTAL=0
HEALTHY=0

for region in "${REGIONS[@]}"; do
	FQDN=$(az container show \
		--resource-group "orbx-${region}-rg" \
		--name "orbx-${region}" \
		--query "ipAddress.fqdn" -o tsv 2>/dev/null || echo "")

	[ -z "$FQDN" ] && continue

	((TOTAL++))

	if response=$(curl -k -s -m 10 "https://$FQDN:8443/health" 2>/dev/null); then
		if echo "$response" | grep -q "healthy"; then
			echo -e "${region}: ${GREEN}✅ Healthy${NC}"
			((HEALTHY++))
		else
			echo -e "${region}: ${RED}❌ Unhealthy${NC}"
		fi
	else
		echo -e "${region}: ${RED}❌ Unreachable${NC}"
	fi
done

echo -e "\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "Total: $TOTAL"
echo -e "${GREEN}Healthy: $HEALTHY${NC}"
echo -e "${RED}Unhealthy: $((TOTAL - HEALTHY))${NC}"
echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

[ $HEALTHY -eq $TOTAL ] && echo -e "${GREEN}🎉 All servers healthy!${NC}" || echo -e "${YELLOW}⚠️  Some servers need attention${NC}"
