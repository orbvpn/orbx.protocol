#!/bin/bash

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/orbnet-api-client.sh"

ACR_NAME="orbxregistry"
IMAGE_NAME="orbx-protocol"
VERSION="latest"
KEYVAULT_NAME="orbx-vault"

# 30 Azure regions
declare -A REGIONS=(
    ["eastus"]="East US|US" ["westus"]="West US|US" ["centralus"]="Central US|US"
    ["canadacentral"]="Canada|CA" ["northeurope"]="North Europe|IE" ["westeurope"]="West Europe|NL"
    ["uksouth"]="UK South|GB" ["francecentral"]="France|FR" ["germanywestcentral"]="Germany|DE"
    ["swedencentral"]="Sweden|SE" ["switzerlandnorth"]="Switzerland|CH" ["italynorth"]="Italy|IT"
    ["southeastasia"]="Singapore|SG" ["eastasia"]="Hong Kong|HK" ["japaneast"]="Japan|JP"
    ["koreacentral"]="Korea|KR" ["australiaeast"]="Australia|AU" ["centralindia"]="India|IN"
    ["uaenorth"]="UAE|AE" ["southafricanorth"]="South Africa|ZA" ["qatarcentral"]="Qatar|QA"
    ["israelcentral"]="Israel|IL" ["brazilsouth"]="Brazil|BR" ["norwayeast"]="Norway|NO"
    ["polandcentral"]="Poland|PL" ["spaincentral"]="Spain|ES" ["mexicocentral"]="Mexico|MX"
    ["southindia"]="South India|IN" ["westus3"]="West US 3|US" ["australiasoutheast"]="Australia SE|AU"
)

TOTAL=${#REGIONS[@]}
SUCCESS=0
FAILED=0

echo -e "${GREEN}╔════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  FULLY AUTOMATED - Deploy to $TOTAL Regions        ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════════╝${NC}"
echo -e "${BLUE}Each region auto-registers & gets unique credentials!${NC}\n"

read -p "Continue? (yes/no): " CONFIRM
[ "$CONFIRM" != "yes" ] && exit 0

# Get credentials
echo -e "${YELLOW}🔑 Getting credentials...${NC}"
ORBNET_ADMIN_EMAIL=$(az keyvault secret show --vault-name $KEYVAULT_NAME --name "ORBNET-ADMIN-EMAIL" --query value -o tsv)
ORBNET_ADMIN_PASSWORD=$(az keyvault secret show --vault-name $KEYVAULT_NAME --name "ORBNET-ADMIN-PASSWORD" --query value -o tsv)
ORBNET_ENDPOINT=$(az keyvault secret show --vault-name $KEYVAULT_NAME --name "ORBNET-ENDPOINT" --query value -o tsv)
ACR_USERNAME=$(az keyvault secret show --vault-name $KEYVAULT_NAME --name "ACR-USERNAME" --query value -o tsv)
ACR_PASSWORD=$(az keyvault secret show --vault-name $KEYVAULT_NAME --name "ACR-PASSWORD" --query value -o tsv)

# Login once
echo -e "${YELLOW}🔐 Logging into OrbNet...${NC}"
ADMIN_TOKEN=$(orbnet_login "$ORBNET_ADMIN_EMAIL" "$ORBNET_ADMIN_PASSWORD")

# Deploy function
deploy_region() {
    local region=$1
    local info=$2
    IFS='|' read -r location country <<< "$info"
    
    local rg="orbx-${region}-rg"
    local container="orbx-${region}"
    local dns="orbx-${region}"
    local name="OrbX - $location"
    
    echo -e "${GREEN}🌍 $location ($country)${NC}"
    
    # Create RG
    az group create --name $rg --location $region --tags Environment=Production --output none 2>/dev/null || return 1
    
    # Register (auto-generates credentials!)
    local sid=$(orbnet_check_server_exists "$ADMIN_TOKEN" "$name" 2>/dev/null || echo "")
    local creds
    
    if [ -n "$sid" ]; then
        creds=$(orbnet_regenerate_credentials "$ADMIN_TOKEN" "$sid" 2>/dev/null) || return 1
    else
        creds=$(orbnet_register_server "$ADMIN_TOKEN" "$name" "pending" 8443 "$location" "$country" "$region" 2>/dev/null) || return 1
        sid=$(echo "$creds" | jq -r '.server_id')
    fi
    
    local key=$(echo "$creds" | jq -r '.api_key')
    local jwt=$(echo "$creds" | jq -r '.jwt_secret')
    
    # Deploy
    az container create \
        --resource-group $rg --name $container --image $ACR_NAME.azurecr.io/$IMAGE_NAME:$VERSION \
        --dns-name-label $dns --ports 8443 --cpu 2 --memory 4 \
        --registry-login-server $ACR_NAME.azurecr.io \
        --registry-username $ACR_USERNAME --registry-password $ACR_PASSWORD \
        --environment-variables ORBNET_ENDPOINT="$ORBNET_ENDPOINT" \
        --secure-environment-variables JWT_SECRET="$jwt" ORBNET_API_KEY="$key" \
        --restart-policy Always --output none 2>/dev/null || return 1
    
    # Update with FQDN
    local fqdn=$(az container show --resource-group $rg --name $container --query "ipAddress.fqdn" -o tsv 2>/dev/null)
    orbnet_update_server "$ADMIN_TOKEN" "$sid" "$fqdn" 2>/dev/null
    
    echo -e "   ✅ https://$fqdn:8443"
    return 0
}

# Deploy all
START=$(date +%s)
for region in "${!REGIONS[@]}"; do
    deploy_region "$region" "${REGIONS[$region]}" && ((SUCCESS++)) || ((FAILED++))
    sleep 2
done
END=$(date +%s)

echo -e "\n${GREEN}╔════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║            DEPLOYMENT COMPLETE                  ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════════╝${NC}"
echo -e "Success: ${GREEN}$SUCCESS${NC} | Failed: ${RED}$FAILED${NC} | Time: ${YELLOW}$(((END-START)/60))m${NC}"
echo -e "\n${BLUE}🤖 $SUCCESS servers auto-registered with unique credentials!${NC}"
echo -e "\n${YELLOW}Next: ./test-all-regions.sh${NC}"