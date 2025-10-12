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

# DNS Configuration
DNS_ZONE_NAME="orbvpn.com"  # YOUR DOMAIN
DNS_RESOURCE_GROUP="dns-rg"  # Resource group containing DNS zone

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
echo -e "${BLUE}Each region auto-registers & gets unique credentials!${NC}"
echo -e "${BLUE}DNS: orbx-{region}.${DNS_ZONE_NAME}${NC}\n"

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

# Create DNS CNAME record
create_dns_cname() {
    local region=$1
    local container_fqdn=$2
    local subdomain="orbx-${region}"
    
    # Delete existing record if exists
    az network dns record-set cname delete \
        --resource-group $DNS_RESOURCE_GROUP \
        --zone-name $DNS_ZONE_NAME \
        --name $subdomain \
        --yes --output none 2>/dev/null || true
    
    # Create CNAME record
    az network dns record-set cname create \
        --resource-group $DNS_RESOURCE_GROUP \
        --zone-name $DNS_ZONE_NAME \
        --name $subdomain \
        --ttl 300 \
        --output none 2>/dev/null
    
    az network dns record-set cname set-record \
        --resource-group $DNS_RESOURCE_GROUP \
        --zone-name $DNS_ZONE_NAME \
        --record-set-name $subdomain \
        --cname $container_fqdn \
        --output none 2>/dev/null
    
    if [ $? -eq 0 ]; then
        echo -e "   🌐 DNS: ${subdomain}.${DNS_ZONE_NAME} → ${container_fqdn}"
        return 0
    else
        echo -e "   ${YELLOW}⚠️  DNS creation failed (will use container FQDN)${NC}"
        return 1
    fi
}

# Deploy function
deploy_region() {
    local region=$1
    local info=$2
    IFS='|' read -r location country <<< "$info"
    
    local rg="orbx-${region}-rg"
    local container="orbx-${region}"
    local dns_label="orbx-${region}"
    local name="OrbX - $location"
    local custom_hostname="orbx-${region}.${DNS_ZONE_NAME}"
    
    echo -e "${GREEN}🌍 $location ($country)${NC}"
    
    # Create RG
    az group create --name $rg --location $region --tags Environment=Production --output none 2>/dev/null || return 1
    
    # Register or regenerate credentials
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
    
    # Deploy container
    az container create \
        --resource-group $rg --name $container --image $ACR_NAME.azurecr.io/$IMAGE_NAME:$VERSION \
        --dns-name-label $dns_label --ports 8443 51820 --cpu 2 --memory 4 \
        --registry-login-server $ACR_NAME.azurecr.io \
        --registry-username $ACR_USERNAME --registry-password $ACR_PASSWORD \
        --environment-variables ORBNET_ENDPOINT="$ORBNET_ENDPOINT" \
        --secure-environment-variables JWT_SECRET="$jwt" ORBNET_API_KEY="$key" \
        --restart-policy Always --output none 2>/dev/null || return 1
    
    # Get container FQDN and IP
    local container_fqdn=$(az container show --resource-group $rg --name $container --query "ipAddress.fqdn" -o tsv 2>/dev/null)
    local container_ip=$(az container show --resource-group $rg --name $container --query "ipAddress.ip" -o tsv 2>/dev/null)
    
    # Create DNS CNAME record
    local dns_created=false
    if create_dns_cname "$region" "$container_fqdn"; then
        dns_created=true
    fi
    
    # Determine final hostname
    local final_hostname
    if [ "$dns_created" = true ]; then
        final_hostname="$custom_hostname"
    else
        final_hostname="$container_fqdn"
    fi
    
    # Update OrbNet with hostname and IP
    orbnet_update_server_full "$ADMIN_TOKEN" "$sid" "$final_hostname" "$container_ip" 2>/dev/null
    
    echo -e "   ✅ https://${final_hostname}:8443"
    echo -e "   📍 IP: ${container_ip}"
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
echo -e "\n${BLUE}🤖 $SUCCESS servers deployed with DNS hostnames!${NC}"
echo -e "${BLUE}📡 Format: orbx-{region}.${DNS_ZONE_NAME}${NC}"
echo -e "\n${YELLOW}Next: ./test-all-regions.sh${NC}"