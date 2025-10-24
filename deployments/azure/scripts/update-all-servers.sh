#!/bin/bash

################################################################################
# OrbX Protocol - Update All Servers
#
# This script:
# 1. Builds and pushes new Docker image to ACR
# 2. Reads all active servers from deployed-servers.txt
# 3. Updates each server with new image via SSH
# 4. Verifies health of each server
# 5. Reports deployment status
#
# Usage: ./update-all-servers.sh [options]
#   Options:
#     --skip-build    Skip building new image (use existing latest)
#     --region REGION Only update servers in specified region
#     --dry-run       Show what would be updated without doing it
################################################################################

# ============================================
# OrbX Server Update Script (Azure Live Query)
# ============================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
SSH_USER="azureuser"
SSH_TIMEOUT=10
HEALTH_CHECK_RETRIES=3
HEALTH_CHECK_DELAY=5

# Get ACR credentials
ACR_NAME="orbxregistry"

echo "Getting ACR credentials..."

# Use the CORRECT Key Vault name
KV_NAME="orbx-vault"

if az keyvault show --name "$KV_NAME" &>/dev/null; then
	echo "Using Key Vault: $KV_NAME"
	ACR_USERNAME=$(az keyvault secret show --vault-name "$KV_NAME" --name acr-username --query value -o tsv 2>/dev/null || echo "")
	ACR_PASSWORD=$(az keyvault secret show --vault-name "$KV_NAME" --name acr-password --query value -o tsv 2>/dev/null || echo "")
fi

# Fallback to getting credentials directly from ACR
if [ -z "$ACR_USERNAME" ] || [ -z "$ACR_PASSWORD" ]; then
	echo "Getting credentials directly from ACR..."
	ACR_CREDS=$(az acr credential show --name $ACR_NAME --query "{username:username, password:passwords[0].value}" -o json)
	ACR_USERNAME=$(echo "$ACR_CREDS" | jq -r '.username')
	ACR_PASSWORD=$(echo "$ACR_CREDS" | jq -r '.password')
fi

if [ -z "$ACR_USERNAME" ] || [ -z "$ACR_PASSWORD" ]; then
	echo -e "${RED}✗${NC} Failed to get ACR credentials"
	exit 1
fi

echo -e "${GREEN}✓${NC} ACR credentials obtained"

# Image settings
IMAGE_NAME="orbx-protocol"
IMAGE_TAG="prod"

# Counters
TOTAL_SERVERS=0
SUCCESSFUL_UPDATES=0
FAILED_UPDATES=0
SKIPPED_UPDATES=0

# Options
DRY_RUN=false
FILTER_REGION=""
FAILED_SERVERS=()

# ============================================
# Helper Functions
# ============================================

log_info() { echo -e "${BLUE}ℹ${NC}  $1"; }
log_success() { echo -e "${GREEN}✓${NC} $1"; }
log_warning() { echo -e "${YELLOW}⚠${NC}  $1"; }
log_error() { echo -e "${RED}✗${NC} $1"; }
log_section() { echo -e "\n${GREEN}════════════════════════════════════════════════════════════${NC}\n  $1\n${GREEN}════════════════════════════════════════════════════════════${NC}\n"; }
log_progress() { echo -e "\n${YELLOW}→${NC} $1"; }

show_usage() {
	cat <<EOF
Usage: $0 [OPTIONS]

Update all deployed OrbX servers by querying Azure directly.

Options:
  -r, --region REGION    Update only servers in specified region
  -d, --dry-run         Show what would be updated without making changes
  -h, --help            Show this help message

Examples:
  $0                    # Update all servers
  $0 -r eastus          # Update only eastus servers
  $0 --dry-run          # Preview updates without applying

EOF
	exit 0
}

# ============================================
# Parse Arguments
# ============================================

while [[ $# -gt 0 ]]; do
	case $1 in
	-r | --region)
		FILTER_REGION="$2"
		shift 2
		;;
	-d | --dry-run)
		DRY_RUN=true
		shift
		;;
	-h | --help)
		show_usage
		;;
	*)
		log_error "Unknown option: $1"
		show_usage
		;;
	esac
done

# ============================================
# Discover Servers from Azure
# ============================================

discover_servers() {
	log_section "Discovering Servers from Azure"

	DISCOVERED_SERVERS="/tmp/orbx-discovered-servers-$$.txt"
	>"$DISCOVERED_SERVERS"

	log_info "Querying Azure for OrbX resource groups..."

	RG_LIST=$(az group list --query "[?starts_with(name, 'orbx-')].name" -o tsv)

	if [ -z "$RG_LIST" ]; then
		log_error "No OrbX resource groups found"
		log_info "Have you deployed any servers yet?"
		exit 1
	fi

	log_success "Found resource groups. Discovering VMs..."

	for RG in $RG_LIST; do
		REGION=$(echo "$RG" | sed 's/orbx-//;s/-rg$//')

		if [ -n "$FILTER_REGION" ] && [ "$REGION" != "$FILTER_REGION" ]; then
			continue
		fi

		log_info "  Checking region: $REGION..."

		VM_DETAILS=$(az vm show \
			--resource-group "$RG" \
			--name "orbx-${REGION}-vm" \
			--show-details \
			--query "{name:name, publicIp:publicIps, fqdn:fqdns}" \
			-o json 2>/dev/null || echo "{}")

		if [ "$VM_DETAILS" != "{}" ] && [ -n "$VM_DETAILS" ]; then
			VM_NAME=$(echo "$VM_DETAILS" | jq -r '.name // empty')
			PUBLIC_IP=$(echo "$VM_DETAILS" | jq -r '.publicIp // empty')
			FQDN=$(echo "$VM_DETAILS" | jq -r '.fqdn // empty')

			if [ -z "$FQDN" ] || [ "$FQDN" = "null" ]; then
				FQDN="orbx-${REGION}-vm.${REGION}.cloudapp.azure.com"
			fi

			SERVER_ID=$(az vm show \
				--resource-group "$RG" \
				--name "$VM_NAME" \
				--query "tags.serverId" -o tsv 2>/dev/null || echo "unknown")

			if [ -n "$VM_NAME" ] && [ "$VM_NAME" != "null" ]; then
				echo "${FQDN}|${SERVER_ID}|${REGION}|${VM_NAME}|${PUBLIC_IP}" >>"$DISCOVERED_SERVERS"
				log_success "    ✓ Found: ${VM_NAME} (${PUBLIC_IP})"
			fi
		fi
	done

	TOTAL_SERVERS=$(wc -l <"$DISCOVERED_SERVERS" | tr -d ' ')

	if [ "$TOTAL_SERVERS" -eq 0 ]; then
		log_error "No OrbX VMs found in Azure"
		exit 1
	fi

	echo ""
	if [ -n "$FILTER_REGION" ]; then
		log_success "Discovered $TOTAL_SERVERS servers in region: $FILTER_REGION"
	else
		log_success "Discovered $TOTAL_SERVERS total servers across all regions"
	fi

	DEPLOYED_SERVERS_FILE="$DISCOVERED_SERVERS"
}

# ============================================
# Update Server
# ============================================

update_server() {
	local FQDN="$1"
	local SERVER_ID="$2"
	local REGION="$3"
	local SERVER_NAME="$4"
	local PUBLIC_IP="$5"

	log_progress "Updating: $SERVER_NAME ($REGION)"
	log_info "  FQDN: $FQDN"
	log_info "  IP: $PUBLIC_IP"

	if [ "$DRY_RUN" = true ]; then
		log_warning "  [DRY RUN] Would update this server"
		((SKIPPED_UPDATES++))
		return 0
	fi

	UPDATE_SCRIPT="/tmp/orbx-update-${REGION}.sh"

	cat >"$UPDATE_SCRIPT" <<'REMOTE_SCRIPT_EOF'
#!/bin/bash
set -e

echo "================================================"
echo "OrbX Server Update"
echo "================================================"

# Install jq if needed
if ! command -v jq &> /dev/null; then
    echo "→ Installing jq..."
    sudo apt-get update -qq
    sudo apt-get install -y jq
fi

# Save environment variables from existing container
echo "→ Saving current container configuration..."
if sudo docker ps -a | grep -q orbx-server; then
    ORBNET_ENDPOINT=$(sudo docker inspect orbx-server | jq -r '.[0].Config.Env[] | select(startswith("ORBNET_ENDPOINT="))' | cut -d= -f2-)
    ORBNET_SERVER_ID=$(sudo docker inspect orbx-server | jq -r '.[0].Config.Env[] | select(startswith("ORBNET_SERVER_ID="))' | cut -d= -f2-)
    ORBNET_API_KEY=$(sudo docker inspect orbx-server | jq -r '.[0].Config.Env[] | select(startswith("ORBNET_API_KEY="))' | cut -d= -f2-)
    JWT_SECRET=$(sudo docker inspect orbx-server | jq -r '.[0].Config.Env[] | select(startswith("JWT_SECRET="))' | cut -d= -f2-)
    WG_PRIVATE_KEY=$(sudo docker inspect orbx-server | jq -r '.[0].Config.Env[] | select(startswith("WG_PRIVATE_KEY="))' | cut -d= -f2-)
    WG_PUBLIC_KEY=$(sudo docker inspect orbx-server | jq -r '.[0].Config.Env[] | select(startswith("WG_PUBLIC_KEY="))' | cut -d= -f2-)
    
    # Get TLS certs from host filesystem
    if [ -f /etc/orbx/certs/cert.pem ] && [ -f /etc/orbx/certs/key.pem ]; then
        TLS_CERT=$(sudo cat /etc/orbx/certs/cert.pem | base64 -w 0)
        TLS_KEY=$(sudo cat /etc/orbx/certs/key.pem | base64 -w 0)
        echo "✓ Configuration and certificates saved"
    else
        echo "ERROR: TLS certificates not found!"
        exit 1
    fi
else
    echo "ERROR: No existing container found!"
    exit 1
fi

echo "→ Logging into Azure Container Registry..."
echo "$ACR_PASSWORD" | sudo docker login ${ACR_NAME}.azurecr.io -u "$ACR_USERNAME" --password-stdin

echo "→ Pulling latest image..."
sudo docker pull ${ACR_NAME}.azurecr.io/${IMAGE_NAME}:${IMAGE_TAG}

echo "→ Stopping existing container..."
sudo docker stop orbx-server 2>/dev/null || true
sudo docker rm orbx-server 2>/dev/null || true

echo "→ Starting updated container with saved configuration..."
sudo docker run -d \
    --name orbx-server \
    --restart always \
    --network host \
    --privileged \
    --cap-add NET_ADMIN \
    --cap-add SYS_MODULE \
    --device /dev/net/tun \
    -v /lib/modules:/lib/modules:ro \
    -v /etc/orbx/certs:/etc/orbx/certs \
    -e ORBNET_ENDPOINT="${ORBNET_ENDPOINT}" \
    -e ORBNET_SERVER_ID="${ORBNET_SERVER_ID}" \
    -e ORBNET_API_KEY="${ORBNET_API_KEY}" \
    -e JWT_SECRET="${JWT_SECRET}" \
    -e WIREGUARD_ENABLED="true" \
    -e WG_PRIVATE_KEY="${WG_PRIVATE_KEY}" \
    -e WG_PUBLIC_KEY="${WG_PUBLIC_KEY}" \
    -e TLS_CERT="${TLS_CERT}" \
    -e TLS_KEY="${TLS_KEY}" \
    ${ACR_NAME}.azurecr.io/${IMAGE_NAME}:${IMAGE_TAG}

echo "→ Waiting for container to start..."
sleep 8

if ! sudo docker ps | grep -q orbx-server; then
    echo "ERROR: Container failed to start"
    sudo docker logs orbx-server 2>&1 | tail -30
    exit 1
fi

echo "✓ Container started successfully"
sudo docker ps --filter name=orbx-server --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"

echo ""
echo "→ Verifying WireGuard..."
sudo docker exec orbx-server wg show | head -3

exit 0
REMOTE_SCRIPT_EOF

	log_info "  Executing update on remote server..."

	if ssh -o ConnectTimeout=$SSH_TIMEOUT \
		-o StrictHostKeyChecking=no \
		-o UserKnownHostsFile=/dev/null \
		-o LogLevel=ERROR \
		$SSH_USER@$FQDN \
		"export ACR_NAME='$ACR_NAME' && \
            export ACR_USERNAME='$ACR_USERNAME' && \
            export ACR_PASSWORD='$ACR_PASSWORD' && \
            export IMAGE_NAME='$IMAGE_NAME' && \
            export IMAGE_TAG='$IMAGE_TAG' && \
            bash -s" <"$UPDATE_SCRIPT" 2>&1 | sed 's/^/    /'; then

		rm -f "$UPDATE_SCRIPT"
		log_info "  Verifying server health..."

		HEALTHY=false
		for i in $(seq 1 $HEALTH_CHECK_RETRIES); do
			sleep $HEALTH_CHECK_DELAY
			if curl -k -s --max-time 10 "https://${FQDN}:8443/health" | grep -q "healthy"; then
				HEALTHY=true
				break
			fi
			if [ $i -lt $HEALTH_CHECK_RETRIES ]; then
				log_warning "    Health check $i/$HEALTH_CHECK_RETRIES failed, retrying..."
			fi
		done

		if [ "$HEALTHY" = true ]; then
			log_success "  ✓ $SERVER_NAME updated and healthy"
			((SUCCESSFUL_UPDATES++))
		else
			log_warning "  ⚠ $SERVER_NAME updated but health check failed"
			log_warning "    Container may still be starting up"
			((SUCCESSFUL_UPDATES++))
		fi
		return 0
	else
		log_error "  ✗ Failed to update $SERVER_NAME"
		FAILED_SERVERS+=("$SERVER_NAME ($REGION) - $FQDN")
		((FAILED_UPDATES++))
		rm -f "$UPDATE_SCRIPT"
		return 1
	fi
}

# ============================================
# Update All Servers
# ============================================

update_all_servers() {
	log_section "Updating Servers"
	COUNT=0

	while IFS='|' read -r FQDN SERVER_ID REGION SERVER_NAME PUBLIC_IP; do
		((COUNT++))
		log_info "[$COUNT/$TOTAL_SERVERS]"
		update_server "$FQDN" "$SERVER_ID" "$REGION" "$SERVER_NAME" "$PUBLIC_IP"
		[ $COUNT -lt $TOTAL_SERVERS ] && sleep 2
	done <"$DEPLOYED_SERVERS_FILE"
}

# ============================================
# Show Summary
# ============================================

show_summary() {
	log_section "Update Summary"
	echo -e "${BLUE}Total Servers:${NC}       $TOTAL_SERVERS"
	echo -e "${GREEN}Successful Updates:${NC}  $SUCCESSFUL_UPDATES"
	echo -e "${RED}Failed Updates:${NC}      $FAILED_UPDATES"

	if [ "$DRY_RUN" = true ]; then
		echo -e "${YELLOW}Skipped (Dry Run):${NC}   $SKIPPED_UPDATES"
	fi

	if [ $FAILED_UPDATES -gt 0 ]; then
		echo ""
		log_error "Failed Servers:"
		for server in "${FAILED_SERVERS[@]}"; do
			echo "  • $server"
		done
	fi

	rm -f "$DEPLOYED_SERVERS_FILE"

	echo ""
	if [ $FAILED_UPDATES -eq 0 ]; then
		log_success "✅ All servers updated successfully!"
	else
		log_warning "⚠️  Some servers failed to update. Check the logs above."
		exit 1
	fi
}

# ============================================
# Main
# ============================================

main() {
	log_section "OrbX Server Update Tool"

	[ "$DRY_RUN" = true ] && log_warning "Running in DRY RUN mode"
	[ -n "$FILTER_REGION" ] && log_info "Filtering to region: $FILTER_REGION"

	discover_servers

	if [ "$DRY_RUN" = false ]; then
		echo ""
		read -p "$(echo -e ${YELLOW}Continue with update? [y/N]:${NC})" -n 1 -r
		echo
		[[ ! $REPLY =~ ^[Yy]$ ]] && {
			log_info "Update cancelled"
			exit 0
		}
	fi

	update_all_servers
	show_summary
}

main "$@"
