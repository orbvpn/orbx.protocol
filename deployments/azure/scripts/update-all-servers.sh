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

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
ACR_NAME="orbxregistry"
IMAGE_NAME="orbx-protocol"
IMAGE_TAG="prod"
DEPLOYED_SERVERS_FILE="deployed-servers.txt"
SSH_USER="azureuser"
SSH_TIMEOUT=30
HEALTH_CHECK_RETRIES=5
HEALTH_CHECK_DELAY=10

# Parse command line arguments
SKIP_BUILD=false
FILTER_REGION=""
DRY_RUN=false

while [[ $# -gt 0 ]]; do
	case $1 in
	--skip-build)
		SKIP_BUILD=true
		shift
		;;
	--region)
		FILTER_REGION="$2"
		shift 2
		;;
	--dry-run)
		DRY_RUN=true
		shift
		;;
	*)
		echo "Unknown option: $1"
		echo "Usage: $0 [--skip-build] [--region REGION] [--dry-run]"
		exit 1
		;;
	esac
done

# Statistics
TOTAL_SERVERS=0
SUCCESSFUL_UPDATES=0
FAILED_UPDATES=0
SKIPPED_UPDATES=0
declare -a FAILED_SERVERS

################################################################################
# Helper Functions
################################################################################

log_section() {
	echo ""
	echo -e "${CYAN}════════════════════════════════════════════════════════════${NC}"
	echo -e "${CYAN}  $1${NC}"
	echo -e "${CYAN}════════════════════════════════════════════════════════════${NC}"
	echo ""
}

log_info() {
	echo -e "${BLUE}ℹ ${NC} $1"
}

log_success() {
	echo -e "${GREEN}✓${NC} $1"
}

log_warning() {
	echo -e "${YELLOW}⚠${NC} $1"
}

log_error() {
	echo -e "${RED}✗${NC} $1"
}

log_progress() {
	echo -e "${MAGENTA}►${NC} $1"
}

################################################################################
# Main Functions
################################################################################

# Get ACR credentials from Azure Key Vault
get_acr_credentials() {
	log_info "Retrieving ACR credentials from Azure Key Vault..."

	ACR_USERNAME=$(az keyvault secret show --vault-name "orbx-vault" --name "ACR-USERNAME" --query value -o tsv)
	ACR_PASSWORD=$(az keyvault secret show --vault-name "orbx-vault" --name "ACR-PASSWORD" --query value -o tsv)

	if [ -z "$ACR_USERNAME" ] || [ -z "$ACR_PASSWORD" ]; then
		log_error "Failed to retrieve ACR credentials from Key Vault"
		exit 1
	fi

	log_success "ACR credentials retrieved"
}

# Build and push new Docker image
build_and_push_image() {
	if [ "$SKIP_BUILD" = true ]; then
		log_warning "Skipping build (--skip-build flag set)"
		return 0
	fi

	log_section "Building and Pushing New Docker Image"

	# Get script directory and navigate to project root
	SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
	PROJECT_ROOT="$SCRIPT_DIR/../../.."

	log_info "Project root: $PROJECT_ROOT"
	cd "$PROJECT_ROOT"

	# Verify Dockerfile exists
	if [ ! -f "Dockerfile" ]; then
		log_error "Dockerfile not found at: $(pwd)/Dockerfile"
		exit 1
	fi

	# Login to ACR
	log_info "Logging in to Azure Container Registry..."
	az acr login --name $ACR_NAME

	# Build image
	ACR_LOGIN_SERVER="$ACR_NAME.azurecr.io"
	BUILD_TIMESTAMP=$(date +%Y%m%d-%H%M%S)

	log_info "Building Docker image..."
	log_info "Image: $ACR_LOGIN_SERVER/$IMAGE_NAME:$IMAGE_TAG"

	docker build \
		--platform linux/amd64 \
		-t $ACR_LOGIN_SERVER/$IMAGE_NAME:$IMAGE_TAG \
		-t $ACR_LOGIN_SERVER/$IMAGE_NAME:$BUILD_TIMESTAMP \
		-f Dockerfile \
		. || {
		log_error "Docker build failed"
		exit 1
	}

	log_success "Image built successfully"

	# Push to registry
	log_info "Pushing to Azure Container Registry..."

	docker push $ACR_LOGIN_SERVER/$IMAGE_NAME:$IMAGE_TAG || {
		log_error "Docker push failed"
		exit 1
	}

	docker push $ACR_LOGIN_SERVER/$IMAGE_NAME:$BUILD_TIMESTAMP || {
		log_warning "Failed to push timestamped image (non-critical)"
	}

	log_success "Image pushed successfully"
	log_success "Tagged as: $IMAGE_TAG and $BUILD_TIMESTAMP"
}

# Load servers from deployed-servers.txt
load_servers() {
	log_section "Loading Server List"

	if [ ! -f "$DEPLOYED_SERVERS_FILE" ]; then
		log_error "Server list not found: $DEPLOYED_SERVERS_FILE"
		log_info "Have you deployed any servers yet?"
		exit 1
	fi

	# Count total servers (optionally filtered by region)
	if [ -n "$FILTER_REGION" ]; then
		TOTAL_SERVERS=$(grep "|$FILTER_REGION|" "$DEPLOYED_SERVERS_FILE" | wc -l | tr -d ' ')
		log_info "Found $TOTAL_SERVERS servers in region: $FILTER_REGION"
	else
		TOTAL_SERVERS=$(wc -l <"$DEPLOYED_SERVERS_FILE" | tr -d ' ')
		log_info "Found $TOTAL_SERVERS total servers"
	fi

	if [ "$TOTAL_SERVERS" -eq 0 ]; then
		log_error "No servers found to update"
		exit 1
	fi
}

# Update a single server
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

	# Create update script that will run on remote server
	local UPDATE_SCRIPT="/tmp/orbx-update-${REGION}.sh"

	cat >"$UPDATE_SCRIPT" <<'REMOTE_SCRIPT_EOF'
#!/bin/bash
set -e

echo "================================================"
echo "OrbX Server Update"
echo "================================================"

# Login to ACR
echo "→ Logging into Azure Container Registry..."
echo "$ACR_PASSWORD" | docker login ${ACR_NAME}.azurecr.io -u "$ACR_USERNAME" --password-stdin

# Pull latest image
echo "→ Pulling latest image..."
docker pull ${ACR_NAME}.azurecr.io/${IMAGE_NAME}:${IMAGE_TAG}

# Stop existing container
echo "→ Stopping existing container..."
docker stop orbx-server 2>/dev/null || true
docker rm orbx-server 2>/dev/null || true

# Start new container with same configuration
echo "→ Starting updated container..."
docker run -d \
    --name orbx-server \
    --restart always \
    --privileged \
    --cap-add NET_ADMIN \
    --cap-add SYS_MODULE \
    --device /dev/net/tun \
    -p 8443:8443 \
    -p 51820:51820 \
    -v /lib/modules:/lib/modules:ro \
    -v /etc/orbx/certs:/etc/orbx/certs:ro \
    -e ORBNET_ENDPOINT="$ORBNET_ENDPOINT" \
    -e ORBNET_SERVER_ID="$ORBNET_SERVER_ID" \
    -e ORBNET_API_KEY="$ORBNET_API_KEY" \
    -e JWT_SECRET="$JWT_SECRET" \
    -e WIREGUARD_ENABLED="true" \
    -e WG_PRIVATE_KEY="$WG_PRIVATE_KEY" \
    -e WG_PUBLIC_KEY="$WG_PUBLIC_KEY" \
    ${ACR_NAME}.azurecr.io/${IMAGE_NAME}:${IMAGE_TAG}

# Wait for container to be healthy
echo "→ Waiting for container to start..."
sleep 5

# Check if container is running
if ! docker ps | grep -q orbx-server; then
    echo "ERROR: Container failed to start"
    echo "Last logs:"
    docker logs orbx-server 2>&1 | tail -20
    exit 1
fi

echo "✓ Container started successfully"
echo ""
echo "Container info:"
docker ps --filter name=orbx-server --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"

exit 0
REMOTE_SCRIPT_EOF

	# Get environment variables from the VM (they're already set during deployment)
	log_info "  Executing update on remote server..."

	# Execute update script via SSH
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

		# Remove temporary script
		rm -f "$UPDATE_SCRIPT"

		# Verify health endpoint
		log_info "  Verifying server health..."
		local HEALTHY=false

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
			return 0
		else
			log_warning "  ⚠ $SERVER_NAME updated but health check failed"
			log_warning "    Container may still be starting up"
			((SUCCESSFUL_UPDATES++))
			return 0
		fi
	else
		log_error "  ✗ Failed to update $SERVER_NAME"
		FAILED_SERVERS+=("$SERVER_NAME ($REGION) - $FQDN")
		((FAILED_UPDATES++))
		rm -f "$UPDATE_SCRIPT"
		return 1
	fi
}

# Update all servers
update_all_servers() {
	log_section "Updating Servers"

	local COUNT=0

	while IFS='|' read -r FQDN SERVER_ID REGION WG_PUBLIC_KEY SERVER_NAME TYPE PUBLIC_IP; do
		# Skip if filtering by region and this isn't the target region
		if [ -n "$FILTER_REGION" ] && [ "$REGION" != "$FILTER_REGION" ]; then
			continue
		fi

		((COUNT++))
		echo ""
		log_info "═══ Progress: $COUNT/$TOTAL_SERVERS ═══"

		update_server "$FQDN" "$SERVER_ID" "$REGION" "$SERVER_NAME" "$PUBLIC_IP"

		# Small delay between updates to avoid overwhelming SSH
		sleep 2

	done <"$DEPLOYED_SERVERS_FILE"
}

# Print summary report
print_summary() {
	log_section "Update Summary"

	echo ""
	echo "╔════════════════════════════════════════════════════════════╗"
	echo "║                   UPDATE RESULTS                           ║"
	echo "╚════════════════════════════════════════════════════════════╝"
	echo ""
	echo -e "  Total Servers:        ${CYAN}$TOTAL_SERVERS${NC}"
	echo -e "  ${GREEN}Successful Updates:  $SUCCESSFUL_UPDATES${NC}"

	if [ "$DRY_RUN" = true ]; then
		echo -e "  ${YELLOW}Skipped (Dry Run):   $SKIPPED_UPDATES${NC}"
	fi

	if [ $FAILED_UPDATES -gt 0 ]; then
		echo -e "  ${RED}Failed Updates:      $FAILED_UPDATES${NC}"
		echo ""
		echo "Failed servers:"
		for server in "${FAILED_SERVERS[@]}"; do
			echo -e "    ${RED}✗${NC} $server"
		done
		echo ""
		log_warning "Some servers failed to update. Please check them manually."
		echo ""
		echo "To check a specific server:"
		echo "  ssh azureuser@<FQDN> 'sudo docker logs orbx-server'"
		echo ""
		exit 1
	else
		echo ""
		if [ "$DRY_RUN" = true ]; then
			log_success "Dry run completed successfully!"
			log_info "Run without --dry-run to perform actual updates"
		else
			log_success "All servers updated successfully! 🎉"
			log_info "All servers are now running the latest version"
		fi
		echo ""
	fi
}

################################################################################
# Main Script
################################################################################

main() {
	echo ""
	echo "╔════════════════════════════════════════════════════════════╗"
	echo "║                                                            ║"
	echo "║         OrbX Protocol - Update All Servers                ║"
	echo "║                                                            ║"
	echo "╚════════════════════════════════════════════════════════════╝"
	echo ""

	# Show configuration
	if [ "$DRY_RUN" = true ]; then
		log_warning "DRY RUN MODE - No actual changes will be made"
	fi

	if [ "$SKIP_BUILD" = true ]; then
		log_warning "Skipping Docker build - using existing image"
	fi

	if [ -n "$FILTER_REGION" ]; then
		log_info "Filtering to region: $FILTER_REGION"
	fi

	# Confirm action
	if [ "$DRY_RUN" = false ]; then
		echo ""
		echo -e "${YELLOW}This will update ALL OrbX servers in production.${NC}"
		echo -e "${YELLOW}Each server will be briefly unavailable during update.${NC}"
		echo ""
		read -p "Continue? (yes/no): " CONFIRM

		if [ "$CONFIRM" != "yes" ]; then
			log_warning "Update cancelled by user"
			exit 0
		fi
	fi

	# Execute update process
	get_acr_credentials
	build_and_push_image
	load_servers
	update_all_servers
	print_summary
}

# Run main function
main
