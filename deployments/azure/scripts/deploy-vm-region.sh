#!/bin/bash

# Deploy OrbX server to Azure VM with full WireGuard support
# Usage: ./deploy-vm-region.sh <region> [vm-size]

set -e

# Configuration
REGION=${1:-eastus}
VM_SIZE=${2:-Standard_B2s} # 2 vCPU, 4GB RAM (~$30-40/month)
RESOURCE_GROUP="orbx-${REGION}-rg"
VM_NAME="orbx-${REGION}-vm"
ACR_NAME="orbxregistry"
KEYVAULT_NAME="orbx-vault"
NSG_NAME="orbx-${REGION}-nsg"
PUBLIC_IP_NAME="orbx-${REGION}-ip"
NIC_NAME="orbx-${REGION}-nic"
VNET_NAME="orbx-${REGION}-vnet"
SUBNET_NAME="orbx-${REGION}-subnet"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}☁️  Deploying OrbX Protocol VM to ${REGION}${NC}"
echo "=============================================="

# ============================================
# Step 0: Get SHARED JWT secret from Key Vault
# ============================================
echo -e "\n${YELLOW}🔐 Retrieving SHARED JWT secret from Key Vault...${NC}"

# Get the shared JWT secret that OrbNet uses
SHARED_JWT_SECRET=$(az keyvault secret show \
	--vault-name $KEYVAULT_NAME \
	--name "JWT-SECRET" \
	--query value -o tsv)

if [ -z "$SHARED_JWT_SECRET" ] || [ "$SHARED_JWT_SECRET" = "null" ]; then
	echo -e "${RED}❌ SHARED JWT secret not found in Key Vault!${NC}"
	echo -e "${YELLOW}This secret should be the SAME secret that OrbNet uses.${NC}"
	echo -e "${YELLOW}Please run setup-azure.sh first to configure the shared secret.${NC}"
	exit 1
fi

echo -e "${GREEN}✅ Retrieved shared JWT secret (length: ${#SHARED_JWT_SECRET})${NC}"

# ============================================
# Step 0: Check required tools
# ============================================
if ! command -v wg &>/dev/null; then
	echo -e "${RED}❌ WireGuard tools not installed locally${NC}"
	echo -e "${YELLOW}Install with: sudo apt install wireguard-tools (or brew install wireguard-tools on Mac)${NC}"
	exit 1
fi

if ! command -v jq &>/dev/null; then
	echo -e "${RED}❌ jq not installed${NC}"
	echo -e "${YELLOW}Install with: sudo apt install jq (or brew install jq on Mac)${NC}"
	exit 1
fi

if ! command -v az &>/dev/null; then
	echo -e "${RED}❌ Azure CLI not installed${NC}"
	exit 1
fi

# ============================================
# Step 1: Get shared secrets from Key Vault
# ============================================
echo -e "\n${YELLOW}🔑 Retrieving shared secrets from Key Vault...${NC}"
ORBNET_ENDPOINT=$(az keyvault secret show --vault-name $KEYVAULT_NAME --name "ORBNET-ENDPOINT" --query value -o tsv)
ORBNET_AUTH_TOKEN=$(az keyvault secret show --vault-name $KEYVAULT_NAME --name "ORBNET-AUTH-TOKEN" --query value -o tsv)
ACR_USERNAME=$(az keyvault secret show --vault-name $KEYVAULT_NAME --name "ACR-USERNAME" --query value -o tsv)
ACR_PASSWORD=$(az keyvault secret show --vault-name $KEYVAULT_NAME --name "ACR-PASSWORD" --query value -o tsv)

# ✅ TLS certs will be generated uniquely on each VM
echo -e "${GREEN}✅ Retrieved all secrets from Key Vault${NC}"
echo -e "${YELLOW}TLS certificates will be generated uniquely on each VM${NC}"

# Validate secrets were retrieved
if [ -z "$ORBNET_ENDPOINT" ] || [ -z "$ORBNET_AUTH_TOKEN" ]; then
	echo -e "${RED}❌ Failed to retrieve required secrets from Key Vault${NC}"
	exit 1
fi

echo -e "${GREEN}✓ Secrets retrieved successfully${NC}"

# Generate UNIQUE WireGuard keys for this region
echo -e "\n${YELLOW}🔑 Generating unique WireGuard keys for ${REGION}...${NC}"
WG_PRIVATE_KEY=$(wg genkey)
WG_PUBLIC_KEY=$(echo "$WG_PRIVATE_KEY" | wg pubkey)
echo -e "${GREEN}✓ WireGuard keys generated for this region${NC}"
echo -e "${GREEN}Public Key: ${WG_PUBLIC_KEY}${NC}"

# ============================================
# Step 2: Register this server with OrbNet API
# ============================================
echo -e "\n${YELLOW}📝 Registering server with OrbNet API...${NC}"

# Generate hostname
HOSTNAME="${VM_NAME}.${REGION}.cloudapp.azure.com"

# Map Azure region to country code
case $REGION in
eastus | eastus2 | westus | westus2 | westus3 | centralus | northcentralus | southcentralus | westcentralus)
	COUNTRY_CODE="US"
	LOCATION_NAME="United States"
	;;
canadacentral | canadaeast)
	COUNTRY_CODE="CA"
	LOCATION_NAME="Canada"
	;;
brazilsouth)
	COUNTRY_CODE="BR"
	LOCATION_NAME="Brazil"
	;;
northeurope)
	COUNTRY_CODE="IE"
	LOCATION_NAME="Ireland"
	;;
westeurope)
	COUNTRY_CODE="NL"
	LOCATION_NAME="Netherlands"
	;;
uksouth | ukwest)
	COUNTRY_CODE="GB"
	LOCATION_NAME="United Kingdom"
	;;
francecentral)
	COUNTRY_CODE="FR"
	LOCATION_NAME="France"
	;;
germanywestcentral)
	COUNTRY_CODE="DE"
	LOCATION_NAME="Germany"
	;;
norwayeast)
	COUNTRY_CODE="NO"
	LOCATION_NAME="Norway"
	;;
switzerlandnorth)
	COUNTRY_CODE="CH"
	LOCATION_NAME="Switzerland"
	;;
swedencentral)
	COUNTRY_CODE="SE"
	LOCATION_NAME="Sweden"
	;;
eastasia)
	COUNTRY_CODE="HK"
	LOCATION_NAME="Hong Kong"
	;;
southeastasia)
	COUNTRY_CODE="SG"
	LOCATION_NAME="Singapore"
	;;
japaneast | japanwest)
	COUNTRY_CODE="JP"
	LOCATION_NAME="Japan"
	;;
australiaeast | australiasoutheast)
	COUNTRY_CODE="AU"
	LOCATION_NAME="Australia"
	;;
centralindia | southindia)
	COUNTRY_CODE="IN"
	LOCATION_NAME="India"
	;;
uaenorth)
	COUNTRY_CODE="AE"
	LOCATION_NAME="UAE"
	;;
*)
	COUNTRY_CODE="US"
	LOCATION_NAME="Unknown"
	;;
esac

# Register server via GraphQL
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
SERVER_NAME="OrbX-${COUNTRY_CODE}-${REGION}-${TIMESTAMP}"

REGISTER_RESPONSE=$(curl -s -X POST "$ORBNET_ENDPOINT" \
	-H "Content-Type: application/json" \
	-H "Authorization: Bearer $ORBNET_AUTH_TOKEN" \
	-d '{
    "query": "mutation RegisterOrbXServer($input: OrbXServerInput!) { registerOrbXServer(input: $input) { server { id name region hostname } apiKey jwtSecret } }",
    "variables": {
      "input": {
        "name": "'"${SERVER_NAME}"'",
        "region": "'"${REGION}"'",
        "hostname": "'"${HOSTNAME}"'",
        "ipAddress": "'"${HOSTNAME}"'",
        "port": 8443,
        "location": "'"${LOCATION_NAME}"'",
        "country": "'"${COUNTRY_CODE}"'",
        "protocols": ["wireguard", "teams", "google-meet", "shaparak", "doh", "https"],
        "maxConnections": 1000,
        "publicKey": "'"${WG_PUBLIC_KEY}"'"
      }
    }
  }')

# Extract credentials
ORBNET_API_KEY=$(echo $REGISTER_RESPONSE | jq -r '.data.registerOrbXServer.apiKey')
JWT_SECRET=$(echo $REGISTER_RESPONSE | jq -r '.data.registerOrbXServer.jwtSecret')
ORBNET_SERVER_ID=$(echo $REGISTER_RESPONSE | jq -r '.data.registerOrbXServer.server.id')

if [ "$ORBNET_API_KEY" = "null" ] || [ -z "$ORBNET_API_KEY" ]; then
	# Check if error is because server already exists
	if echo "$REGISTER_RESPONSE" | grep -q "already exists"; then
		echo -e "${YELLOW}⚠️  Server name conflict detected${NC}"
		echo -e "${YELLOW}Creating server with unique identifier...${NC}"

		# Generate truly unique name using process ID and timestamp
		UNIQUE_ID="$(date +%s)-$$"
		SERVER_NAME="OrbX-${COUNTRY_CODE}-${REGION}-${UNIQUE_ID}"

		# Try registering again with unique name
		REGISTER_RESPONSE=$(curl -s -X POST "$ORBNET_ENDPOINT" \
			-H "Content-Type: application/json" \
			-H "Authorization: Bearer $ORBNET_AUTH_TOKEN" \
			-d '{
        "query": "mutation RegisterOrbXServer($input: OrbXServerInput!) { registerOrbXServer(input: $input) { server { id name region hostname } apiKey jwtSecret } }",
        "variables": {
          "input": {
            "name": "'"${SERVER_NAME}"'",
            "region": "'"${REGION}-$(date +%s)"'",
            "hostname": "'"${HOSTNAME}"'",
            "ipAddress": "'"${HOSTNAME}"'",
            "port": 8443,
            "location": "'"${LOCATION_NAME}"'",
            "country": "'"${COUNTRY_CODE}"'",
            "protocols": ["wireguard", "teams", "google-meet", "shaparak", "doh", "https"],
            "maxConnections": 1000,
            "publicKey": "'"${WG_PUBLIC_KEY}"'"
          }
        }
      }')

		ORBNET_API_KEY=$(echo $REGISTER_RESPONSE | jq -r '.data.registerOrbXServer.apiKey')
		JWT_SECRET=$(echo $REGISTER_RESPONSE | jq -r '.data.registerOrbXServer.jwtSecret')
		ORBNET_SERVER_ID=$(echo $REGISTER_RESPONSE | jq -r '.data.registerOrbXServer.server.id')

		if [ "$ORBNET_API_KEY" = "null" ] || [ -z "$ORBNET_API_KEY" ]; then
			echo -e "${RED}❌ Still failed to register server${NC}"
			echo -e "${RED}Response:${NC}"
			echo "$REGISTER_RESPONSE" | jq '.' 2>/dev/null || echo "$REGISTER_RESPONSE"
			exit 1
		fi

		echo -e "${GREEN}✅ Server registered with unique name: ${SERVER_NAME}${NC}"
	else
		echo -e "${RED}❌ Failed to register server with OrbNet API${NC}"
		echo -e "${RED}Response:${NC}"
		echo "$REGISTER_RESPONSE" | jq '.' 2>/dev/null || echo "$REGISTER_RESPONSE"
		exit 1
	fi
fi

# ✅ VERIFY the returned JWT secret matches our SHARED secret
if [ "$JWT_SECRET" != "$SHARED_JWT_SECRET" ]; then
	echo -e "${RED}⚠️  WARNING: Returned JWT secret doesn't match Key Vault!${NC}"
	echo -e "${YELLOW}Using Key Vault secret instead...${NC}"
	JWT_SECRET="$SHARED_JWT_SECRET"
fi

echo -e "${GREEN}✅ Server registered with OrbNet${NC}"
echo -e "${GREEN}Server Name: ${SERVER_NAME}${NC}"
echo -e "${GREEN}Server ID: ${ORBNET_SERVER_ID}${NC}"
echo -e "${GREEN}Region: ${REGION}${NC}"

# ============================================
# Step 3: Create resource group
# ============================================
echo -e "\n${YELLOW}📦 Creating resource group...${NC}"
az group create \
	--name $RESOURCE_GROUP \
	--location $REGION \
	--tags Environment=Production Application=OrbX Region=$REGION \
	>/dev/null

echo -e "${GREEN}✓ Resource group created${NC}"

# ============================================
# Step 4: Create network infrastructure
# ============================================
echo -e "\n${YELLOW}🌐 Creating network infrastructure...${NC}"

# Create Virtual Network
az network vnet create \
	--resource-group $RESOURCE_GROUP \
	--name $VNET_NAME \
	--address-prefix 10.0.0.0/16 \
	--subnet-name $SUBNET_NAME \
	--subnet-prefix 10.0.1.0/24 \
	>/dev/null

echo -e "${GREEN}✓ Virtual network created${NC}"

# Create Network Security Group
az network nsg create \
	--resource-group $RESOURCE_GROUP \
	--name $NSG_NAME \
	>/dev/null

# Allow HTTPS (8443)
az network nsg rule create \
	--resource-group $RESOURCE_GROUP \
	--nsg-name $NSG_NAME \
	--name Allow-HTTPS \
	--priority 1000 \
	--source-address-prefixes '*' \
	--source-port-ranges '*' \
	--destination-address-prefixes '*' \
	--destination-port-ranges 8443 \
	--access Allow \
	--protocol Tcp \
	>/dev/null

# Allow WireGuard (51820)
az network nsg rule create \
	--resource-group $RESOURCE_GROUP \
	--nsg-name $NSG_NAME \
	--name Allow-WireGuard \
	--priority 1001 \
	--source-address-prefixes '*' \
	--source-port-ranges '*' \
	--destination-address-prefixes '*' \
	--destination-port-ranges 51820 \
	--access Allow \
	--protocol Tcp \
	>/dev/null

# Allow SSH (for management)
az network nsg rule create \
	--resource-group $RESOURCE_GROUP \
	--nsg-name $NSG_NAME \
	--name Allow-SSH \
	--priority 1002 \
	--source-address-prefixes '*' \
	--source-port-ranges '*' \
	--destination-address-prefixes '*' \
	--destination-port-ranges 22 \
	--access Allow \
	--protocol Tcp \
	>/dev/null

echo -e "${GREEN}✓ Network security group created${NC}"

# Create Public IP
az network public-ip create \
	--resource-group $RESOURCE_GROUP \
	--name $PUBLIC_IP_NAME \
	--allocation-method Static \
	--sku Standard \
	--dns-name $VM_NAME \
	>/dev/null

echo -e "${GREEN}✓ Public IP created${NC}"

# Create Network Interface
az network nic create \
	--resource-group $RESOURCE_GROUP \
	--name $NIC_NAME \
	--vnet-name $VNET_NAME \
	--subnet $SUBNET_NAME \
	--public-ip-address $PUBLIC_IP_NAME \
	--network-security-group $NSG_NAME \
	>/dev/null

echo -e "${GREEN}✓ Network interface created${NC}"

# ============================================
# Step 5: Create startup script
# ============================================
echo -e "\n${YELLOW}📝 Creating VM startup script...${NC}"

cat >/tmp/orbx-vm-init.sh <<'INIT_SCRIPT_EOF'
#!/bin/bash
set -e

echo "========================================="
echo "OrbX VM Initialization"
echo "========================================="

# Update system
apt-get update
apt-get upgrade -y

# Install Docker
echo "Installing Docker..."
apt-get install -y ca-certificates curl gnupg lsb-release
mkdir -p /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
apt-get update
apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

# Install WireGuard kernel modules
echo "Installing WireGuard..."
apt-get install -y wireguard wireguard-tools linux-headers-$(uname -r)

# Enable IP forwarding
echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.conf
sysctl -p

# Load WireGuard module
modprobe wireguard

echo "[OK] System setup complete"
INIT_SCRIPT_EOF

# Append container startup to the init script
cat >>/tmp/orbx-vm-init.sh <<INIT_SCRIPT_EOF

# Login to Azure Container Registry
echo "Logging into Azure Container Registry..."
echo "${ACR_PASSWORD}" | docker login ${ACR_NAME}.azurecr.io -u ${ACR_USERNAME} --password-stdin

# Pull latest image
echo "Pulling latest OrbX image..."
docker pull ${ACR_NAME}.azurecr.io/orbx-protocol:prod

# Stop and remove any existing container
docker stop orbx-server 2>/dev/null || true
docker rm orbx-server 2>/dev/null || true

# Create certificate directory and save TLS certificates
echo "Setting up TLS certificates..."
mkdir -p /etc/orbx/certs
# ✅ Generate unique TLS certificate for this server
echo "Generating unique TLS certificate for ${FQDN}..."
openssl req -x509 -newkey rsa:4096 -nodes \
  -keyout /etc/orbx/certs/key.pem \
  -out /etc/orbx/certs/cert.pem \
  -days 365 \
  -subj "/C=US/ST=Azure/L=${REGION}/O=OrbVPN/CN=${FQDN}"
chmod 600 /etc/orbx/certs/*.pem
echo "✓ TLS certificate generated"
chmod 600 /etc/orbx/certs/key.pem
chmod 644 /etc/orbx/certs/cert.pem

# Create symlinks for backwards compatibility
ln -sf /etc/orbx/certs/cert.pem /etc/orbx/certs/tls.crt
ln -sf /etc/orbx/certs/key.pem /etc/orbx/certs/tls.key

# Start OrbX container with full privileges
echo "Starting OrbX container..."
docker run -d \\
  --name orbx-server \\
  --restart always \\
  --privileged \\
  --cap-add NET_ADMIN \\
  --cap-add SYS_MODULE \\
  --device /dev/net/tun \\
  -p 8443:8443 \\
  -p 51820:51820 \\
  -v /lib/modules:/lib/modules:ro \\
  -v /etc/orbx/certs:/etc/orbx/certs:ro \\
  -e ORBNET_ENDPOINT="${ORBNET_ENDPOINT}" \\
  -e ORBNET_SERVER_ID="${ORBNET_SERVER_ID}" \\
  -e ORBNET_API_KEY="${ORBNET_API_KEY}" \\
  -e JWT_SECRET="${JWT_SECRET}" \\
  -e WIREGUARD_ENABLED="true" \\
  -e WG_PRIVATE_KEY="${WG_PRIVATE_KEY}" \\
  -e WG_PUBLIC_KEY="${WG_PUBLIC_KEY}" \\
  # -e TLS_CERT="\$(cat /etc/orbx/certs/cert.pem | base64 -w 0)" \\
  # -e TLS_KEY="\$(cat /etc/orbx/certs/key.pem | base64 -w 0)" \\
  ${ACR_NAME}.azurecr.io/orbx-protocol:prod

echo "[OK] OrbX container started"

# Setup auto-update on reboot
cat > /etc/systemd/system/orbx-update.service <<'SERVICE_EOF'
[Unit]
Description=Update and restart OrbX container
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/orbx-update.sh

[Install]
WantedBy=multi-user.target
SERVICE_EOF

# Create update script
cat > /usr/local/bin/orbx-update.sh <<'UPDATE_EOF'
#!/bin/bash
echo "${ACR_PASSWORD}" | docker login ${ACR_NAME}.azurecr.io -u ${ACR_USERNAME} --password-stdin
docker pull ${ACR_NAME}.azurecr.io/orbx-protocol:prod
docker stop orbx-server || true
docker rm orbx-server || true

# Ensure TLS certs exist
mkdir -p /etc/orbx/certs
if [ ! -f /etc/orbx/certs/cert.pem ]; then
# ✅ Generate unique TLS certificate for this server
  echo "Generating unique TLS certificate for ${FQDN}..."
  openssl req -x509 -newkey rsa:4096 -nodes \
    -keyout /etc/orbx/certs/key.pem \
    -out /etc/orbx/certs/cert.pem \
    -days 365 \
    -subj "/C=US/ST=Azure/L=${REGION}/O=OrbVPN/CN=${FQDN}"
  chmod 600 /etc/orbx/certs/*.pem
  echo "✓ TLS certificate generated"
  chmod 600 /etc/orbx/certs/key.pem
  chmod 644 /etc/orbx/certs/cert.pem
  ln -sf /etc/orbx/certs/cert.pem /etc/orbx/certs/tls.crt
  ln -sf /etc/orbx/certs/key.pem /etc/orbx/certs/tls.key
fi

docker run -d \\
  --name orbx-server \\
  --restart always \\
  --privileged \\
  --cap-add NET_ADMIN \\
  --cap-add SYS_MODULE \\
  --device /dev/net/tun \\
  -p 8443:8443 \\
  -p 51820:51820 \\
  -v /lib/modules:/lib/modules:ro \\
  -v /etc/orbx/certs:/etc/orbx/certs:ro \\
  -e ORBNET_ENDPOINT="${ORBNET_ENDPOINT}" \\
  -e ORBNET_SERVER_ID="${ORBNET_SERVER_ID}" \\
  -e ORBNET_API_KEY="${ORBNET_API_KEY}" \\
  -e JWT_SECRET="${JWT_SECRET}" \\
  -e WIREGUARD_ENABLED="true" \\
  -e WG_PRIVATE_KEY="${WG_PRIVATE_KEY}" \\
  -e WG_PUBLIC_KEY="${WG_PUBLIC_KEY}" \\
  # -e TLS_CERT="\$(cat /etc/orbx/certs/cert.pem | base64 -w 0)" \\
  # -e TLS_KEY="\$(cat /etc/orbx/certs/key.pem | base64 -w 0)" \\
  ${ACR_NAME}.azurecr.io/orbx-protocol:prod
UPDATE_EOF

chmod +x /usr/local/bin/orbx-update.sh
systemctl enable orbx-update.service

echo "========================================="
echo "[OK] OrbX VM initialization complete!"
echo "========================================="
INIT_SCRIPT_EOF

echo -e "${GREEN}✓ Startup script created${NC}"

# ============================================
# Step 6: Create VM
# ============================================
echo -e "\n${YELLOW}🖥️  Creating virtual machine...${NC}"
echo -e "${YELLOW}This may take 3-5 minutes...${NC}"

az vm create \
	--resource-group $RESOURCE_GROUP \
	--name $VM_NAME \
	--location $REGION \
	--nics $NIC_NAME \
	--image Ubuntu2204 \
	--size $VM_SIZE \
	--admin-username azureuser \
	--generate-ssh-keys \
	--custom-data /tmp/orbx-vm-init.sh \
	--tags Environment=Production Application=OrbX Region=$REGION \
	>/dev/null

echo -e "${GREEN}✓ Virtual machine created${NC}"

# Cleanup temp file
rm -f /tmp/orbx-vm-init.sh

# Get VM public IP/FQDN
FQDN=$(az network public-ip show \
	--resource-group $RESOURCE_GROUP \
	--name $PUBLIC_IP_NAME \
	--query dnsSettings.fqdn \
	--output tsv)

PUBLIC_IP=$(az network public-ip show \
	--resource-group $RESOURCE_GROUP \
	--name $PUBLIC_IP_NAME \
	--query ipAddress \
	--output tsv)

echo -e "${GREEN}✓ VM FQDN: ${FQDN}${NC}"
echo -e "${GREEN}✓ VM IP: ${PUBLIC_IP}${NC}"

# ============================================
# Step 7: Wait for initialization
# ============================================
echo -e "\n${YELLOW}⏳ Waiting for VM initialization (this takes 4-5 minutes)...${NC}"
echo -e "${YELLOW}The VM is installing Docker, WireGuard, and starting the container...${NC}"

# Wait for VM to complete initialization
sleep 300 # 5 minutes

# ============================================
# Step 8: Health check
# ============================================
echo -e "\n${YELLOW}🔍 Running health check...${NC}"

MAX_HEALTH_ATTEMPTS=15
for i in $(seq 1 $MAX_HEALTH_ATTEMPTS); do
	echo -e "${YELLOW}  Attempt $i/$MAX_HEALTH_ATTEMPTS...${NC}"
	HEALTH_RESPONSE=$(curl -k -s -m 10 "https://$FQDN:8443/health" 2>/dev/null || echo "failed")

	if echo "$HEALTH_RESPONSE" | grep -q "healthy"; then
		echo -e "${GREEN}✅ Health check PASSED${NC}"

		# Update server status in OrbNet to ONLINE
		curl -s -X POST "$ORBNET_ENDPOINT" \
			-H "Content-Type: application/json" \
			-H "Authorization: Bearer $ORBNET_AUTH_TOKEN" \
			-d '{
        "query": "mutation UpdateOrbXServerStatus($serverId: ID!, $online: Boolean!) { updateOrbXServerStatus(serverId: $serverId, online: $online) { id online } }",
        "variables": {
          "serverId": "'"$ORBNET_SERVER_ID"'",
          "online": true
        }
      }' >/dev/null

		echo -e "${GREEN}✅ Server status updated to ONLINE in OrbNet${NC}"
		break
	else
		if [ $i -eq $MAX_HEALTH_ATTEMPTS ]; then
			echo -e "${RED}❌ Health check FAILED after $MAX_HEALTH_ATTEMPTS attempts${NC}"
			echo -e "${RED}Response: $HEALTH_RESPONSE${NC}"

			echo -e "\n${YELLOW}To debug, SSH into the VM:${NC}"
			echo -e "${YELLOW}  ssh azureuser@${FQDN}${NC}"
			echo -e "${YELLOW}  sudo docker logs orbx-server${NC}"

			# Update server status to ERROR
			curl -s -X POST "$ORBNET_ENDPOINT" \
				-H "Content-Type: application/json" \
				-H "Authorization: Bearer $ORBNET_AUTH_TOKEN" \
				-d '{
          "query": "mutation UpdateOrbXServerStatus($serverId: ID!, $online: Boolean!) { updateOrbXServerStatus(serverId: $serverId, online: $online) { id online } }",
          "variables": {
            "serverId": "'"$ORBNET_SERVER_ID"'",
            "online": false
          }
        }' >/dev/null
		else
			echo -e "${YELLOW}  Waiting 20s before retry...${NC}"
			sleep 20
		fi
	fi
done

# ============================================
# Summary
# ============================================
echo -e "\n${GREEN}============================================${NC}"
echo -e "${GREEN}🎉 Deployment Complete!${NC}"
echo -e "${GREEN}============================================${NC}"
echo -e "Server Name: ${YELLOW}${SERVER_NAME}${NC}"
echo -e "Region: ${YELLOW}${REGION}${NC}"
echo -e "Server ID: ${YELLOW}${ORBNET_SERVER_ID}${NC}"
echo -e "Server URL: ${YELLOW}https://$FQDN:8443${NC}"
echo -e "WireGuard: ${YELLOW}$FQDN:51820${NC}"
echo -e "Public Key: ${YELLOW}$WG_PUBLIC_KEY${NC}"
echo -e "VM IP: ${YELLOW}$PUBLIC_IP${NC}"
echo -e "\n${YELLOW}Management:${NC}"
echo -e "  SSH: ${YELLOW}ssh azureuser@${FQDN}${NC}"
echo -e "  Logs: ${YELLOW}ssh azureuser@${FQDN} 'sudo docker logs orbx-server'${NC}"
echo -e "  Restart: ${YELLOW}ssh azureuser@${FQDN} 'sudo docker restart orbx-server'${NC}"
echo -e "  Update: ${YELLOW}ssh azureuser@${FQDN} 'sudo /usr/local/bin/orbx-update.sh'${NC}"
echo -e "\n${YELLOW}Test endpoints:${NC}"
echo -e "  ${YELLOW}curl -k https://$FQDN:8443/health${NC}"
echo -e "  ${YELLOW}curl -k https://$FQDN:8443/metrics${NC}"

# Save deployment info
echo "$FQDN|$ORBNET_SERVER_ID|$REGION|$WG_PUBLIC_KEY|$SERVER_NAME|VM|$PUBLIC_IP" >>deployed-servers.txt
echo -e "\n${GREEN}✓ Deployment info saved to deployed-servers.txt${NC}"
