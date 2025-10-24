cd deployments/azure/scripts

# Create fix-nsg-rules.sh
cat >fix-nsg-rules.sh <<'EOF'
#!/bin/bash

# Read all regions from deployed-servers.txt
if [ ! -f ../deployed-servers.txt ]; then
    echo "Error: deployed-servers.txt not found"
    exit 1
fi

# Get unique regions
REGIONS=$(awk -F'|' '{print $3}' ../deployed-servers.txt | sort -u)

echo "Fixing NSG rules for WireGuard (TCP → UDP)..."
echo ""

for REGION in $REGIONS; do
    echo "→ Fixing region: $REGION"
    
    # Delete old TCP rule
    az network nsg rule delete \
        --resource-group orbx-${REGION}-rg \
        --nsg-name orbx-${REGION}-nsg \
        --name Allow-WireGuard \
        2>/dev/null
    
    # Create new UDP rule
    az network nsg rule create \
        --resource-group orbx-${REGION}-rg \
        --nsg-name orbx-${REGION}-nsg \
        --name Allow-WireGuard \
        --priority 1001 \
        --source-address-prefixes '*' \
        --destination-port-ranges 51820 \
        --protocol Udp \
        --access Allow \
        --direction Inbound \
        --output none
    
    if [ $? -eq 0 ]; then
        echo "  ✓ Fixed NSG rule for $REGION"
    else
        echo "  ✗ Failed to fix NSG rule for $REGION"
    fi
done

echo ""
echo "✅ NSG rules fixed for all regions!"
EOF

chmod +x fix-nsg-rules.sh
