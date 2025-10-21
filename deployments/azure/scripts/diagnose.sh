#!/bin/bash

echo "=== Checking Key Vault Secrets ==="
echo "ORBNET_ENDPOINT:"
az keyvault secret show --vault-name orbx-vault --name "ORBNET-ENDPOINT" --query value -o tsv

echo ""
echo "ORBNET_AUTH_TOKEN (first 20 chars):"
az keyvault secret show --vault-name orbx-vault --name "ORBNET-AUTH-TOKEN" --query value -o tsv | cut -c1-20

echo ""
echo "TLS_CERT (first 50 chars):"
az keyvault secret show --vault-name orbx-vault --name "TLS-CERT" --query value -o tsv | cut -c1-50

echo ""
echo "TLS_KEY (first 50 chars):"
az keyvault secret show --vault-name orbx-vault --name "TLS-KEY" --query value -o tsv | cut -c1-50

echo ""
echo "=== Testing API Registration ==="
ORBNET_ENDPOINT=$(az keyvault secret show --vault-name orbx-vault --name "ORBNET-ENDPOINT" --query value -o tsv)
ORBNET_AUTH_TOKEN=$(az keyvault secret show --vault-name orbx-vault --name "ORBNET-AUTH-TOKEN" --query value -o tsv)

TEST_RESPONSE=$(curl -s -X POST "$ORBNET_ENDPOINT" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ORBNET_AUTH_TOKEN" \
  -d '{
    "query": "mutation RegisterOrbXServer($input: OrbXServerInput!) { registerOrbXServer(input: $input) { server { id name } apiKey jwtSecret } }",
    "variables": {
      "input": {
        "name": "TEST-SERVER",
        "region": "test-'$(date +%s)'",
        "hostname": "test.example.com",
        "ipAddress": "1.2.3.4",
        "port": 8443,
        "location": "Test",
        "country": "US",
        "protocols": ["wireguard"],
        "maxConnections": 100,
        "publicKey": "test-key"
      }
    }
  }')

echo "API Response:"
echo $TEST_RESPONSE | jq '.'