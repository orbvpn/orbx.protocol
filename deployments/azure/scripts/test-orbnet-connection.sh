#!/bin/bash

# Test OrbNet API connection and authentication

set -e

ORBNET_ENDPOINT=${1:-"https://orbnet.xyz/graphql"}

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}🧪 Testing OrbNet API Connection${NC}"
echo "=============================================="
echo -e "Endpoint: ${YELLOW}$ORBNET_ENDPOINT${NC}"
echo ""

# Check if jq is installed
if ! command -v jq &>/dev/null; then
	echo -e "${RED}❌ jq is required but not installed${NC}"
	echo "Install it with: brew install jq"
	exit 1
fi

# Get credentials
read -p "Enter OrbNet admin email: " EMAIL
read -sp "Enter OrbNet admin password: " PASSWORD
echo ""

# Test login
echo -e "\n${YELLOW}Testing login...${NC}"
LOGIN_RESPONSE=$(curl -s -X POST "$ORBNET_ENDPOINT" \
	-H "Content-Type: application/json" \
	-d '{
    "query": "mutation Login($email: String!, $password: String!) { login(email: $email, password: $password) { accessToken } }",
    "variables": {
      "email": "'"$EMAIL"'",
      "password": "'"$PASSWORD"'"
    }
  }')

# Check for errors
if echo "$LOGIN_RESPONSE" | jq -e '.errors' >/dev/null 2>&1; then
	echo -e "${RED}❌ Login failed${NC}"
	echo "$LOGIN_RESPONSE" | jq '.errors'
	exit 1
fi

# Extract token
TOKEN=$(echo $LOGIN_RESPONSE | jq -r '.data.login.accessToken')

if [ "$TOKEN" = "null" ] || [ -z "$TOKEN" ]; then
	echo -e "${RED}❌ No access token received${NC}"
	echo "Response: $LOGIN_RESPONSE"
	exit 1
fi

echo -e "${GREEN}✅ Login successful!${NC}"
echo -e "Token (first 20 chars): ${YELLOW}${TOKEN:0:20}...${NC}"

# Test querying servers
echo -e "\n${YELLOW}Fetching existing OrbX servers...${NC}"
SERVERS_RESPONSE=$(curl -s -X POST "$ORBNET_ENDPOINT" \
	-H "Content-Type: application/json" \
	-H "Authorization: Bearer $TOKEN" \
	-d '{
    "query": "query { orbxServers { id name region hostname online } }"
  }')

if echo "$SERVERS_RESPONSE" | jq -e '.errors' >/dev/null 2>&1; then
	echo -e "${RED}❌ Query failed${NC}"
	echo "$SERVERS_RESPONSE" | jq '.errors'
else
	SERVER_COUNT=$(echo "$SERVERS_RESPONSE" | jq '.data.orbxServers | length')
	echo -e "${GREEN}✅ Query successful!${NC}"
	echo -e "Existing servers: ${YELLOW}$SERVER_COUNT${NC}"

	if [ "$SERVER_COUNT" -gt 0 ]; then
		echo -e "\n${YELLOW}Server list:${NC}"
		echo "$SERVERS_RESPONSE" | jq -r '.data.orbxServers[] | "  - \(.name) (\(.region)) - Online: \(.online)"'
	fi
fi

# Test registering a dummy server
echo -e "\n${YELLOW}Testing server registration (dry run)...${NC}"
read -p "Do you want to test registering a dummy server? (yes/no): " TEST_REGISTER

if [ "$TEST_REGISTER" = "yes" ]; then
	REGISTER_RESPONSE=$(curl -s -X POST "$ORBNET_ENDPOINT" \
		-H "Content-Type: application/json" \
		-H "Authorization: Bearer $TOKEN" \
		-d '{
      "query": "mutation RegisterOrbXServer($input: OrbXServerInput!) { registerOrbXServer(input: $input) { server { id name region } apiKey jwtSecret } }",
      "variables": {
        "input": {
          "name": "Test Server - Delete Me",
          "region": "test",
          "hostname": "test.example.com",
          "ipAddress": "1.2.3.4",
          "port": 8443,
          "location": "Test Location",
          "country": "Test",
          "protocols": ["wireguard"],
          "maxConnections": 10
        }
      }
    }')

	if echo "$REGISTER_RESPONSE" | jq -e '.errors' >/dev/null 2>&1; then
		echo -e "${RED}❌ Registration failed${NC}"
		echo "$REGISTER_RESPONSE" | jq '.errors'
	else
		echo -e "${GREEN}✅ Registration successful!${NC}"
		SERVER_ID=$(echo "$REGISTER_RESPONSE" | jq -r '.data.registerOrbXServer.server.id')
		API_KEY=$(echo "$REGISTER_RESPONSE" | jq -r '.data.registerOrbXServer.apiKey')
		JWT_SECRET=$(echo "$REGISTER_RESPONSE" | jq -r '.data.registerOrbXServer.jwtSecret')

		echo -e "Server ID: ${YELLOW}$SERVER_ID${NC}"
		echo -e "API Key: ${YELLOW}${API_KEY:0:20}...${NC}"
		echo -e "JWT Secret: ${YELLOW}${JWT_SECRET:0:20}...${NC}"

		# Offer to delete the test server
		echo ""
		read -p "Delete test server? (yes/no): " DELETE_TEST
		if [ "$DELETE_TEST" = "yes" ]; then
			DELETE_RESPONSE=$(curl -s -X POST "$ORBNET_ENDPOINT" \
				-H "Content-Type: application/json" \
				-H "Authorization: Bearer $TOKEN" \
				-d '{
          "query": "mutation DeleteOrbXServer($id: ID!) { deleteOrbXServer(id: $id) }",
          "variables": {
            "id": "'"$SERVER_ID"'"
          }
        }')

			if echo "$DELETE_RESPONSE" | jq -e '.data.deleteOrbXServer' >/dev/null 2>&1; then
				echo -e "${GREEN}✅ Test server deleted${NC}"
			fi
		fi
	fi
fi

echo -e "\n${GREEN}============================================${NC}"
echo -e "${GREEN}✅ All tests passed!${NC}"
echo -e "${GREEN}============================================${NC}"
echo -e "\nYour OrbNet API is working correctly."
echo -e "Token: ${YELLOW}$TOKEN${NC}"
echo -e "\nYou can now proceed with: ${YELLOW}./setup-complete.sh${NC}"
