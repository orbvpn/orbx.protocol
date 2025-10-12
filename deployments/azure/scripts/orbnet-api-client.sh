#!/bin/bash

# OrbNet API Client - Handles all GraphQL API calls

set -e

ORBNET_ENDPOINT="${ORBNET_ENDPOINT:-https://api.orbvpn.com/graphql}"

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

orbnet_login() {
    local email=$1
    local password=$2
    echo -e "${YELLOW}🔐 Logging into OrbNet API...${NC}"
    
    local query='mutation Login($email: String!, $password: String!) {
        login(email: $email, password: $password) {
            accessToken
            user { id email role }
        }
    }'
    
    local variables="{\"email\":\"$email\",\"password\":\"$password\"}"
    local response=$(curl -s -X POST "$ORBNET_ENDPOINT" \
        -H "Content-Type: application/json" \
        -d "$(jq -n --arg q "$query" --argjson v "$variables" '{query:$q,variables:$v}')")
    
    if echo "$response" | jq -e '.errors' >/dev/null 2>&1; then
        echo -e "${RED}❌ Login failed${NC}"
        return 1
    fi
    
    local token=$(echo "$response" | jq -r '.data.login.accessToken')
    echo -e "${GREEN}✅ Logged in successfully${NC}"
    echo "$token"
}

orbnet_register_server() {
    local admin_token=$1
    local server_name=$2
    local ip=$3
    local port=$4
    local location=$5
    local country=$6
    local region=$7
    
    echo -e "${YELLOW}📝 Registering: $server_name${NC}"
    
    local query='mutation RegisterOrbXServer($input: OrbXServerInput!) {
        registerOrbXServer(input: $input) {
            server { id name }
            apiKey
            jwtSecret
        }
    }'
    
    # Generate default hostname from region
    local default_hostname="orbx-${region}.orbvpn.com"
    
    local input="{
        \"name\":\"$server_name\",
        \"region\":\"$region\",
        \"hostname\":\"$default_hostname\",
        \"ipAddress\":\"$ip\",
        \"port\":$port,
        \"location\":\"$location\",
        \"country\":\"$country\",
        \"protocols\":[\"wireguard\",\"teams\",\"shaparak\",\"doh\",\"https\",\"google-meet\"],
        \"maxConnections\":1000
    }"
    
    local response=$(curl -s -X POST "$ORBNET_ENDPOINT" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $admin_token" \
        -d "$(jq -n --arg q "$query" --argjson i "$input" '{query:$q,variables:{input:$i}}')")
    
    if echo "$response" | jq -e '.errors' >/dev/null 2>&1; then
        echo -e "${RED}❌ Registration failed${NC}"
        echo "$response" | jq '.errors' >&2
        return 1
    fi
    
    local server_id=$(echo "$response" | jq -r '.data.registerOrbXServer.server.id')
    local api_key=$(echo "$response" | jq -r '.data.registerOrbXServer.apiKey')
    local jwt_secret=$(echo "$response" | jq -r '.data.registerOrbXServer.jwtSecret')
    
    echo -e "${GREEN}✅ Registered (ID: $server_id)${NC}"
    jq -n --arg sid "$server_id" --arg key "$api_key" --arg jwt "$jwt_secret" \
        '{server_id:$sid,api_key:$key,jwt_secret:$jwt}'
}

orbnet_update_server() {
    local admin_token=$1
    local server_id=$2
    local fqdn=$3
    
    echo -e "${YELLOW}🔄 Updating server with FQDN...${NC}"
    
    local query='mutation UpdateOrbXServer($id: ID!, $input: OrbXServerInput!) {
        updateOrbXServer(id: $id, input: $input) { 
            id 
            name 
            hostname
        }
    }'
    
    local input="{\"ipAddress\":\"$fqdn\"}"
    
    local response=$(curl -s -X POST "$ORBNET_ENDPOINT" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $admin_token" \
        -d "$(jq -n --arg q "$query" --arg id "$server_id" --argjson i "$input" '{query:$q,variables:{id:$id,input:$i}}')")
    
    if echo "$response" | jq -e '.errors' >/dev/null 2>&1; then
        echo -e "${RED}❌ Update failed${NC}"
        return 1
    fi
    
    echo -e "${GREEN}✅ Updated with FQDN${NC}"
}

# NEW FUNCTION - Update both hostname and IP
orbnet_update_server_full() {
    local admin_token=$1
    local server_id=$2
    local hostname=$3
    local ip_address=$4
    
    echo -e "${YELLOW}🔄 Updating server hostname and IP...${NC}"
    
    local query='mutation UpdateOrbXServer($id: ID!, $input: OrbXServerInput!) {
        updateOrbXServer(id: $id, input: $input) {
            id
            name
            hostname
            ipAddress
        }
    }'
    
    local input="{\"hostname\":\"$hostname\",\"ipAddress\":\"$ip_address\"}"
    
    local response=$(curl -s -X POST "$ORBNET_ENDPOINT" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $admin_token" \
        -d "$(jq -n --arg q "$query" --arg id "$server_id" --argjson i "$input" '{query:$q,variables:{id:$id,input:$i}}')")
    
    if echo "$response" | jq -e '.errors' >/dev/null 2>&1; then
        echo -e "${RED}❌ Update failed${NC}"
        echo "$response" | jq '.errors' >&2
        return 1
    fi
    
    echo -e "${GREEN}✅ Updated: Hostname=$hostname, IP=$ip_address${NC}"
}

orbnet_check_server_exists() {
    local admin_token=$1
    local server_name=$2
    
    local query='query { orbxServers { id name } }'
    local response=$(curl -s -X POST "$ORBNET_ENDPOINT" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $admin_token" \
        -d "$(jq -n --arg q "$query" '{query:$q}')")
    
    if echo "$response" | jq -e '.errors' >/dev/null 2>&1; then
        return 1
    fi
    
    local server_id=$(echo "$response" | jq -r ".data.orbxServers[]|select(.name==\"$server_name\")|.id")
    
    if [ -n "$server_id" ] && [ "$server_id" != "null" ]; then
        echo "$server_id"
        return 0
    fi
    return 1
}

orbnet_regenerate_credentials() {
    local admin_token=$1
    local server_id=$2
    
    echo -e "${YELLOW}🔄 Regenerating credentials for server $server_id...${NC}"
    
    local query='mutation RegenerateOrbXServerCredentials($id: ID!) {
        regenerateOrbXServerCredentials(id: $id) {
            server { id name }
            apiKey
            jwtSecret
        }
    }'
    
    local response=$(curl -s -X POST "$ORBNET_ENDPOINT" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $admin_token" \
        -d "$(jq -n --arg q "$query" --arg id "$server_id" '{query:$q,variables:{id:$id}}')")
    
    if echo "$response" | jq -e '.errors' >/dev/null 2>&1; then
        echo -e "${RED}❌ Regeneration failed${NC}"
        echo "$response" | jq '.errors' >&2
        return 1
    fi
    
    local api_key=$(echo "$response" | jq -r '.data.regenerateOrbXServerCredentials.apiKey')
    local jwt_secret=$(echo "$response" | jq -r '.data.regenerateOrbXServerCredentials.jwtSecret')
    
    echo -e "${GREEN}✅ Credentials regenerated${NC}"
    jq -n --arg sid "$server_id" --arg key "$api_key" --arg jwt "$jwt_secret" \
        '{server_id:$sid,api_key:$key,jwt_secret:$jwt}'
}

# NEW FUNCTION - Get server by region
orbnet_get_server_by_region() {
    local admin_token=$1
    local region=$2
    
    local query='query { orbxServers { id name region } }'
    local response=$(curl -s -X POST "$ORBNET_ENDPOINT" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $admin_token" \
        -d "$(jq -n --arg q "$query" '{query:$q}')")
    
    if echo "$response" | jq -e '.errors' >/dev/null 2>&1; then
        return 1
    fi
    
    local server_id=$(echo "$response" | jq -r ".data.orbxServers[]|select(.region==\"$region\")|.id")
    
    if [ -n "$server_id" ] && [ "$server_id" != "null" ]; then
        echo "$server_id"
        return 0
    fi
    return 1
}

# NEW FUNCTION - Update server status
orbnet_update_server_status() {
    local admin_token=$1
    local server_id=$2
    local online=$3  # true or false
    
    local query='mutation UpdateOrbXServerStatus($id: ID!, $online: Boolean!) {
        updateOrbXServerStatus(serverId: $id, online: $online) {
            id
            online
        }
    }'
    
    local response=$(curl -s -X POST "$ORBNET_ENDPOINT" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $admin_token" \
        -d "$(jq -n --arg q "$query" --arg id "$server_id" --argjson online "$online" '{query:$q,variables:{id:$id,online:$online}}')")
    
    if echo "$response" | jq -e '.errors' >/dev/null 2>&1; then
        return 1
    fi
    
    return 0
}