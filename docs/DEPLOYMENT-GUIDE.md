# 🚀 OrbX Multi-Region Deployment Guide

Complete guide for deploying OrbX Protocol servers to 30 Azure regions with one-click automation.

## 📋 Table of Contents

- [Project Overview](#project-overview)
- [What's Complete](#whats-complete)
- [Prerequisites](#prerequisites)
- [Initial Setup](#initial-setup)
- [Multi-Region Deployment](#multi-region-deployment)
- [Testing & Validation](#testing--validation)
- [Management & Operations](#management--operations)
- [Cost Estimation](#cost-estimation)
- [Troubleshooting](#troubleshooting)
- [Flutter Client Development](#flutter-client-development)

---

## 🎯 Project Overview

**OrbX** is a post-quantum VPN obfuscation server designed to bypass internet restrictions in Iran and other censored regions. The system uses:

- **Protocol Mimicry**: Disguises VPN traffic as Teams, Banking (Shaparak), DNS, or HTTPS
- **Post-Quantum Crypto**: Kyber768 key exchange for future-proof security
- **Multi-Region**: Deploy to 30 global Azure regions for resilient access
- **Flutter Client**: Cross-platform app (iOS, Android, macOS, tvOS, Windows, Linux)

---

## ✅ What's Complete

### Backend Infrastructure

- ✅ **OrbX Protocol Server** (Go)

  - Post-quantum cryptography (Kyber768)
  - Protocol mimicry handlers (Teams, Shaparak, DoH, HTTPS)
  - Lattice-based traffic obfuscation
  - Timing channel protection
  - JWT authentication
  - OrbNet API integration

- ✅ **OrbNet API** (Java/Spring Boot)

  - GraphQL API for server management
  - User authentication & authorization
  - Usage tracking & metrics
  - Server registration system
  - Notification system (FCM for Flutter)

- ✅ **Deployment Infrastructure**
  - Docker containerization
  - Azure Container Registry setup
  - Azure Key Vault for secrets
  - Single-region deployment scripts
  - **Multi-region deployment automation** ⭐ NEW

### What's NOT Started Yet

- ❌ **Flutter Client** (You'll develop this after deployment)

---

## 📦 Prerequisites

### Required Tools

```bash
# Azure CLI
brew install azure-cli

# Docker
brew install docker

# Git (for version control)
brew install git

# jq (for JSON parsing in scripts)
brew install jq
```

### Azure Account

- Active Azure subscription
- Owner or Contributor role
- Budget: ~$2,700/month for 30 regions

### OrbNet API Credentials

You need these from your OrbNet API:

- `JWT_SECRET`
- `ORBNET_API_KEY`
- `ORBNET_ENDPOINT` (e.g., `https://api.orbvpn.com/graphql`)

---

## 🔧 Initial Setup

### 1. Login to Azure

```bash
az login

# Select subscription if you have multiple
az account list --output table
az account set --subscription "YOUR_SUBSCRIPTION_ID"
```

### 2. Setup Shared Resources (One-Time)

This creates the Container Registry and Key Vault that all regions will share.

```bash
cd deployments/azure/scripts

# Make scripts executable
chmod +x setup-azure.sh
chmod +x build-and-push.sh
chmod +x deploy-all-regions.sh
chmod +x test-all-regions.sh
chmod +x manage-all-regions.sh

# Run initial setup
./setup-azure.sh
```

**This will prompt you for:**

- JWT Secret
- OrbNet API Key
- OrbNet Endpoint

All secrets are stored securely in Azure Key Vault.

### 3. Build and Push Docker Image

```bash
./build-and-push.sh
```

This builds your OrbX server Docker image and pushes it to Azure Container Registry. All 30 regions will use this same image.

---

## 🌍 Multi-Region Deployment

### Deploy to All 30 Regions (One Click!)

```bash
./deploy-all-regions.sh
```

**This will:**

1. Show you the 30 regions it will deploy to
2. Ask for confirmation
3. Deploy containers to all regions in parallel
4. Generate a `deployed-servers.txt` file with all server URLs

**Regions Deployed:**

| Region             | Location             | Country |
| ------------------ | -------------------- | ------- |
| eastus             | East US              | US 🇺🇸   |
| westus             | West US              | US 🇺🇸   |
| centralus          | Central US           | US 🇺🇸   |
| canadacentral      | Canada Central       | CA 🇨🇦   |
| northeurope        | North Europe         | IE 🇮🇪   |
| westeurope         | West Europe          | NL 🇳🇱   |
| uksouth            | UK South             | GB 🇬🇧   |
| francecentral      | France Central       | FR 🇫🇷   |
| germanywestcentral | Germany West Central | DE 🇩🇪   |
| swedencentral      | Sweden Central       | SE 🇸🇪   |
| switzerlandnorth   | Switzerland North    | CH 🇨🇭   |
| italynorth         | Italy North          | IT 🇮🇹   |
| southeastasia      | Southeast Asia       | SG 🇸🇬   |
| eastasia           | East Asia            | HK 🇭🇰   |
| japaneast          | Japan East           | JP 🇯🇵   |
| koreacentral       | Korea Central        | KR 🇰🇷   |
| australiaeast      | Australia East       | AU 🇦🇺   |
| centralindia       | Central India        | IN 🇮🇳   |
| uaenorth           | UAE North            | AE 🇦🇪   |
| southafricanorth   | South Africa North   | ZA 🇿🇦   |
| qatarcentral       | Qatar Central        | QA 🇶🇦   |
| israelcentral      | Israel Central       | IL 🇮🇱   |
| brazilsouth        | Brazil South         | BR 🇧🇷   |
| norwayeast         | Norway East          | NO 🇳🇴   |
| polandcentral      | Poland Central       | PL 🇵🇱   |
| spaincentral       | Spain Central        | ES 🇪🇸   |
| mexicocentral      | Mexico Central       | MX 🇲🇽   |
| southindia         | South India          | IN 🇮🇳   |
| westus3            | West US 3            | US 🇺🇸   |
| australiasoutheast | Australia Southeast  | AU 🇦🇺   |

**Deployment Time:** ~15-20 minutes

---

## ✅ Testing & Validation

### Test All Server Health Endpoints

```bash
./test-all-regions.sh
```

This tests the `/health` endpoint on all 30 servers and shows which are healthy.

**Expected output:**

```
✅ HEALTHY: 30/30
```

### Manual Testing

Test individual server:

```bash
# Replace with actual FQDN from deployed-servers.txt
curl -k https://orbx-eastus.eastus.azurecontainer.io:8443/health

# Expected response:
# {"status":"healthy","version":"1.0.0"}
```

Test with JWT token:

```bash
# Get JWT token from your OrbNet API first
curl -k -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  https://orbx-eastus.eastus.azurecontainer.io:8443/tunnel
```

---

## 🛠️ Management & Operations

### View Status of All Deployments

```bash
./manage-all-regions.sh status
```

### Stop All Servers

```bash
./manage-all-regions.sh stop
```

### Start All Servers

```bash
./manage-all-regions.sh start
```

### Restart All Servers

```bash
./manage-all-regions.sh restart
```

### View Logs from All Regions

```bash
./manage-all-regions.sh logs
```

### Delete All Deployments

```bash
./manage-all-regions.sh delete
# Type "DELETE" to confirm
```

### Update Servers (After Code Changes)

```bash
# 1. Build new image
./build-and-push.sh

# 2. Restart all containers to pull new image
./manage-all-regions.sh restart
```

---

## 💰 Cost Estimation

### Monthly Costs (30 Regions)

| Resource                        | Unit Cost | Quantity | Total          |
| ------------------------------- | --------- | -------- | -------------- |
| Container Instance (2 CPU, 4GB) | $70/mo    | 30       | $2,100         |
| Container Registry (Standard)   | $20/mo    | 1        | $20            |
| Key Vault                       | $0.03/mo  | 1        | $0.03          |
| Bandwidth (Estimate)            | Variable  | -        | $500           |
| **TOTAL**                       |           |          | **~$2,620/mo** |

### Cost Optimization Tips

1. **Start with fewer regions** (e.g., 10 regions = ~$900/mo)
2. **Use smaller instances** (1 CPU, 2GB = ~$35/region)
3. **Delete unused regions** during low-traffic periods
4. **Use Azure reserved instances** for 30% discount

---

## 🐛 Troubleshooting

### Container Won't Start

```bash
# Check logs
az container logs --resource-group orbx-eastus-rg --name orbx-eastus

# Common issues:
# 1. Missing secrets → Check Key Vault
# 2. Image pull failed → Check ACR credentials
# 3. Port conflict → Check firewall rules
```

### Health Check Failing

```bash
# Test locally first
docker run -p 8443:8443 \
  -e JWT_SECRET="your-secret" \
  -e ORBNET_API_KEY="your-key" \
  -e ORBNET_ENDPOINT="https://api.orbvpn.com/graphql" \
  orbxregistry.azurecr.io/orbx-protocol:latest

# Then test:
curl -k https://localhost:8443/health
```

### Region Deployment Failed

```bash
# Deploy single region manually
az container create \
  --resource-group orbx-eastus-rg \
  --name orbx-eastus \
  --image orbxregistry.azurecr.io/orbx-protocol:latest \
  # ... (see deploy-all-regions.sh for full params)
```

### Can't Connect from Iran

Make sure:

1. Servers are using proper protocol mimicry
2. DNS is not blocked (use IP addresses if needed)
3. Try different protocols (Teams, Shaparak, DoH)

---

## 📱 Flutter Client Development

After servers are deployed, you can start building the Flutter client:

### Client Requirements

The Flutter app should:

1. **Authenticate** with OrbNet API
2. **Get server list** from OrbNet GraphQL API
3. **Receive JWT token** for connecting to OrbX servers
4. **Connect to best server** based on:
   - Latency
   - Current connections
   - User's location
5. **Switch protocols** dynamically if one gets blocked

### API Integration

```dart
// Example GraphQL query for server list
query GetOrbXServers {
  orbxServers(enabled: true, online: true) {
    id
    name
    ipAddress
    port
    location
    country
    protocols
    currentConnections
    latencyMs
  }
}

// Example authentication
mutation Login($email: String!, $password: String!) {
  login(email: $email, password: $password) {
    accessToken
    user {
      id
      email
    }
  }
}
```

### Server Connection

The OrbX servers expect:

- **Authorization header**: `Bearer <JWT_TOKEN>`
- **Protocol selection**: Via endpoint path
  - `/tunnel` - Generic HTTPS
  - `/teams/messages` - Teams mimicry
  - `/shaparak/transaction` - Banking mimicry
  - `/dns-query` - DoH mimicry

### Platform Support

Your Flutter app will work on:

- ✅ iOS
- ✅ Android
- ✅ macOS
- ✅ tvOS
- ✅ Android TV
- ✅ Windows (via platform channel)
- ✅ Linux (via platform channel)

---

## 🎉 Summary

You now have:

1. ✅ **30 OrbX servers** deployed globally
2. ✅ **One-click deployment** automation
3. ✅ **Easy management** scripts
4. ✅ **Testing tools** for validation
5. ✅ **Ready for Flutter client** development

### Quick Command Reference

```bash
# Deploy everything
./deploy-all-regions.sh

# Test all servers
./test-all-regions.sh

# View status
./manage-all-regions.sh status

# View logs
./manage-all-regions.sh logs

# Update after code changes
./build-and-push.sh
./manage-all-regions.sh restart
```

---

## 📞 Support

If you encounter issues:

1. Check the logs: `./manage-all-regions.sh logs`
2. Review troubleshooting section above
3. Check Azure Portal for detailed error messages
4. Test locally with Docker first

---

**Happy Deploying! 🚀**
