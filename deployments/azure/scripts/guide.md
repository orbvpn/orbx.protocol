## ☁️ AZURE DEPLOYMENT GUIDE

### **Prerequisites**

```bash
# Install Azure CLI
brew install azure-cli

# Login to Azure
az login

# Set subscription (if you have multiple)
az account list --output table
az account set --subscription "YOUR_SUBSCRIPTION_ID"

# Install Docker (if not already installed)
brew install docker
```

---

## 🚀 STEP 1: Azure Resource Setup

### Create deployment script: `deployments/azure/scripts/setup-azure.sh`

Make it executable:

```bash
chmod +x deployments/azure/scripts/setup-azure.sh
```

---

## 🐳 STEP 2: Build and Push Docker Image

### Create: `deployments/azure/scripts/build-and-push.sh`

Make it executable:

```bash
chmod +x deployments/azure/scripts/build-and-push.sh
```

---

## 📦 STEP 3: Deploy Container Instance

### Create: `deployments/azure/scripts/deploy-container.sh`

Make it executable:

```bash
chmod +x deployments/azure/scripts/deploy-container.sh
```

---

## 🔧 STEP 4: Update Dockerfile for Production

Create `Dockerfile`:

---

## 📋 STEP 5: Update Production Config

Create `configs/config.production.yaml`:

# .env file (NOT committed to git, in .gitignore)

JWT_SECRET=your-actual-jwt-secret-here
ORBNET_ENDPOINT=https://api.orbnet.io
ORBNET_API_KEY=your-actual-api-key-here

---

## 🚀 STEP 6: Deploy Everything

Now run the deployment:

```bash
# 1. Setup Azure resources
./deployments/azure/scripts/setup-azure.sh

# Enter your secrets when prompted:
# - JWT_SECRET: (from your OrbNet config)
# - ORBNET_API_KEY: (your API key)
# - ORBNET_ENDPOINT: https://orbnet.xyz/graphql

# 2. Build and push Docker image
./deployments/azure/scripts/build-and-push.sh

# 3. Deploy container
./deployments/azure/scripts/deploy-container.sh
```

---

## ✅ STEP 7: Verify Deployment

```bash
# Get your server URL
FQDN=$(az container show \
  --resource-group orbx-production-rg \
  --name orbx-protocol \
  --query "ipAddress.fqdn" \
  --output tsv)

echo "Server URL: https://$FQDN:8443"

# Test health endpoint
curl -k https://$FQDN:8443/health

# Expected response:
# {"status":"healthy","version":"1.0.0"}

# Test metrics endpoint
curl -k https://$FQDN:8443/metrics

# Check logs
az container logs \
  --resource-group orbx-production-rg \
  --name orbx-protocol \
  --follow
```

---

## 📊 STEP 8: Setup Monitoring (Optional)

Create `deployments/azure/scripts/setup-monitoring.sh`:

````bash
#!/bin/bash

---

## 🔄 STEP 9: Update/Redeploy

Create `deployments/azure/scripts/update.sh`:

Make it executable:

```bash
chmod +x deployments/azure/scripts/update.sh
````

---

## 📝 Quick Reference

```bash
# View logs
az container logs --resource-group orbx-production-rg --name orbx-protocol --follow

# Restart container
az container restart --resource-group orbx-production-rg --name orbx-protocol

# Stop container
az container stop --resource-group orbx-production-rg --name orbx-protocol

# Start container
az container start --resource-group orbx-production-rg --name orbx-protocol

# Delete everything
az group delete --name orbx-production-rg --yes --no-wait
```

---

## 💰 Cost Estimate

**Monthly costs (approximate):**

- Container Instance (2 CPU, 4GB RAM): ~$70/month
- Container Registry (Standard): ~$20/month
- Key Vault: ~$0.03/month
- Virtual Network: Free
- **Total: ~$90/month**

---

## 🎯 Next Steps After Deployment

1. **Setup Custom Domain**: Point your domain to the Azure container
2. **Get SSL Certificate**: Use Let's Encrypt or Azure App Service Certificate
3. **Setup CI/CD**: Automate deployment with GitHub Actions
4. **Configure Alerts**: Setup alerts for downtime, high CPU, etc.
5. **Scale**: Consider Azure Kubernetes Service (AKS) for production scale

**Ready to deploy? Start with Step 1!** 🚀
