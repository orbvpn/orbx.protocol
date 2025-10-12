# ⚡ Quick Setup Guide

Get your OrbX infrastructure deployed in 30 minutes with full automation!

---

## 🎯 What You'll Have After This:

- ✅ Automated deployment (no manual secrets entry)
- ✅ Auto-update on git push (CI/CD)
- ✅ Test-first workflow (safe deployments)
- ✅ Google Meet protocol support
- ✅ 30 global servers (or test with 1 first)

---

## 📋 Prerequisites (5 minutes)

```bash
# Install required tools
brew install azure-cli docker jq git

# Login to Azure
az login

# Verify login
az account show
```

---

## 🚀 Setup Steps

### **Step 1: Get Your Secrets** (2 minutes)

You need these from your OrbNet API:

- `JWT_SECRET`
- `ORBNET_API_KEY`
- `ORBNET_ENDPOINT`

Save them somewhere secure (you'll paste them once).

---

### **Step 2: Clone & Configure** (3 minutes)

```bash
# Clone your repository
cd orbx-server

# Create secrets file from template
cp deployments/azure/.env.deployment.template deployments/azure/.env.deployment

# Edit with your actual secrets (ONE TIME ONLY)
nano deployments/azure/.env.deployment
```

Paste your secrets:

```bash
JWT_SECRET=paste-your-jwt-secret-here
ORBNET_API_KEY=paste-your-api-key-here
ORBNET_ENDPOINT=https://api.orbvpn.com/graphql
```

Save and close.

**⚠️ Important:** This file is in `.gitignore` - it won't be committed!

---

### **Step 3: Automated Azure Setup** (5 minutes)

```bash
cd deployments/azure/scripts

# Make scripts executable
chmod +x *.sh

# Run automated setup (NO prompts!)
./setup-azure-automated.sh
```

This creates:

- Container Registry
- Key Vault (with your secrets)
- Virtual Network
- TLS Certificates

**No manual input required!** ✅

---

### **Step 4: Build Docker Image** (3 minutes)

```bash
./build-and-push.sh
```

Builds your OrbX server and uploads to Azure.

---

### **Step 5: Test Single Server First** (5 minutes)

```bash
./deploy-single-test.sh
```

**What it does:**

- Deploys to ONE test server (eastus)
- Automatically tests health endpoint
- Shows you if everything works
- Gives you server URL to test

**Expected output:**

```
✅ Health check PASSED!
✅ Metrics endpoint accessible
✅ Tunnel endpoint working

Test Deployment Successful! ✅

Test server: https://orbx-test-eastus-xxxxx.eastus.azurecontainer.io:8443
```

---

### **Step 6: Deploy to All 30 Regions** (15 minutes)

If test passed:

```bash
# Clean up test server
az group delete --name orbx-eastus-test-rg --yes

# Deploy to all 30 regions!
./deploy-all-regions.sh
```

Type `yes` when prompted.

**Wait 15-20 minutes** while it deploys to all regions.

---

### **Step 7: Verify All Deployments** (2 minutes)

```bash
./test-all-regions.sh
```

**Expected output:**

```
✅ eastus: Healthy
✅ westus: Healthy
✅ northeurope: Healthy
...
━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Total: 30
Healthy: 30
Unhealthy: 0
━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

---

## 🔄 Setup CI/CD (Optional but Recommended)

### **One-Time GitHub Setup** (5 minutes)

**Step 1: Create Azure Service Principal**

```bash
az ad sp create-for-rbac \
  --name "github-actions-orbx" \
  --role contributor \
  --scopes /subscriptions/$(az account show --query id -o tsv) \
  --sdk-auth
```

**Step 2: Copy the JSON output** (entire JSON object)

**Step 3: Add to GitHub**

1. Go to your GitHub repo
2. Settings → Secrets and variables → Actions
3. Click "New repository secret"
4. Name: `AZURE_CREDENTIALS`
5. Value: Paste the JSON from step 1
6. Click "Add secret"

**Step 4: Add workflow file**

```bash
mkdir -p .github/workflows

# Copy the deploy-azure.yml I created
# Save it to .github/workflows/deploy-azure.yml

git add .github/workflows/deploy-azure.yml
git commit -m "Add CI/CD workflow"
git push
```

✅ **Done!** Now every push to `main` auto-tests, push to `production` auto-deploys!

---

## 🎉 You're Done!

### **What You Have Now:**

| Feature         | Status        | Command                      |
| --------------- | ------------- | ---------------------------- |
| Azure setup     | ✅ Complete   | `./setup-azure-automated.sh` |
| Docker image    | ✅ Built      | `./build-and-push.sh`        |
| Test server     | ✅ Deployed   | `./deploy-single-test.sh`    |
| 30 prod servers | ✅ Deployed   | `./deploy-all-regions.sh`    |
| Auto-deploy     | ✅ Configured | `git push origin production` |

---

## 📱 Next Steps: Build Flutter App

Your backend is ready! Now you can:

1. **Initialize Flutter project**
2. **Connect to OrbNet GraphQL API**
3. **Implement VPN connection logic**
4. **Add protocol switching** (Teams, Meet, Shaparak, DoH, HTTPS)
5. **Test on all platforms**

All backend APIs are ready and documented! 🚀

---

## 🛠️ Daily Usage

### **Update Deployment (Manual)**

```bash
# Make code changes
git commit -am "Updated protocol"

# Build new image
./build-and-push.sh

# Test first!
./deploy-single-test.sh

# If test passes, update all
./manage-all-regions.sh restart
```

### **Update Deployment (Automatic - Recommended)**

```bash
# Make code changes
git commit -am "Updated protocol"

# Push to test
git push origin main
# → Auto-tests on single server

# If test passes, deploy to production
git checkout production
git merge main
git push origin production
# → Auto-deploys to all 30 servers!
```

**No manual steps needed!** ✅

---

## 📊 Management Commands

```bash
# View all servers
./manage-all-regions.sh status

# Stop all servers (save money)
./manage-all-regions.sh stop

# Start all servers
./manage-all-regions.sh start

# Restart all servers (e.g., after update)
./manage-all-regions.sh restart

# View logs from all servers
./manage-all-regions.sh logs

# Test health of all servers
./test-all-regions.sh

# Delete everything
./manage-all-regions.sh delete
```

---

## 💰 Cost Estimate

- **30 regions:** ~$2,620/month
- **10 regions:** ~$900/month
- **1 test server:** ~$90/month

Start with 10 regions to test, scale to 30 when ready!

---

## 🆘 Troubleshooting

### **Setup failed?**

```bash
# Check Azure login
az account show

# Check if secrets file exists
cat deployments/azure/.env.deployment

# Try manual setup
./setup-azure.sh  # Will prompt for secrets
```

### **Test deployment failed?**

```bash
# Check logs
az container logs \
  --resource-group orbx-eastus-test-rg \
  --name orbx-eastus-test \
  --follow

# Check container status
az container show \
  --resource-group orbx-eastus-test-rg \
  --name orbx-eastus-test
```

### **CI/CD not working?**

```bash
# Check GitHub secret exists
# Go to: Repo → Settings → Secrets → Actions

# Check workflow file exists
cat .github/workflows/deploy-azure.yml

# Check GitHub Actions logs
# Go to: Repo → Actions tab
```

---

## ✅ Verification Checklist

After setup, verify:

- [ ] Azure resources created (Container Registry, Key Vault)
- [ ] Docker image pushed to registry
- [ ] Test server deployed and healthy
- [ ] All 30 servers deployed (if you did full deployment)
- [ ] Health checks passing on all servers
- [ ] `deployed-servers.txt` file created with all URLs
- [ ] GitHub Actions workflow added (if using CI/CD)
- [ ] CI/CD working (push to `main` triggers test)

---

**Time to complete:** 30-40 minutes

**Difficulty:** Easy (all automated!)

**Result:** Production-ready VPN infrastructure! 🎊
