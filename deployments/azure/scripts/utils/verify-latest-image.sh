#!/bin/bash

# Verification Script: Check if 'latest' is truly the latest image

REGISTRY="orbxregistry.azurecr.io"
REPO="orbx-protocol"

echo "🔍 Checking all tags ordered by creation time (newest first)..."
echo ""

# Show tags ordered by time (newest first)
az acr repository show-tags \
  --name orbxregistry \
  --repository $REPO \
  --orderby time_desc \
  --output table

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🔎 Checking if latest, prod, and timestamped tags point to same image:"
echo ""

# Get digests (the actual unique identifier of the image content)
LATEST_DIGEST=$(az acr repository show --name orbxregistry --image ${REPO}:latest --query "digest" -o tsv)
PROD_DIGEST=$(az acr repository show --name orbxregistry --image ${REPO}:prod --query "digest" -o tsv)
DATE_DIGEST=$(az acr repository show --name orbxregistry --image ${REPO}:20251027-191510 --query "digest" -o tsv)

echo "latest digest:          $LATEST_DIGEST"
echo "prod digest:            $PROD_DIGEST"  
echo "20251027-191510 digest: $DATE_DIGEST"
echo ""

if [ "$LATEST_DIGEST" = "$PROD_DIGEST" ] && [ "$LATEST_DIGEST" = "$DATE_DIGEST" ]; then
    echo "✅ SUCCESS: All three tags point to the SAME image!"
    echo "   Your 'latest' tag is correctly updated."
else
    echo "⚠️  WARNING: Tags point to DIFFERENT images!"
    echo "   'latest' might not be your newest build."
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📅 Timestamps for key tags:"
echo ""

for tag in latest prod 20251027-191510; do
    echo "Tag: $tag"
    az acr repository show \
      --name orbxregistry \
      --image ${REPO}:$tag \
      --query "{created: createdTime, updated: lastUpdateTime}" \
      --output table
    echo ""
done
```

## 📖 **What This Script Does**

1. **Orders tags by creation time** - Shows which is truly newest
2. **Compares image digests** - The digest (sha256:...) is the unique fingerprint of the actual image content
3. **Shows timestamps** - When each tag was created/updated

## ✅ **What You Should See If Everything Is Correct**

All three tags (`latest`, `prod`, `20251027-191510`) should have:
- **Same digest** (sha256:386b0c796adef...)
- **Same or very close timestamps**

## 🔧 **How Docker Build/Push Tags Work**

From your build output, I can see you're doing a **multi-platform build**, which means:
```
docker buildx build --platform linux/amd64,linux/arm64 \
  -t orbxregistry.azurecr.io/orbx-protocol:latest \
  -t orbxregistry.azurecr.io/orbx-protocol:prod \
  -t orbxregistry.azurecr.io/orbx-protocol:20251027-191510 \
  --push .