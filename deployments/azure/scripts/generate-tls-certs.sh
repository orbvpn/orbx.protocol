#!/bin/bash

# Generate self-signed TLS certificates for OrbX Server
# Location: deployments/azure/scripts/generate-tls-certs.sh

set -e

KEYVAULT_NAME="orbx-vault"
CERT_DIR="./certs"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}🔐 Generating TLS Certificates${NC}"
echo "=============================================="

# Create certs directory
mkdir -p $CERT_DIR

# Generate private key
echo -e "\n${YELLOW}Generating private key...${NC}"
openssl genrsa -out $CERT_DIR/server.key 2048

# Generate certificate signing request
echo -e "\n${YELLOW}Generating CSR...${NC}"
openssl req -new -key $CERT_DIR/server.key \
  -out $CERT_DIR/server.csr \
  -subj "/C=US/ST=State/L=City/O=OrbVPN/CN=*.azurecontainer.io"

# Generate self-signed certificate (valid for 1 year)
echo -e "\n${YELLOW}Generating self-signed certificate...${NC}"
openssl x509 -req -days 365 \
  -in $CERT_DIR/server.csr \
  -signkey $CERT_DIR/server.key \
  -out $CERT_DIR/server.crt

# Convert to PEM format (Azure format)
echo -e "\n${YELLOW}Converting to PEM format...${NC}"
cat $CERT_DIR/server.crt > $CERT_DIR/cert.pem
cat $CERT_DIR/server.key > $CERT_DIR/key.pem

# Upload to Azure Key Vault
echo -e "\n${YELLOW}Uploading to Azure Key Vault...${NC}"

# Convert cert and key to base64 for storage
TLS_CERT=$(base64 -i $CERT_DIR/cert.pem | tr -d '\n')
TLS_KEY=$(base64 -i $CERT_DIR/key.pem | tr -d '\n')

az keyvault secret set \
  --vault-name $KEYVAULT_NAME \
  --name "TLS-CERT" \
  --value "$TLS_CERT"

az keyvault secret set \
  --vault-name $KEYVAULT_NAME \
  --name "TLS-KEY" \
  --value "$TLS_KEY"

echo -e "\n${GREEN}✅ TLS Certificates generated and stored in Key Vault${NC}"
echo -e "${GREEN}Cert location: $CERT_DIR/cert.pem${NC}"
echo -e "${GREEN}Key location: $CERT_DIR/key.pem${NC}"

# Verify certificate
echo -e "\n${YELLOW}Certificate Details:${NC}"
openssl x509 -in $CERT_DIR/cert.pem -text -noout | grep -A 2 "Subject:"
openssl x509 -in $CERT_DIR/cert.pem -text -noout | grep -A 2 "Validity"

echo -e "\n${GREEN}✅ Done! Certificates are ready for deployment.${NC}"