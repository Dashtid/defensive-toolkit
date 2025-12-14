#!/bin/bash
# SSL Certificate Generation Script for Defensive Toolkit
# Generates self-signed certificates for development and staging
# For production, use Let's Encrypt or your organization's CA

set -e

# Configuration
CERT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERT_FILE="$CERT_DIR/cert.pem"
KEY_FILE="$CERT_DIR/key.pem"
DAYS_VALID=365

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo "[*] SSL Certificate Generation for Defensive Toolkit"
echo "=============================================="

# Check if OpenSSL is installed
if ! command -v openssl &> /dev/null; then
    echo -e "${RED}[X] OpenSSL is not installed${NC}"
    exit 1
fi

# Prompt for certificate details
echo -e "\n${YELLOW}[!] Enter certificate details (or press Enter for defaults):${NC}"
read -p "Country (C) [US]: " COUNTRY
COUNTRY=${COUNTRY:-US}

read -p "State (ST) [California]: " STATE
STATE=${STATE:-California}

read -p "City (L) [San Francisco]: " CITY
CITY=${CITY:-San Francisco}

read -p "Organization (O) [Defensive Toolkit]: " ORG
ORG=${ORG:-Defensive Toolkit}

read -p "Common Name (CN) [localhost]: " CN
CN=${CN:-localhost}

read -p "Email [admin@localhost]: " EMAIL
EMAIL=${EMAIL:-admin@localhost}

# Create certificate directory if it doesn't exist
mkdir -p "$CERT_DIR"

# Check if certificates already exist
if [ -f "$CERT_FILE" ] && [ -f "$KEY_FILE" ]; then
    echo -e "\n${YELLOW}[!] Certificates already exist${NC}"
    read -p "Do you want to overwrite them? (y/N): " OVERWRITE
    if [ "$OVERWRITE" != "y" ] && [ "$OVERWRITE" != "Y" ]; then
        echo -e "${GREEN}[OK] Keeping existing certificates${NC}"
        exit 0
    fi
    echo "[*] Backing up existing certificates..."
    mv "$CERT_FILE" "$CERT_FILE.bak.$(date +%s)"
    mv "$KEY_FILE" "$KEY_FILE.bak.$(date +%s)"
fi

# Generate self-signed certificate
echo -e "\n[*] Generating self-signed certificate..."
openssl req -x509 -nodes -days $DAYS_VALID -newkey rsa:4096 \
    -keyout "$KEY_FILE" \
    -out "$CERT_FILE" \
    -subj "/C=$COUNTRY/ST=$STATE/L=$CITY/O=$ORG/CN=$CN/emailAddress=$EMAIL" \
    -addext "subjectAltName=DNS:localhost,DNS:api,DNS:$CN,IP:127.0.0.1,IP:172.20.0.0/16"

# Set proper permissions
chmod 600 "$KEY_FILE"
chmod 644 "$CERT_FILE"

echo -e "${GREEN}[OK] Certificate generated successfully${NC}"
echo ""
echo "Certificate details:"
echo "  - Certificate: $CERT_FILE"
echo "  - Private Key: $KEY_FILE"
echo "  - Valid for: $DAYS_VALID days"
echo ""

# Display certificate information
echo "[*] Certificate Information:"
openssl x509 -in "$CERT_FILE" -noout -text | grep -A2 "Subject:"
echo ""

# Verify certificate
echo "[*] Verifying certificate..."
openssl verify -CAfile "$CERT_FILE" "$CERT_FILE" || true

echo ""
echo -e "${YELLOW}[!] IMPORTANT NOTES:${NC}"
echo "1. This is a self-signed certificate suitable for development/staging only"
echo "2. Browsers will show security warnings - this is expected"
echo "3. For production, use Let's Encrypt or your organization's CA"
echo ""
echo "To use Let's Encrypt in production:"
echo "  1. Install Certbot: https://certbot.eff.org/"
echo "  2. Run: certbot certonly --webroot -w /var/www/certbot -d yourdomain.com"
echo "  3. Update docker-compose.yml to mount Let's Encrypt certificates"
echo ""
echo -e "${GREEN}[OK] Certificate generation complete${NC}"
