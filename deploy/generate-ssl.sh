#!/bin/bash

# SSL Certificate Generation Script
# Unified script for both Docker and Monolith deployments
# Reads configuration from deploy/certs-config.ini

set -e

# Determine script location and config file
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${CONFIG_FILE:-$SCRIPT_DIR/certs-config.ini}"

# If called from container, config will be at /certs-config.ini
if [ ! -f "$CONFIG_FILE" ] && [ -f "/certs-config.ini" ]; then
    CONFIG_FILE="/certs-config.ini"
fi

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# Function to read config value
get_config() {
    local key=$1
    grep "^$key=" "$CONFIG_FILE" | cut -d'=' -f2 | sed 's/^[[:space:]]*//;s/[[:space:]]*$//'
}

# Determine certificate directory
# First argument is cert directory path, can be:
# - Absolute path (from container): /etc/nginx/ssl
# - Relative path (from monolith): ./certs/ssl
# - Default: ./certs/ssl
if [ -n "$1" ] && [[ "$1" == /* ]]; then
    # Absolute path provided (from container)
    CERT_DIR="$1"
else
    # Relative path or default
    CERT_DIR="${1:-.}/certs/ssl"
fi

# Check if config file exists
if [ ! -f "$CONFIG_FILE" ]; then
    echo -e "${RED}❌ Error: SSL config file not found at $CONFIG_FILE${NC}"
    exit 1
fi

echo -e "${YELLOW}🔐 Generating SSL certificates...${NC}"

# Create SSL directory
mkdir -p "$CERT_DIR"

# Read configuration values
COMMON_NAME=$(get_config common_name)
COUNTRY=$(get_config country)
STATE=$(get_config state)
LOCALITY=$(get_config locality)
ORGANIZATION=$(get_config organization)
ORGANIZATIONAL_UNIT=$(get_config organizational_unit)
EMAIL=$(get_config email)
DAYS=$(get_config days)
KEY_SIZE=$(get_config key_size)
ALT_NAMES=$(get_config alt_names)

SERVER_CERT="$CERT_DIR/server.crt"
SERVER_KEY="$CERT_DIR/server.key"

# Generate certificate if not exists
if [ ! -f "$SERVER_CERT" ] || [ ! -f "$SERVER_KEY" ]; then
    # Build subject string
    SUBJECT="/C=$COUNTRY/ST=$STATE/L=$LOCALITY/O=$ORGANIZATION/OU=$ORGANIZATIONAL_UNIT/CN=$COMMON_NAME/emailAddress=$EMAIL"

    # Build and execute openssl command
    if [ -n "$ALT_NAMES" ]; then
        openssl req -x509 -nodes -days "$DAYS" -newkey "rsa:$KEY_SIZE" \
            -keyout "$SERVER_KEY" \
            -out "$SERVER_CERT" \
            -subj "$SUBJECT" \
            -addext "subjectAltName=$ALT_NAMES"
    else
        openssl req -x509 -nodes -days "$DAYS" -newkey "rsa:$KEY_SIZE" \
            -keyout "$SERVER_KEY" \
            -out "$SERVER_CERT" \
            -subj "$SUBJECT"
    fi

    echo -e "${GREEN}✅ SSL certificates generated${NC}"
    echo -e "   ${GREEN}Certificate:${NC} $SERVER_CERT"
    echo -e "   ${GREEN}Private Key:${NC} $SERVER_KEY"
else
    echo -e "${GREEN}✅ SSL certificates already exist${NC}"
fi

echo -e "${YELLOW}🔒 Certificate details:${NC}"
openssl x509 -in "$SERVER_CERT" -text -noout | grep -E "(Subject:|Not Before:|Not After:|DNS:)"
