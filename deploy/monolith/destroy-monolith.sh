#!/bin/bash

# Contract Manager - Destroy Monolith Environment Script
# This script completely destroys the monolith environment:
# - Stops all services
# - Drops the database
# - Removes logs, certificates, and data

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color
BOLD='\033[1m'

echo -e "${RED}💥 Destroying Contract Manager (Monolith Mode)${NC}"
echo -e "${RED}================================================${NC}"
echo -e "${YELLOW}⚠️  This will permanently delete the database and all data!${NC}"
echo ""

read -p "Are you sure you want to continue? (yes/no): " -r
if [[ ! $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
    echo "Aborted."
    exit 0
fi

echo ""

# Load configuration
CONFIG_FILE="monolith.ini"
if [ -f "$CONFIG_FILE" ]; then
    while IFS='=' read -r key value; do
        [[ $key =~ ^[[:space:]]*# ]] && continue
        [[ -z "$key" ]] && continue
        key=$(echo "$key" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        value=$(echo "$value" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        export "$key=$value"
    done < "$CONFIG_FILE"
fi

# Stop services first
echo "Stopping services..."
./stop-monolith.sh

echo ""

# Drop database
echo "Dropping database..."
if psql -h ${DB_HOST:-localhost} -p ${DB_PORT:-5432} -U ${DB_USER:-postgres} -c "DROP DATABASE IF EXISTS ${DB_NAME:-entity_hub};" 2>/dev/null; then
    echo -e "${GREEN}✓ Database dropped${NC}"
else
    echo -e "${YELLOW}⚠️  Could not drop database (may not exist or insufficient permissions)${NC}"
fi

# Remove data directories
echo "Removing data directories..."
DIRS_TO_REMOVE=(
    "${POSTGRES_VOLUME_PATH:-./data/db}"
    "${BACKEND_LOGS_PATH:-./logs/backend}"
    "${SSL_CERTS_PATH:-./certs/ssl}"
    "./logs"
    "./data"
    "./certs"
)

for dir in "${DIRS_TO_REMOVE[@]}"; do
    if [ -d "$dir" ]; then
        rm -rf "$dir"
        echo -e "${GREEN}✓ Removed $dir${NC}"
    fi
done

# Remove temporary nginx config
if [ -f "/tmp/entity-hub-monolith.conf" ]; then
    rm -f /tmp/entity-hub-monolith.conf
    echo -e "${GREEN}✓ Removed temporary nginx config${NC}"
fi

echo ""
echo -e "${GREEN}✅ Monolith environment destroyed successfully!${NC}"
echo -e "${YELLOW}To recreate, run: ./start-monolith.sh${NC}"
