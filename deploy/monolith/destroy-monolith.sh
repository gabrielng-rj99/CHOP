#!/bin/bash

# Client Hub - Destroy Monolith Environment Script
# ⚠️  WARNING: This script completely destroys the monolith environment:
# - Stops all services
# - Drops the database and user
# - Removes logs, certificates, builds, and data
# - This action is IRREVERSIBLE!

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Resolve Paths
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
CONFIG_FILE="$SCRIPT_DIR/monolith.ini"

echo ""
echo -e "${RED}${BOLD}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${RED}${BOLD}║                    ⚠️  DANGER ZONE ⚠️                          ║${NC}"
echo -e "${RED}${BOLD}║              Destroy Monolith Environment                      ║${NC}"
echo -e "${RED}${BOLD}╚════════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${YELLOW}This will permanently delete:${NC}"
echo -e "  ${RED}✗${NC} Database: ${BOLD}ehopdb${NC} (all data will be lost)"
echo -e "  ${RED}✗${NC} Database user: ${BOLD}ehopuser${NC}"
echo -e "  ${RED}✗${NC} Backend logs"
echo -e "  ${RED}✗${NC} Frontend build (dist/)"
echo -e "  ${RED}✗${NC} SSL certificates"
echo -e "  ${RED}✗${NC} Compiled binaries"
echo -e "  ${RED}✗${NC} All temporary files"
echo ""
echo -e "${RED}${BOLD}⚠️  THIS ACTION CANNOT BE UNDONE! ⚠️${NC}"
echo ""

# First confirmation
read -p "Are you ABSOLUTELY sure you want to destroy everything? (type 'yes' to confirm): " -r
echo ""
if [[ ! "$REPLY" == "yes" ]]; then
    echo -e "${GREEN}Aborted. Nothing was deleted.${NC}"
    exit 0
fi

# Second confirmation
echo -e "${YELLOW}Last chance! This will delete ALL data permanently.${NC}"
read -p "Type 'DELETE EVERYTHING' to proceed: " -r
echo ""
if [[ ! "$REPLY" == "DELETE EVERYTHING" ]]; then
    echo -e "${GREEN}Aborted. Nothing was deleted.${NC}"
    exit 0
fi

echo ""
echo -e "${RED}🔥 Proceeding with destruction...${NC}"
echo ""

# Load configuration
echo "📄 Loading configuration..."
if [ -f "$CONFIG_FILE" ]; then
    # Load config variables
    declare -A CONFIG
    while IFS= read -r line; do
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        [[ -z "$line" ]] && continue
        if [[ "$line" =~ ^[[:space:]]*([A-Z_][A-Z0-9_]*)=(.*)$ ]]; then
            key="${BASH_REMATCH[1]}"
            value="${BASH_REMATCH[2]}"
            value="${value%\"}"
            value="${value#\"}"
            CONFIG[$key]="$value"
            export "$key=$value"
        fi
    done < "$CONFIG_FILE"
    echo -e "${GREEN}✓ Configuration loaded${NC}"
else
    echo -e "${YELLOW}⚠️  Configuration file not found, using defaults${NC}"
fi

# Set defaults
DB_HOST="${DB_HOST:-localhost}"
DB_PORT="${DB_PORT:-5432}"
DB_USER="${DB_USER:-ehopuser}"
DB_NAME="${DB_NAME:-ehopdb}"

echo ""

# Stop services first
echo "🛑 Stopping all services..."
if [ -f "$SCRIPT_DIR/stop-monolith.sh" ]; then
    bash "$SCRIPT_DIR/stop-monolith.sh" 2>/dev/null || true
    echo -e "${GREEN}✓ Services stopped${NC}"
else
    echo -e "${YELLOW}⚠️  stop-monolith.sh not found, skipping${NC}"
fi

echo ""

# Drop database and user
echo "🗄️  Destroying database..."
if command -v psql >/dev/null 2>&1; then
    # Check if database exists
    DB_EXISTS=$(sudo -u postgres psql -h "$DB_HOST" -p "$DB_PORT" -tAc "SELECT 1 FROM pg_database WHERE datname='${DB_NAME}'" 2>/dev/null | tr -d ' ')

    if [[ "$DB_EXISTS" == "1" ]]; then
        echo "Dropping database ${DB_NAME}..."

        # First, terminate all connections to the database
        echo "  → Terminating active connections..."
        sudo -u postgres psql -h "$DB_HOST" -p "$DB_PORT" -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '${DB_NAME}' AND pid <> pg_backend_pid();" >/dev/null 2>&1 || true

        # Wait a moment for connections to close
        sleep 1

        # Now drop the database
        DROP_OUTPUT=$(sudo -u postgres psql -h "$DB_HOST" -p "$DB_PORT" -c "DROP DATABASE ${DB_NAME};" 2>&1)
        DROP_EXIT=$?

        if [ $DROP_EXIT -eq 0 ]; then
            echo -e "${GREEN}✓ Database ${DB_NAME} dropped${NC}"
        else
            echo -e "${RED}❌ Failed to drop database${NC}"
            echo "Error: $DROP_OUTPUT"
            echo ""
            echo "Possible reasons:"
            echo "  • Active connections (try stopping services first)"
            echo "  • Insufficient permissions"
            echo ""
            echo "Manual fix:"
            echo "  sudo -u postgres psql -c \"SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '${DB_NAME}';\""
            echo "  sudo -u postgres psql -c \"DROP DATABASE ${DB_NAME};\""
        fi
    else
        echo -e "${YELLOW}⚠️  Database ${DB_NAME} does not exist${NC}"
    fi

    # Drop user
    USER_EXISTS=$(sudo -u postgres psql -h "$DB_HOST" -p "$DB_PORT" -tAc "SELECT 1 FROM pg_roles WHERE rolname='${DB_USER}'" 2>/dev/null | tr -d ' ')

    if [[ "$USER_EXISTS" == "1" ]]; then
        echo "Dropping user ${DB_USER}..."

        DROP_USER_OUTPUT=$(sudo -u postgres psql -h "$DB_HOST" -p "$DB_PORT" -c "DROP USER ${DB_USER};" 2>&1)
        DROP_USER_EXIT=$?

        if [ $DROP_USER_EXIT -eq 0 ]; then
            echo -e "${GREEN}✓ User ${DB_USER} dropped${NC}"
        else
            echo -e "${RED}❌ Failed to drop user${NC}"
            echo "Error: $DROP_USER_OUTPUT"
            echo ""
            echo "Manual fix:"
            echo "  sudo -u postgres psql -c \"DROP USER ${DB_USER};\""
        fi
    else
        echo -e "${YELLOW}⚠️  User ${DB_USER} does not exist${NC}"
    fi
else
    echo -e "${YELLOW}⚠️  PostgreSQL not found, skipping database cleanup${NC}"
fi

echo ""

# Remove directories and files
echo "🗑️  Removing files and directories..."

# Backend binary
if [ -f "$PROJECT_ROOT/backend/ehop-backend.bin" ]; then
    rm -f "$PROJECT_ROOT/backend/ehop-backend.bin"
    echo -e "${GREEN}✓ Removed backend binary${NC}"
fi

# Frontend build
if [ -d "$PROJECT_ROOT/frontend/dist" ]; then
    rm -rf "$PROJECT_ROOT/frontend/dist"
    echo -e "${GREEN}✓ Removed frontend build (dist/)${NC}"
fi

# Logs
if [ -d "$PROJECT_ROOT/logs/backend" ]; then
    rm -rf "$PROJECT_ROOT/logs/backend"
    echo -e "${GREEN}✓ Removed backend logs${NC}"
fi

if [ -d "$PROJECT_ROOT/logs" ] && [ -z "$(ls -A "$PROJECT_ROOT/logs" 2>/dev/null)" ]; then
    rm -rf "$PROJECT_ROOT/logs"
    echo -e "${GREEN}✓ Removed logs directory${NC}"
fi

# SSL certificates
if [ -d "$PROJECT_ROOT/deploy/certs/ssl" ]; then
    rm -rf "$PROJECT_ROOT/deploy/certs/ssl"
    echo -e "${GREEN}✓ Removed SSL certificates${NC}"
fi

if [ -d "$PROJECT_ROOT/deploy/certs" ] && [ -z "$(ls -A "$PROJECT_ROOT/deploy/certs" 2>/dev/null)" ]; then
    rm -rf "$PROJECT_ROOT/deploy/certs"
    echo -e "${GREEN}✓ Removed certs directory${NC}"
fi

# Data directory (if exists)
if [ -d "$PROJECT_ROOT/data/db" ]; then
    rm -rf "$PROJECT_ROOT/data/db"
    echo -e "${GREEN}✓ Removed data directory${NC}"
fi

if [ -d "$PROJECT_ROOT/data" ] && [ -z "$(ls -A "$PROJECT_ROOT/data" 2>/dev/null)" ]; then
    rm -rf "$PROJECT_ROOT/data"
fi

# Nginx runtime config
if [ -f "$SCRIPT_DIR/nginx-runtime.conf" ]; then
    rm -f "$SCRIPT_DIR/nginx-runtime.conf"
    echo -e "${GREEN}✓ Removed nginx runtime config${NC}"
fi

# Temporary nginx config
if [ -f "/tmp/Client-Hub-monolith.conf" ]; then
    sudo rm -f /tmp/Client-Hub-monolith.conf 2>/dev/null || true
    echo -e "${GREEN}✓ Removed temporary nginx config${NC}"
fi

# PID files
if [ -f "/tmp/ehop-backend.bin.pid" ]; then
    rm -f /tmp/ehop-backend.bin.pid
    echo -e "${GREEN}✓ Removed PID file${NC}"
fi

# Nginx logs
if [ -f "/tmp/ehop_access.log" ]; then
    sudo rm -f /tmp/ehop_access.log 2>/dev/null || true
    echo -e "${GREEN}✓ Removed nginx access log${NC}"
fi

# Nginx logs
if [ -f "/tmp/ehop_error.log" ]; then
    sudo rm -f /tmp/ehop_error.log 2>/dev/null || true
    echo -e "${GREEN}✓ Removed nginx error log${NC}"
fi

# Clear passwords from monolith.ini
echo "🔐 Clearing passwords from configuration..."
if [ -f "$CONFIG_FILE" ]; then
    # Reset DB_PASSWORD to empty
    sed -i 's/^DB_PASSWORD=.*/DB_PASSWORD=/' "$CONFIG_FILE"
    echo -e "${GREEN}✓ Cleared DB_PASSWORD from monolith.ini${NC}"

    # Reset JWT_SECRET to empty
    sed -i 's/^JWT_SECRET=.*/JWT_SECRET=/' "$CONFIG_FILE"
    echo -e "${GREEN}✓ Cleared JWT_SECRET from monolith.ini${NC}"
fi

echo ""
echo -e "${GREEN}${BOLD}✅ Monolith environment completely destroyed!${NC}"
echo ""
echo -e "${BLUE}The following was preserved:${NC}"
echo -e "  ✓ Source code (backend/ and frontend/)"
echo -e "  ✓ Configuration file (monolith.ini) - passwords cleared"
echo -e "  ✓ Node modules (frontend/node_modules/)"
echo -e "  ✓ Go modules cache"
echo ""
echo -e "${YELLOW}To recreate the environment, run:${NC}"
echo -e "  ${BOLD}./start-monolith.sh${NC}"
echo -e "${BLUE}(New passwords will be auto-generated)${NC}"
echo ""
