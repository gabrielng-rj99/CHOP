#!/bin/bash

# Client Hub - Destroy Development Environment Script
# ⚠️  WARNING: This script completely destroys the development environment:
# - Stops all services (backend + Vite)
# - Drops the development database and user
# - Removes logs, builds, and temporary files
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
CONFIG_FILE="$SCRIPT_DIR/dev.ini"

echo ""
echo -e "${RED}${BOLD}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${RED}${BOLD}║                    ⚠️  DANGER ZONE ⚠️                          ║${NC}"
echo -e "${RED}${BOLD}║            Destroy Development Environment                     ║${NC}"
echo -e "${RED}${BOLD}╚════════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${YELLOW}This will permanently delete:${NC}"
echo -e "  ${RED}✗${NC} Development database: ${BOLD}ehopdb_dev${NC} (all data will be lost)"
echo -e "  ${RED}✗${NC} Database user: ${BOLD}ehopuser${NC}"
echo -e "  ${RED}✗${NC} Development logs (backend + Vite)"
echo -e "  ${RED}✗${NC} Compiled backend binary"
echo -e "  ${RED}✗${NC} All temporary files"
echo ""
echo -e "${BLUE}ℹ️  The following will be preserved:${NC}"
echo -e "  ${GREEN}✓${NC} Source code"
echo -e "  ${GREEN}✓${NC} Configuration file (dev.ini)"
echo -e "  ${GREEN}✓${NC} node_modules/ and Go modules cache"
echo -e "  ${GREEN}✓${NC} Production database (ehopdb) - if exists"
echo ""
echo -e "${RED}${BOLD}⚠️  THIS ACTION CANNOT BE UNDONE! ⚠️${NC}"
echo ""





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
DB_NAME="${DB_NAME:-ehopdb_dev}"

echo ""

# Stop services first
echo "🛑 Stopping all development services..."
if [ -f "$SCRIPT_DIR/stop-dev.sh" ]; then
    bash "$SCRIPT_DIR/stop-dev.sh" 2>/dev/null || true
    echo -e "${GREEN}✓ Services stopped${NC}"
else
    echo -e "${YELLOW}⚠️  stop-dev.sh not found, skipping${NC}"
fi

echo ""

# Drop database (but not user - user might be shared with production)
echo "🗄️  Destroying development database..."
if command -v psql >/dev/null 2>&1; then
    # Check if development database exists
    DB_EXISTS=$(sudo -u postgres psql -h "$DB_HOST" -p "$DB_PORT" -tAc "SELECT 1 FROM pg_database WHERE datname='${DB_NAME}'" 2>/dev/null | tr -d ' ')

    if [[ "$DB_EXISTS" == "1" ]]; then
        echo "Dropping development database ${DB_NAME}..."

        # First, terminate all connections to the database
        echo "  → Terminating active connections..."
        sudo -u postgres psql -h "$DB_HOST" -p "$DB_PORT" -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '${DB_NAME}' AND pid <> pg_backend_pid();" >/dev/null 2>&1 || true

        # Wait a moment for connections to close
        sleep 1

        # Now drop the database
        DROP_OUTPUT=$(sudo -u postgres psql -h "$DB_HOST" -p "$DB_PORT" -c "DROP DATABASE ${DB_NAME};" 2>&1)
        DROP_EXIT=$?

        if [ $DROP_EXIT -eq 0 ]; then
            echo -e "${GREEN}✓ Development database ${DB_NAME} dropped${NC}"
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
        echo -e "${YELLOW}⚠️  Development database ${DB_NAME} does not exist${NC}"
    fi

    # Note: We don't drop the user here as it might be shared with production
    echo -e "${BLUE}ℹ️  Database user ${DB_USER} was preserved (might be shared with production)${NC}"
else
    echo -e "${YELLOW}⚠️  PostgreSQL not found, skipping database cleanup${NC}"
fi

echo ""

# Remove directories and files
echo "🗑️  Removing development files..."

# Backend binary (dev version)
if [ -f "$PROJECT_ROOT/backend/ehop-backend-dev" ]; then
    rm -f "$PROJECT_ROOT/backend/ehop-backend-dev"
    echo -e "${GREEN}✓ Removed development backend binary${NC}"
fi

# Development logs
if [ -d "$PROJECT_ROOT/logs/backend_dev" ]; then
    rm -rf "$PROJECT_ROOT/logs/backend_dev"
    echo -e "${GREEN}✓ Removed development backend logs${NC}"
fi

if [ -f "$PROJECT_ROOT/logs/vite-dev.log" ]; then
    rm -f "$PROJECT_ROOT/logs/vite-dev.log"
    echo -e "${GREEN}✓ Removed Vite dev log${NC}"
fi

# Remove logs directory if empty
if [ -d "$PROJECT_ROOT/logs" ] && [ -z "$(ls -A "$PROJECT_ROOT/logs" 2>/dev/null)" ]; then
    rm -rf "$PROJECT_ROOT/logs"
    echo -e "${GREEN}✓ Removed logs directory${NC}"
fi

# Development data directory (if exists)
if [ -d "$PROJECT_ROOT/data/db_dev" ]; then
    rm -rf "$PROJECT_ROOT/data/db_dev"
    echo -e "${GREEN}✓ Removed development data directory${NC}"
fi

# Remove data directory if empty
if [ -d "$PROJECT_ROOT/data" ] && [ -z "$(ls -A "$PROJECT_ROOT/data" 2>/dev/null)" ]; then
    rm -rf "$PROJECT_ROOT/data"
fi

# PID files (new locations)
if [ -f "$PROJECT_ROOT/logs/backend_dev/backend.pid" ]; then
    rm -f "$PROJECT_ROOT/logs/backend_dev/backend.pid"
    echo -e "${GREEN}✓ Removed backend PID file${NC}"
fi

if [ -f "$PROJECT_ROOT/logs/vite-dev.pid" ]; then
    rm -f "$PROJECT_ROOT/logs/vite-dev.pid"
    echo -e "${GREEN}✓ Removed Vite PID file${NC}"
fi

# Old PID file locations (cleanup if they exist)
if [ -f "/tmp/ehop-backend-dev.pid" ]; then
    rm -f /tmp/ehop-backend-dev.pid
    echo -e "${GREEN}✓ Removed old backend PID file${NC}"
fi

if [ -f "/tmp/ehop-vite-dev.pid" ]; then
    rm -f /tmp/ehop-vite-dev.pid
    echo -e "${GREEN}✓ Removed old Vite PID file${NC}"
fi



echo ""
echo -e "${GREEN}${BOLD}✅ Development environment completely destroyed!${NC}"
echo ""
echo -e "${BLUE}The following was preserved:${NC}"
echo -e "  ✓ Source code (backend/ and frontend/)"
echo -e "  ✓ Configuration file (dev.ini)"
echo -e "  ✓ Node modules (frontend/node_modules/)"
echo -e "  ✓ Go modules cache"
echo -e "  ✓ Database user (${DB_USER}) - might be shared"
echo -e "  ✓ Production database (ehopdb) - if exists"
echo -e "  ✓ Production environment files"
echo ""
echo -e "${YELLOW}To recreate the development environment, run:${NC}"
echo -e "  ${BOLD}./start-dev.sh${NC}"
echo ""
