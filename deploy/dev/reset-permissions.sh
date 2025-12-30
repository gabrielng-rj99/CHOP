#!/bin/bash

# Client Hub - Reset Permissions and Clean Restart
# This script fixes permission issues and does a clean restart

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'
BOLD='\033[1m'

echo -e "${BLUE}🔧 Resetting Client Hub Development Environment${NC}"
echo -e "${BLUE}=================================================${NC}"
echo ""

# Resolve Paths
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"

cd "$PROJECT_ROOT"

echo "1️⃣  Stopping all processes..."
# Kill backend
pkill -f ehop-backend-dev 2>/dev/null || true

# Kill Vite
pkill -f "vite.*dev" 2>/dev/null || true
pkill -f "npm run dev" 2>/dev/null || true

# Kill node processes on common ports
lsof -ti:5173 2>/dev/null | xargs kill -9 2>/dev/null || true
lsof -ti:3000 2>/dev/null | xargs kill -9 2>/dev/null || true

echo -e "${GREEN}✓ Processes stopped${NC}"
echo ""

echo "2️⃣  Fixing permissions..."
# Check if logs directory needs sudo
if [ -d "logs" ]; then
    # Try without sudo first
    if touch logs/.test 2>/dev/null; then
        rm -f logs/.test
        echo -e "${GREEN}✓ Permissions OK (no sudo needed)${NC}"
    else
        echo -e "${YELLOW}⚠️  Need sudo to fix permissions...${NC}"
        sudo chown -R $USER:$USER logs/ 2>/dev/null || true
        echo -e "${GREEN}✓ Permissions fixed${NC}"
    fi
fi

# Clean old logs and PIDs
rm -rf logs/* 2>/dev/null || true
mkdir -p logs/backend_dev

# Remove old PID files from /tmp
rm -f /tmp/ehop-backend-dev.pid 2>/dev/null || true
rm -f /tmp/ehop-vite-dev.pid 2>/dev/null || true

echo -e "${GREEN}✓ Permissions fixed${NC}"
echo ""

echo "3️⃣  Cleaning build artifacts..."
cd "$PROJECT_ROOT/backend"
rm -f ehop-backend-dev 2>/dev/null || true
echo -e "${GREEN}✓ Backend cleaned${NC}"
echo ""

echo "4️⃣  Rebuilding backend..."
if go build -o ehop-backend-dev ./cmd/server/main.go; then
    echo -e "${GREEN}✓ Backend built successfully${NC}"
else
    echo -e "${RED}❌ Backend build failed!${NC}"
    exit 1
fi
echo ""

echo "5️⃣  Checking frontend dependencies..."
cd "$PROJECT_ROOT/frontend"
if [ ! -d "node_modules" ]; then
    echo "Installing npm dependencies..."
    npm install
else
    echo -e "${GREEN}✓ Dependencies OK${NC}"
fi
echo ""

echo -e "${GREEN}✅ Reset complete!${NC}"
echo ""
echo -e "${BOLD}Next steps:${NC}"
echo "  1. Start the development environment:"
echo "     ${BLUE}./deploy/dev/start-dev.sh${NC}"
echo ""
echo "  2. Wait for both services to start (30-60 seconds)"
echo ""
echo "  3. Access the application:"
echo "     ${BLUE}http://localhost:5173${NC}"
echo ""
echo "  4. If you see errors, check the logs:"
echo "     ${BLUE}tail -f logs/backend_dev/server.log${NC}"
echo "     ${BLUE}tail -f logs/vite-dev.log${NC}"
echo ""
echo -e "${YELLOW}⚠️  Remember: Do NOT use sudo to run start-dev.sh${NC}"
echo ""
