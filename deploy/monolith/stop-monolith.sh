#!/bin/bash

# Contract Manager - Stop Monolith Services Script
# This script stops all running monolith services.

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color
BOLD='\033[1m'

echo -e "${BLUE}🛑 Stopping Contract Manager (Monolith Mode)${NC}"
echo -e "${BLUE}=============================================${NC}"
echo ""

# Stop nginx
echo "Stopping nginx..."
if sudo nginx -s stop 2>/dev/null; then
    echo -e "${GREEN}✓ nginx stopped${NC}"
else
    echo -e "${YELLOW}⚠️  nginx was not running or could not be stopped${NC}"
fi

# Find and stop backend process
echo "Stopping backend..."
if pkill -f "go run cmd/server/main.go" 2>/dev/null; then
    echo -e "${GREEN}✓ backend stopped${NC}"
else
    echo -e "${YELLOW}⚠️  backend was not running${NC}"
fi

# Find and stop frontend process
echo "Stopping frontend..."
if pkill -f "npm run dev" 2>/dev/null; then
    echo -e "${GREEN}✓ frontend stopped${NC}"
else
    echo -e "${YELLOW}⚠️  frontend was not running${NC}"
fi

echo ""
echo -e "${GREEN}✅ All services stopped successfully!${NC}"
