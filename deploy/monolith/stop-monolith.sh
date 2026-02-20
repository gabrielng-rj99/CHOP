#!/bin/bash

# Client Hub - Stop Monolith Services Script
# This script stops all running monolith services.

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color
BOLD='\033[1m'

echo -e "${BLUE}🛑 Stopping Client Hub (Monolith Mode)${NC}"
echo -e "${BLUE}======================================${NC}"
echo ""

# PID file location
PID_FILE="$(cd "$(dirname "$0")/../.." && pwd)/app/monolith/pids/chop-backend.bin.pid"

# Stop backend
echo "Stopping backend..."
if [ -f "$PID_FILE" ]; then
    BACKEND_PID=$(cat "$PID_FILE")
    if kill -0 "$BACKEND_PID" 2>/dev/null; then
        kill "$BACKEND_PID" 2>/dev/null || true
        sleep 2
        # Force kill if still running
        if kill -0 "$BACKEND_PID" 2>/dev/null; then
            kill -9 "$BACKEND_PID" 2>/dev/null || true
        fi
        rm -f "$PID_FILE"
        echo -e "${GREEN}✓ Backend stopped (PID: $BACKEND_PID)${NC}"
    else
        echo -e "${YELLOW}⚠️  Backend PID file exists but process not running${NC}"
        rm -f "$PID_FILE"
    fi
else
    # Fallback: try to kill by process name
    if pkill -f "chop-backend.bin" 2>/dev/null; then
        echo -e "${GREEN}✓ Backend stopped (by process name)${NC}"
    else
        echo -e "${YELLOW}⚠️  Backend was not running${NC}"
    fi
fi

# Stop nginx
echo "Stopping nginx..."
if sudo nginx -s stop 2>/dev/null; then
    echo -e "${GREEN}✓ Nginx stopped gracefully${NC}"
else
    # Force kill if graceful stop failed
    if sudo pkill -9 nginx 2>/dev/null; then
        echo -e "${GREEN}✓ Nginx killed${NC}"
    else
        echo -e "${YELLOW}⚠️  Nginx was not running${NC}"
    fi
fi

# Clean up any orphaned processes
echo "Cleaning up..."
pkill -f "go run.*main.go" 2>/dev/null || true
pkill -f "npm run dev" 2>/dev/null || true

echo ""
echo -e "${GREEN}✅ All services stopped successfully!${NC}"
echo ""
