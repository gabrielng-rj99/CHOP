#!/bin/bash

# Entity Hub - Stop Development Services Script
# This script stops all running development services (backend + Vite).

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color
BOLD='\033[1m'

echo -e "${BLUE}🛑 Stopping Entity Hub (Development Mode)${NC}"
echo -e "${BLUE}==========================================${NC}"
echo ""

# Resolve Paths
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"

# PID file locations
BACKEND_PID_FILE="$PROJECT_ROOT/logs/backend_dev/backend.pid"
VITE_PID_FILE="$PROJECT_ROOT/logs/vite-dev.pid"

# Stop backend
echo "Stopping backend..."
if [ -f "$BACKEND_PID_FILE" ]; then
    BACKEND_PID=$(cat "$BACKEND_PID_FILE")
    if kill -0 "$BACKEND_PID" 2>/dev/null; then
        kill "$BACKEND_PID" 2>/dev/null || true
        sleep 2
        # Force kill if still running
        if kill -0 "$BACKEND_PID" 2>/dev/null; then
            kill -9 "$BACKEND_PID" 2>/dev/null || true
        fi
        rm -f "$BACKEND_PID_FILE"
        echo -e "${GREEN}✓ Backend stopped (PID: $BACKEND_PID)${NC}"
    else
        echo -e "${YELLOW}⚠️  Backend PID file exists but process not running${NC}"
        rm -f "$BACKEND_PID_FILE"
    fi
else
    # Fallback: try to kill by process name
    if pkill -f "ehop-backend-dev" 2>/dev/null; then
        echo -e "${GREEN}✓ Backend stopped (by process name)${NC}"
    else
        echo -e "${YELLOW}⚠️  Backend was not running${NC}"
    fi
fi

# Stop Vite dev server
echo "Stopping Vite dev server..."
if [ -f "$VITE_PID_FILE" ]; then
    VITE_PID=$(cat "$VITE_PID_FILE")
    if kill -0 "$VITE_PID" 2>/dev/null; then
        kill "$VITE_PID" 2>/dev/null || true
        sleep 2
        # Force kill if still running
        if kill -0 "$VITE_PID" 2>/dev/null; then
            kill -9 "$VITE_PID" 2>/dev/null || true
        fi
        rm -f "$VITE_PID_FILE"
        echo -e "${GREEN}✓ Vite stopped (PID: $VITE_PID)${NC}"
    else
        echo -e "${YELLOW}⚠️  Vite PID file exists but process not running${NC}"
        rm -f "$VITE_PID_FILE"
    fi
else
    # Fallback: try to kill by process name
    if pkill -f "vite.*--port" 2>/dev/null; then
        echo -e "${GREEN}✓ Vite stopped (by process name)${NC}"
    else
        echo -e "${YELLOW}⚠️  Vite was not running${NC}"
    fi
fi

# Clean up any orphaned processes
echo "Cleaning up..."
pkill -f "go run.*main.go" 2>/dev/null || true
pkill -f "npm run dev" 2>/dev/null || true

echo ""
echo -e "${GREEN}✅ All development services stopped successfully!${NC}"
echo ""
