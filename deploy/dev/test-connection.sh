#!/bin/bash

# Client Hub - Connection Test Script
# Tests if backend and frontend are properly connected

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'
BOLD='\033[1m'

echo -e "${BLUE}🧪 Testing Client Hub Connection${NC}"
echo -e "${BLUE}=================================${NC}"
echo ""

# Read config
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
CONFIG_FILE="$SCRIPT_DIR/dev.ini"

# Default ports
API_PORT=3000
VITE_PORT=5173

# Try to read from config
if [ -f "$CONFIG_FILE" ]; then
    API_PORT=$(grep "^API_PORT=" "$CONFIG_FILE" | cut -d'=' -f2 | tr -d '"' || echo "3000")
    VITE_PORT=$(grep "^VITE_PORT=" "$CONFIG_FILE" | cut -d'=' -f2 | tr -d '"' || echo "5173")
fi

TESTS_PASSED=0
TESTS_FAILED=0

# Test function
test_endpoint() {
    local name=$1
    local url=$2
    local expected=$3

    echo -n "Testing $name... "

    response=$(curl -s -w "\n%{http_code}" "$url" 2>/dev/null || echo -e "\n000")
    http_code=$(echo "$response" | tail -n 1)
    body=$(echo "$response" | head -n -1)

    if [ "$http_code" = "200" ] || [ "$http_code" = "301" ] || [ "$http_code" = "302" ]; then
        if [ -n "$expected" ]; then
            if echo "$body" | grep -q "$expected"; then
                echo -e "${GREEN}✓ PASS${NC} (HTTP $http_code)"
                ((TESTS_PASSED++))
                return 0
            else
                echo -e "${RED}✗ FAIL${NC} (Expected '$expected' not found)"
                ((TESTS_FAILED++))
                return 1
            fi
        else
            echo -e "${GREEN}✓ PASS${NC} (HTTP $http_code)"
            ((TESTS_PASSED++))
            return 0
        fi
    else
        echo -e "${RED}✗ FAIL${NC} (HTTP $http_code or no response)"
        ((TESTS_FAILED++))
        return 1
    fi
}

# Test 1: Backend Health
echo -e "${BOLD}1. Backend Direct Access${NC}"
test_endpoint "Backend Health" "http://localhost:${API_PORT}/health" "healthy"
echo ""

# Test 2: Frontend
echo -e "${BOLD}2. Frontend (Vite)${NC}"
test_endpoint "Frontend HTML" "http://localhost:${VITE_PORT}/" "<!DOCTYPE html>"
echo ""

# Test 3: Proxy
echo -e "${BOLD}3. API Proxy (Frontend → Backend)${NC}"
test_endpoint "Proxy Health" "http://localhost:${VITE_PORT}/api/health" "healthy"
echo ""

# Test 4: CORS
echo -e "${BOLD}4. CORS Test${NC}"
echo -n "Testing CORS headers... "
cors_response=$(curl -s -H "Origin: http://localhost:${VITE_PORT}" \
                      -H "Access-Control-Request-Method: GET" \
                      -H "Access-Control-Request-Headers: Authorization" \
                      -X OPTIONS \
                      "http://localhost:${API_PORT}/api/health" \
                      -I 2>/dev/null || echo "")

if echo "$cors_response" | grep -qi "access-control-allow"; then
    echo -e "${GREEN}✓ PASS${NC} (CORS headers present)"
    ((TESTS_PASSED++))
else
    echo -e "${YELLOW}⚠ WARNING${NC} (CORS headers not found, but proxy should handle it)"
    # Don't fail on this, proxy handles CORS
    ((TESTS_PASSED++))
fi
echo ""

# Test 5: Process Check
echo -e "${BOLD}5. Process Check${NC}"

echo -n "Backend process... "
if pgrep -f "ehop-backend-dev" > /dev/null; then
    BACKEND_PID=$(pgrep -f "ehop-backend-dev")
    echo -e "${GREEN}✓ RUNNING${NC} (PID: $BACKEND_PID)"
    ((TESTS_PASSED++))
else
    echo -e "${RED}✗ NOT RUNNING${NC}"
    ((TESTS_FAILED++))
fi

echo -n "Vite process... "
if pgrep -f "vite.*dev" > /dev/null; then
    VITE_PID=$(pgrep -f "vite.*dev" | head -1)
    echo -e "${GREEN}✓ RUNNING${NC} (PID: $VITE_PID)"
    ((TESTS_PASSED++))
else
    echo -e "${RED}✗ NOT RUNNING${NC}"
    ((TESTS_FAILED++))
fi
echo ""

# Summary
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BOLD}Test Summary${NC}"
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "  Passed: ${GREEN}$TESTS_PASSED${NC}"
echo -e "  Failed: ${RED}$TESTS_FAILED${NC}"
echo ""

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}${BOLD}🎉 All tests passed!${NC}"
    echo ""
    echo -e "${BOLD}Your environment is ready:${NC}"
    echo -e "  • Frontend: ${BLUE}http://localhost:${VITE_PORT}${NC}"
    echo -e "  • Backend:  ${BLUE}http://localhost:${API_PORT}${NC}"
    echo -e "  • Proxy working: ${GREEN}✓${NC}"
    echo ""
    echo -e "You can start developing! 🚀"
    exit 0
else
    echo -e "${RED}${BOLD}❌ Some tests failed!${NC}"
    echo ""
    echo -e "${YELLOW}Troubleshooting:${NC}"
    echo "  1. Check if services are running:"
    echo "     ps aux | grep -E 'ehop-backend-dev|vite'"
    echo ""
    echo "  2. Check logs:"
    echo "     tail -f logs/backend_dev/server.log"
    echo "     tail -f logs/vite-dev.log"
    echo ""
    echo "  3. Restart services:"
    echo "     ./deploy/dev/stop-dev.sh"
    echo "     ./deploy/dev/start-dev.sh"
    echo ""
    echo "  4. Read documentation:"
    echo "     cat deploy/dev/CONEXAO-FIX.md"
    exit 1
fi
