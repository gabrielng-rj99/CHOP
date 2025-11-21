#!/bin/bash

# ============================================================================
# Entity-Hub Quick System Check
# ============================================================================
# Fast health check for all components
# ============================================================================

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

echo ""
echo -e "${CYAN}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║              Entity-Hub Quick System Check                    ║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════════════════════════════╝${NC}"
echo ""

check_pass() {
    echo -e "${GREEN}✓${NC} $1"
}

check_fail() {
    echo -e "${RED}✗${NC} $1"
}

check_warn() {
    echo -e "${YELLOW}⚠${NC} $1"
}

check_info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

ERRORS=0

# ============================================================================
# 1. Docker Containers
# ============================================================================
echo -e "${CYAN}1. Docker Containers${NC}"

if ! command -v docker &> /dev/null; then
    check_fail "Docker not installed"
    ERRORS=$((ERRORS + 1))
else
    # Check database
    if docker ps | grep -q ehop_db; then
        check_pass "Database container running"
    else
        check_fail "Database container not running"
        ERRORS=$((ERRORS + 1))
    fi

    # Check backend
    if docker ps | grep -q ehop_server; then
        backend_status=$(docker inspect --format='{{.State.Health.Status}}' ehop_server 2>/dev/null)
        if [ "$backend_status" = "healthy" ]; then
            check_pass "Backend container healthy"
        else
            check_warn "Backend container running but not healthy"
        fi
    else
        check_fail "Backend container not running"
        ERRORS=$((ERRORS + 1))
    fi

    # Check frontend
    if docker ps | grep -q ehop_nginx; then
        frontend_status=$(docker inspect --format='{{.State.Health.Status}}' ehop_nginx 2>/dev/null)
        if [ "$frontend_status" = "healthy" ]; then
            check_pass "Frontend container healthy"
        else
            check_warn "Frontend container running but not healthy"
        fi
    else
        check_fail "Frontend container not running"
        ERRORS=$((ERRORS + 1))
    fi
fi

# ============================================================================
# 2. Database
# ============================================================================
echo ""
echo -e "${CYAN}2. Database${NC}"

if docker ps | grep -q ehop_db; then
    # Check tables
    table_count=$(docker exec ehop_db psql -U ehopuser -d ehopdb -t -c "SELECT COUNT(*) FROM pg_tables WHERE schemaname='public';" 2>/dev/null | tr -d ' ')

    if [ "$table_count" = "7" ]; then
        check_pass "All 7 tables exist"
    else
        check_fail "Expected 7 tables, found $table_count"
        ERRORS=$((ERRORS + 1))
    fi

    # Check users
    user_count=$(docker exec ehop_db psql -U ehopuser -d ehopdb -t -c "SELECT COUNT(*) FROM users;" 2>/dev/null | tr -d ' ')

    if [ "$user_count" -gt 0 ]; then
        check_pass "Database has $user_count user(s)"
    else
        check_warn "No users in database - run initialization"
    fi
else
    check_fail "Cannot check database - container not running"
    ERRORS=$((ERRORS + 1))
fi

# ============================================================================
# 3. Backend API
# ============================================================================
echo ""
echo -e "${CYAN}3. Backend API${NC}"

if curl -s -f http://localhost:3000/health > /dev/null 2>&1; then
    check_pass "Backend responding on port 3000"

    # Check initialization status
    init_status=$(curl -s http://localhost:3000/api/initialize/status 2>/dev/null)

    if echo "$init_status" | grep -q '"is_initialized":true'; then
        check_pass "System initialized"
    else
        check_warn "System not fully initialized"
    fi

    if echo "$init_status" | grep -q '"has_users":true'; then
        check_pass "Admin user exists"
    else
        check_warn "No admin user - needs initialization"
    fi
else
    check_fail "Backend not responding on port 3000"
    ERRORS=$((ERRORS + 1))
fi

# ============================================================================
# 4. Frontend
# ============================================================================
echo ""
echo -e "${CYAN}4. Frontend (Nginx)${NC}"

# Check HTTP
if curl -s -f http://localhost:8080/health > /dev/null 2>&1; then
    check_pass "HTTP port 8080 responding"
else
    check_fail "HTTP port 8080 not responding"
    ERRORS=$((ERRORS + 1))
fi

# Check HTTPS
if curl -k -s -f https://localhost:8443/health > /dev/null 2>&1; then
    check_pass "HTTPS port 8443 responding"
else
    check_fail "HTTPS port 8443 not responding"
    ERRORS=$((ERRORS + 1))
fi

# Check API proxy
if curl -k -s -f https://localhost:8443/api/initialize/status > /dev/null 2>&1; then
    check_pass "API proxy working (/api → backend)"
else
    check_fail "API proxy not working"
    ERRORS=$((ERRORS + 1))
fi

# ============================================================================
# 5. Authentication
# ============================================================================
echo ""
echo -e "${CYAN}5. Authentication${NC}"

# Try login with admin credentials
login_response=$(curl -s -X POST http://localhost:3000/api/login \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"Admin@12345678901234567890"}' 2>/dev/null)

if echo "$login_response" | grep -q '"token"'; then
    check_pass "Login working (admin credentials)"

    # Extract token and test protected endpoint
    token=$(echo "$login_response" | grep -o '"token":"[^"]*' | cut -d'"' -f4)

    if [ -n "$token" ]; then
        users_response=$(curl -s -H "Authorization: Bearer $token" http://localhost:3000/api/users 2>/dev/null)

        if echo "$users_response" | grep -q '"data"'; then
            check_pass "Protected endpoints accessible with token"
        else
            check_warn "Token received but protected endpoints failing"
        fi
    fi
else
    check_warn "Login not working - check admin password or initialization"
fi

# ============================================================================
# 6. Network Communication
# ============================================================================
echo ""
echo -e "${CYAN}6. Network Communication${NC}"

if docker ps | grep -q ehop_nginx && docker ps | grep -q ehop_server; then
    # Test if nginx can reach backend
    backend_test=$(docker exec ehop_nginx wget -O- http://backend:3000/health 2>&1)

    if echo "$backend_test" | grep -q "healthy"; then
        check_pass "Nginx → Backend communication working"
    else
        check_fail "Nginx cannot reach backend"
        ERRORS=$((ERRORS + 1))
    fi
fi

# ============================================================================
# Summary
# ============================================================================
echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"

if [ $ERRORS -eq 0 ]; then
    echo -e "${GREEN}✓ ALL CHECKS PASSED - System is operational!${NC}"
    echo ""
    echo -e "${BLUE}Access the system at:${NC}"
    echo "  • Frontend (HTTPS): https://localhost:8443"
    echo "  • Frontend (HTTP):  http://localhost:8080"
    echo "  • Backend API:      http://localhost:3000"
    echo ""
    echo -e "${BLUE}Admin Credentials:${NC}"
    echo "  • Username: admin"
    echo "  • Password: Admin@12345678901234567890"
    echo ""
    exit 0
else
    echo -e "${RED}✗ $ERRORS ERROR(S) FOUND - System needs attention${NC}"
    echo ""
    echo -e "${YELLOW}Troubleshooting:${NC}"
    echo "  1. Check container logs: docker logs <container_name>"
    echo "  2. Restart services: cd deploy && docker-compose restart"
    echo "  3. View detailed logs: docker-compose logs -f"
    echo "  4. Run full tests: bash tests/integration_tests.sh"
    echo ""
    exit 1
fi
