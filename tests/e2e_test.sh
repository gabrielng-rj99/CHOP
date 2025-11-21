#!/bin/bash

# ============================================================================
# Entity-Hub End-to-End Test Script
# ============================================================================
# Complete workflow test: Login → Create → Read → Update → Delete
# ============================================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Configuration
BACKEND_URL="${BACKEND_URL:-http://localhost:3000}"
FRONTEND_URL="${FRONTEND_URL:-https://localhost:8443}"
ADMIN_USER="admin"
ADMIN_PASS="Admin@12345678901234567890"

# Test state
TOKEN=""
TEST_USER_ID=""
TEST_CLIENT_ID=""
TEST_CATEGORY_ID=""
TEST_CONTRACT_ID=""

TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

# ============================================================================
# Helper Functions
# ============================================================================

log_step() {
    echo ""
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}▶ $1${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

log_info() {
    echo -e "${BLUE}  ℹ  $1${NC}"
}

log_success() {
    echo -e "${GREEN}  ✓  $1${NC}"
    TESTS_PASSED=$((TESTS_PASSED + 1))
}

log_error() {
    echo -e "${RED}  ✗  $1${NC}"
    TESTS_FAILED=$((TESTS_FAILED + 1))
}

log_warning() {
    echo -e "${YELLOW}  ⚠  $1${NC}"
}

assert_status() {
    local expected=$1
    local actual=$2
    local message=$3

    TESTS_RUN=$((TESTS_RUN + 1))

    if [ "$expected" = "$actual" ]; then
        log_success "$message (Status: $actual)"
    else
        log_error "$message (Expected: $expected, Got: $actual)"
        return 1
    fi
}

assert_not_empty() {
    local value=$1
    local message=$2

    TESTS_RUN=$((TESTS_RUN + 1))

    if [ -n "$value" ]; then
        log_success "$message"
    else
        log_error "$message - Value is empty"
        return 1
    fi
}

assert_contains() {
    local haystack=$1
    local needle=$2
    local message=$3

    TESTS_RUN=$((TESTS_RUN + 1))

    if echo "$haystack" | grep -q "$needle"; then
        log_success "$message"
    else
        log_error "$message - '$needle' not found"
        return 1
    fi
}

# ============================================================================
# Test Steps
# ============================================================================

test_system_health() {
    log_step "1. System Health Checks"

    # Test backend health
    local response=$(curl -s -w "\n%{http_code}" "$BACKEND_URL/health")
    local status=$(echo "$response" | tail -n1)
    local body=$(echo "$response" | sed '$d')

    assert_status "200" "$status" "Backend health check"
    assert_contains "$body" "healthy" "Backend reports healthy status"

    # Test frontend health
    response=$(curl -k -s -w "\n%{http_code}" "$FRONTEND_URL/health")
    status=$(echo "$response" | tail -n1)

    assert_status "200" "$status" "Frontend health check"

    # Test API proxy
    response=$(curl -k -s -w "\n%{http_code}" "$FRONTEND_URL/api/initialize/status")
    status=$(echo "$response" | tail -n1)
    body=$(echo "$response" | sed '$d')

    assert_status "200" "$status" "API proxy through Nginx"
    assert_contains "$body" "is_initialized" "Initialization status endpoint"
}

test_authentication() {
    log_step "2. Authentication & Authorization"

    # Test login
    log_info "Attempting login..."
    local response=$(curl -s -X POST \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"$ADMIN_USER\",\"password\":\"$ADMIN_PASS\"}" \
        "$BACKEND_URL/api/login")

    TOKEN=$(echo "$response" | grep -o '"token":"[^"]*' | cut -d'"' -f4)
    local refresh_token=$(echo "$response" | grep -o '"refresh_token":"[^"]*' | cut -d'"' -f4)
    local username=$(echo "$response" | grep -o '"username":"[^"]*' | cut -d'"' -f4)
    local role=$(echo "$response" | grep -o '"role":"[^"]*' | cut -d'"' -f4)

    assert_not_empty "$TOKEN" "JWT token received"
    assert_not_empty "$refresh_token" "Refresh token received"
    assert_contains "$username" "admin" "Username matches"
    assert_contains "$role" "root" "Role is root"

    log_info "Token preview: ${TOKEN:0:40}..."

    # Test protected endpoint without token
    response=$(curl -s -w "\n%{http_code}" "$BACKEND_URL/api/users")
    local status=$(echo "$response" | tail -n1)

    assert_status "401" "$status" "Protected endpoint rejects requests without token"

    # Test protected endpoint with token
    response=$(curl -s -w "\n%{http_code}" \
        -H "Authorization: Bearer $TOKEN" \
        "$BACKEND_URL/api/users")
    status=$(echo "$response" | tail -n1)

    assert_status "200" "$status" "Protected endpoint accepts valid token"
}

test_user_crud() {
    log_step "3. User Management (CRUD Operations)"

    # CREATE - Create new user
    log_info "Creating test user..."
    local new_user='{
        "username": "testuser",
        "password": "Test@12345678901234567890",
        "display_name": "Test User E2E",
        "email": "e2e@test.com",
        "role": "user"
    }'

    local response=$(curl -s -w "\n%{http_code}" -X POST \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $TOKEN" \
        -d "$new_user" \
        "$BACKEND_URL/api/users")

    local status=$(echo "$response" | tail -n1)
    local body=$(echo "$response" | sed '$d')

    assert_status "201" "$status" "User created successfully"

    TEST_USER_ID=$(echo "$body" | grep -o '"id":"[^"]*' | head -1 | cut -d'"' -f4)
    assert_not_empty "$TEST_USER_ID" "User ID received"

    # READ - Get user by username
    log_info "Reading user data..."
    response=$(curl -s -w "\n%{http_code}" \
        -H "Authorization: Bearer $TOKEN" \
        "$BACKEND_URL/api/users/testuser")

    status=$(echo "$response" | tail -n1)
    body=$(echo "$response" | sed '$d')

    assert_status "200" "$status" "User retrieved successfully"
    assert_contains "$body" "testuser" "Username in response"
    assert_contains "$body" "Test User E2E" "Full name in response"

    # UPDATE - Update user
    log_info "Updating user..."
    local update_user='{
        "display_name": "Test User Updated",
        "email": "updated@test.com"
    }'

    response=$(curl -s -w "\n%{http_code}" -X PUT \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $TOKEN" \
        -d "$update_user" \
        "$BACKEND_URL/api/users/testuser")

    status=$(echo "$response" | tail -n1)
    body=$(echo "$response" | sed '$d')

    assert_status "200" "$status" "User updated successfully"
    assert_contains "$body" "Test User Updated" "Updated name in response"

    # DELETE - Delete user
    log_info "Deleting user..."
    response=$(curl -s -w "\n%{http_code}" -X DELETE \
        -H "Authorization: Bearer $TOKEN" \
        "$BACKEND_URL/api/users/testuser")

    status=$(echo "$response" | tail -n1)

    assert_status "200" "$status" "User deleted successfully"

    # Verify deletion
    response=$(curl -s -w "\n%{http_code}" \
        -H "Authorization: Bearer $TOKEN" \
        "$BACKEND_URL/api/users/testuser")

    status=$(echo "$response" | tail -n1)

    assert_status "404" "$status" "Deleted user not found"
}

test_client_crud() {
    log_step "4. Client Management (CRUD Operations)"

    # CREATE - Create new client
    log_info "Creating test client..."
    local new_client='{
        "name": "E2E Test Client",
        "cpf": "12345678901",
        "phone": "11999887766",
        "email": "client@e2etest.com",
        "address": "Test Street, 123",
        "city": "Test City",
        "state": "TS"
    }'

    local response=$(curl -s -X POST \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $TOKEN" \
        -d "$new_client" \
        "$BACKEND_URL/api/clients")

    TEST_CLIENT_ID=$(echo "$response" | grep -o '"id":[0-9]*' | head -1 | cut -d':' -f2)
    assert_not_empty "$TEST_CLIENT_ID" "Client created with ID: $TEST_CLIENT_ID"

    # READ - Get client by ID
    log_info "Reading client data..."
    response=$(curl -s -w "\n%{http_code}" \
        -H "Authorization: Bearer $TOKEN" \
        "$BACKEND_URL/api/clients/$TEST_CLIENT_ID")

    local status=$(echo "$response" | tail -n1)
    local body=$(echo "$response" | sed '$d')

    assert_status "200" "$status" "Client retrieved successfully"
    assert_contains "$body" "E2E Test Client" "Client name in response"
    assert_contains "$body" "12345678901" "CPF in response"

    # UPDATE - Update client
    log_info "Updating client..."
    local update_client='{
        "name": "E2E Test Client Updated",
        "phone": "11988776655"
    }'

    response=$(curl -s -w "\n%{http_code}" -X PUT \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $TOKEN" \
        -d "$update_client" \
        "$BACKEND_URL/api/clients/$TEST_CLIENT_ID")

    status=$(echo "$response" | tail -n1)
    body=$(echo "$response" | sed '$d')

    assert_status "200" "$status" "Client updated successfully"
    assert_contains "$body" "E2E Test Client Updated" "Updated name in response"

    # ARCHIVE - Archive client
    log_info "Archiving client..."
    response=$(curl -s -w "\n%{http_code}" -X POST \
        -H "Authorization: Bearer $TOKEN" \
        "$BACKEND_URL/api/clients/$TEST_CLIENT_ID/archive")

    status=$(echo "$response" | tail -n1)

    assert_status "200" "$status" "Client archived successfully"

    # UNARCHIVE - Unarchive client
    log_info "Unarchiving client..."
    response=$(curl -s -w "\n%{http_code}" -X POST \
        -H "Authorization: Bearer $TOKEN" \
        "$BACKEND_URL/api/clients/$TEST_CLIENT_ID/unarchive")

    status=$(echo "$response" | tail -n1)

    assert_status "200" "$status" "Client unarchived successfully"

    # DELETE - Delete client
    log_info "Deleting client..."
    response=$(curl -s -w "\n%{http_code}" -X DELETE \
        -H "Authorization: Bearer $TOKEN" \
        "$BACKEND_URL/api/clients/$TEST_CLIENT_ID")

    status=$(echo "$response" | tail -n1)

    assert_status "200" "$status" "Client deleted successfully"
}

test_category_and_lines() {
    log_step "5. Category and Lines Management"

    # CREATE - Create category
    log_info "Creating test category..."
    local new_category='{
        "name": "E2E Test Category",
        "description": "Category for E2E testing"
    }'

    local response=$(curl -s -X POST \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $TOKEN" \
        -d "$new_category" \
        "$BACKEND_URL/api/categories")

    TEST_CATEGORY_ID=$(echo "$response" | grep -o '"id":[0-9]*' | head -1 | cut -d':' -f2)
    assert_not_empty "$TEST_CATEGORY_ID" "Category created with ID: $TEST_CATEGORY_ID"

    # READ - Get all categories
    log_info "Listing categories..."
    response=$(curl -s -w "\n%{http_code}" \
        -H "Authorization: Bearer $TOKEN" \
        "$BACKEND_URL/api/categories")

    local status=$(echo "$response" | tail -n1)
    local body=$(echo "$response" | sed '$d')

    assert_status "200" "$status" "Categories listed successfully"
    assert_contains "$body" "E2E Test Category" "Created category in list"

    # CREATE - Add line to category
    log_info "Adding line to category..."
    local new_line='{
        "category_id": '$TEST_CATEGORY_ID',
        "name": "E2E Test Line",
        "description": "Line for E2E testing"
    }'

    response=$(curl -s -X POST \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $TOKEN" \
        -d "$new_line" \
        "$BACKEND_URL/api/lines")

    local line_id=$(echo "$response" | grep -o '"id":[0-9]*' | head -1 | cut -d':' -f2)
    assert_not_empty "$line_id" "Line created with ID: $line_id"

    # READ - Get lines for category
    log_info "Getting category lines..."
    response=$(curl -s -w "\n%{http_code}" \
        -H "Authorization: Bearer $TOKEN" \
        "$BACKEND_URL/api/categories/$TEST_CATEGORY_ID/lines")

    status=$(echo "$response" | tail -n1)
    body=$(echo "$response" | sed '$d')

    assert_status "200" "$status" "Category lines retrieved"
    assert_contains "$body" "E2E Test Line" "Line in category"

    # DELETE - Delete line
    log_info "Deleting line..."
    response=$(curl -s -w "\n%{http_code}" -X DELETE \
        -H "Authorization: Bearer $TOKEN" \
        "$BACKEND_URL/api/lines/$line_id")

    status=$(echo "$response" | tail -n1)

    assert_status "200" "$status" "Line deleted successfully"

    # DELETE - Delete category
    log_info "Deleting category..."
    response=$(curl -s -w "\n%{http_code}" -X DELETE \
        -H "Authorization: Bearer $TOKEN" \
        "$BACKEND_URL/api/categories/$TEST_CATEGORY_ID")

    status=$(echo "$response" | tail -n1)

    assert_status "200" "$status" "Category deleted successfully"
}

test_cors_security() {
    log_step "6. CORS and Security Headers"

    # Test CORS preflight
    log_info "Testing CORS preflight..."
    local response=$(curl -s -i -X OPTIONS \
        -H "Origin: https://ehop.home.arpa" \
        -H "Access-Control-Request-Method: POST" \
        -H "Access-Control-Request-Headers: Content-Type,Authorization" \
        "$BACKEND_URL/api/login")

    assert_contains "$response" "Access-Control-Allow-Origin" "CORS Allow-Origin header"
    assert_contains "$response" "Access-Control-Allow-Methods" "CORS Allow-Methods header"
    assert_contains "$response" "Access-Control-Allow-Headers" "CORS Allow-Headers header"

    # Test security headers (via Nginx)
    log_info "Testing security headers..."
    response=$(curl -k -s -i "$FRONTEND_URL/")

    assert_contains "$response" "X-Frame-Options" "X-Frame-Options header"
    assert_contains "$response" "X-Content-Type-Options" "X-Content-Type-Options header"
    assert_contains "$response" "X-XSS-Protection" "X-XSS-Protection header"
}

test_error_handling() {
    log_step "7. Error Handling and Edge Cases"

    # Test 404
    local response=$(curl -s -w "\n%{http_code}" "$BACKEND_URL/api/nonexistent")
    local status=$(echo "$response" | tail -n1)

    assert_status "404" "$status" "Non-existent endpoint returns 404"

    # Test invalid JSON
    response=$(curl -s -w "\n%{http_code}" -X POST \
        -H "Content-Type: application/json" \
        -d "invalid json{" \
        "$BACKEND_URL/api/login")

    status=$(echo "$response" | tail -n1)

    assert_status "400" "$status" "Invalid JSON returns 400"

    # Test invalid credentials
    response=$(curl -s -w "\n%{http_code}" -X POST \
        -H "Content-Type: application/json" \
        -d '{"username":"wrong","password":"wrong"}' \
        "$BACKEND_URL/api/login")

    status=$(echo "$response" | tail -n1)

    assert_status "401" "$status" "Invalid credentials return 401"

    # Test expired/invalid token
    response=$(curl -s -w "\n%{http_code}" \
        -H "Authorization: Bearer invalid.token.here" \
        "$BACKEND_URL/api/users")

    status=$(echo "$response" | tail -n1)

    assert_status "401" "$status" "Invalid token returns 401"
}

# ============================================================================
# Main Test Runner
# ============================================================================

main() {
    echo ""
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                                                                ║${NC}"
    echo -e "${CYAN}║           Entity-Hub End-to-End Test Suite                    ║${NC}"
    echo -e "${CYAN}║                                                                ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    log_info "Backend URL: $BACKEND_URL"
    log_info "Frontend URL: $FRONTEND_URL"
    log_info "Admin User: $ADMIN_USER"
    echo ""

    # Check if backend is accessible
    if ! curl -s -f "$BACKEND_URL/health" > /dev/null 2>&1; then
        log_error "Backend is not accessible at $BACKEND_URL"
        log_info "Please ensure the system is running:"
        log_info "  cd deploy && docker-compose up -d"
        exit 1
    fi

    # Run test suites
    test_system_health
    test_authentication
    test_user_crud
    test_client_crud
    test_category_and_lines
    test_cors_security
    test_error_handling

    # Summary
    echo ""
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                       Test Summary                             ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  ${BLUE}Total Tests:${NC}     $TESTS_RUN"
    echo -e "  ${GREEN}Passed:${NC}          $TESTS_PASSED"
    echo -e "  ${RED}Failed:${NC}          $TESTS_FAILED"
    echo ""

    if [ $TESTS_FAILED -eq 0 ]; then
        echo -e "${GREEN}╔════════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${GREEN}║                 ✓  ALL TESTS PASSED  ✓                        ║${NC}"
        echo -e "${GREEN}║                                                                ║${NC}"
        echo -e "${GREEN}║  The Entity-Hub system is fully operational! 🎉               ║${NC}"
        echo -e "${GREEN}╚════════════════════════════════════════════════════════════════╝${NC}"
        echo ""
        exit 0
    else
        echo -e "${RED}╔════════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${RED}║                 ✗  SOME TESTS FAILED  ✗                       ║${NC}"
        echo -e "${RED}╚════════════════════════════════════════════════════════════════╝${NC}"
        echo ""
        exit 1
    fi
}

# Run the test suite
main "$@"
