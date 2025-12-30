#!/bin/bash

# ============================================================================
# Client-Hub Complete API Test Suite
# ============================================================================
# Tests ALL API endpoints with authentication
# ============================================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

# Configuration
BACKEND_URL="${BACKEND_URL:-http://localhost:3000}"
ADMIN_USER="admin"
ADMIN_PASS="Admin@12345678901234567890"

# Test state
TOKEN=""
TEST_CLIENT_ID=""
TEST_CATEGORY_ID=""
TEST_LINE_ID=""
TEST_CONTRACT_ID=""
TEST_USER_USERNAME=""

TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

# ============================================================================
# Helper Functions
# ============================================================================

log_section() {
    echo ""
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}▶ $1${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

log_test() {
    echo -e "${BLUE}  TEST:${NC} $1"
}

log_success() {
    echo -e "${GREEN}  ✓ PASS:${NC} $1"
    TESTS_PASSED=$((TESTS_PASSED + 1))
}

log_fail() {
    echo -e "${RED}  ✗ FAIL:${NC} $1"
    TESTS_FAILED=$((TESTS_FAILED + 1))
}

log_info() {
    echo -e "${MAGENTA}  ℹ INFO:${NC} $1"
}

test_endpoint() {
    TESTS_RUN=$((TESTS_RUN + 1))
    local method="$1"
    local endpoint="$2"
    local expected_status="$3"
    local data="$4"
    local auth_header="$5"
    local description="$6"

    log_test "$description"

    local cmd="curl -s -w '\n%{http_code}' -X $method"

    if [ -n "$auth_header" ]; then
        cmd="$cmd -H 'Authorization: Bearer $auth_header'"
    fi

    if [ -n "$data" ]; then
        cmd="$cmd -H 'Content-Type: application/json' -d '$data'"
    fi

    cmd="$cmd '$BACKEND_URL$endpoint'"

    response=$(eval $cmd 2>&1)
    status=$(echo "$response" | tail -n1)
    body=$(echo "$response" | sed '$d')

    if [ "$status" = "$expected_status" ]; then
        log_success "$description - Status: $status"
        echo "$body"
        return 0
    else
        log_fail "$description - Expected: $expected_status, Got: $status"
        log_info "Response: $body"
        return 1
    fi
}

# ============================================================================
# API TESTS
# ============================================================================

test_health_and_status() {
    log_section "1. Health & Status Endpoints"

    test_endpoint "GET" "/health" "200" "" "" "Health check"

    test_endpoint "GET" "/api/initialize/status" "200" "" "" "Initialize status"
}

test_authentication() {
    log_section "2. Authentication Endpoints"

    # Test invalid credentials
    test_endpoint "POST" "/api/login" "401" \
        '{"username":"wrong","password":"wrong"}' \
        "" \
        "Login with invalid credentials (should fail)"

    # Test valid login
    log_test "Login with valid credentials"
    TESTS_RUN=$((TESTS_RUN + 1))

    response=$(curl -s -X POST \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"$ADMIN_USER\",\"password\":\"$ADMIN_PASS\"}" \
        "$BACKEND_URL/api/login")

    TOKEN=$(echo "$response" | grep -o '"token":"[^"]*' | cut -d'"' -f4)

    if [ -n "$TOKEN" ]; then
        log_success "Login successful - Token received"
        log_info "Token: ${TOKEN:0:40}..."
    else
        log_fail "Login failed - No token"
        log_info "Response: $response"
        exit 1
    fi
}

test_users_api() {
    log_section "3. Users API"

    # List users
    test_endpoint "GET" "/api/users" "200" "" "$TOKEN" "GET /api/users - List all users"

    # Create user
    TEST_USER_USERNAME="testuser_$(date +%s)"
    local user_data="{
        \"username\": \"$TEST_USER_USERNAME\",
        \"password\": \"Test@12345678901234567890\",
        \"display_name\": \"Test User API\",
        \"email\": \"test@api.com\",
        \"role\": \"user\"
    }"

    local result=$(test_endpoint "POST" "/api/users" "201" "$user_data" "$TOKEN" "POST /api/users - Create user")

    # Get specific user
    test_endpoint "GET" "/api/users/$TEST_USER_USERNAME" "200" "" "$TOKEN" "GET /api/users/{username} - Get user details"

    # Update user
    local update_data="{
        \"display_name\": \"Test User Updated\",
        \"email\": \"updated@api.com\"
    }"
    test_endpoint "PUT" "/api/users/$TEST_USER_USERNAME" "200" "$update_data" "$TOKEN" "PUT /api/users/{username} - Update user"

    # Block user
    test_endpoint "PUT" "/api/users/$TEST_USER_USERNAME/block" "200" "" "$TOKEN" "PUT /api/users/{username}/block - Block user"

    # Unlock user
    test_endpoint "PUT" "/api/users/$TEST_USER_USERNAME/unlock" "200" "" "$TOKEN" "PUT /api/users/{username}/unlock - Unlock user"

    # Delete user
    test_endpoint "DELETE" "/api/users/$TEST_USER_USERNAME" "200" "" "$TOKEN" "DELETE /api/users/{username} - Delete user"
}

test_clients_api() {
    log_section "4. Clients API"

    # List clients
    test_endpoint "GET" "/api/clients" "200" "" "$TOKEN" "GET /api/clients - List all clients"

    test_endpoint "GET" "/api/clients?include_stats=true" "200" "" "$TOKEN" "GET /api/clients?include_stats=true - List with stats"

    # Create client
    local client_data='{
        "name": "API Test Client",
        "cpf": "12345678901",
        "phone": "11999999999",
        "email": "client@test.com",
        "address": "Test St, 123",
        "city": "Test City",
        "state": "TS",
        "zip_code": "12345-678"
    }'

    log_test "POST /api/clients - Create client"
    TESTS_RUN=$((TESTS_RUN + 1))

    response=$(curl -s -X POST \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $TOKEN" \
        -d "$client_data" \
        "$BACKEND_URL/api/clients")

    TEST_CLIENT_ID=$(echo "$response" | grep -o '"id":[0-9]*' | head -1 | cut -d':' -f2)

    if [ -n "$TEST_CLIENT_ID" ]; then
        log_success "Client created - ID: $TEST_CLIENT_ID"
    else
        log_fail "Failed to create client"
        log_info "Response: $response"
    fi

    # Get client
    test_endpoint "GET" "/api/clients/$TEST_CLIENT_ID" "200" "" "$TOKEN" "GET /api/clients/{id} - Get client details"

    # Update client
    local update_data='{
        "name": "API Test Client Updated",
        "phone": "11988888888"
    }'
    test_endpoint "PUT" "/api/clients/$TEST_CLIENT_ID" "200" "$update_data" "$TOKEN" "PUT /api/clients/{id} - Update client"

    # Archive client
    test_endpoint "POST" "/api/clients/$TEST_CLIENT_ID/archive" "200" "" "$TOKEN" "POST /api/clients/{id}/archive - Archive client"

    # Unarchive client
    test_endpoint "POST" "/api/clients/$TEST_CLIENT_ID/unarchive" "200" "" "$TOKEN" "POST /api/clients/{id}/unarchive - Unarchive client"

    # Get client affiliates
    test_endpoint "GET" "/api/clients/$TEST_CLIENT_ID/affiliates" "200" "" "$TOKEN" "GET /api/clients/{id}/affiliates - List affiliates"

    # Create affiliate
    local affiliate_data='{
        "name": "Test Affiliate",
        "cpf": "98765432100",
        "relationship": "Filho"
    }'

    log_test "POST /api/clients/{id}/affiliates - Create affiliate"
    TESTS_RUN=$((TESTS_RUN + 1))

    response=$(curl -s -X POST \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $TOKEN" \
        -d "$affiliate_data" \
        "$BACKEND_URL/api/clients/$TEST_CLIENT_ID/affiliates")

    affiliate_id=$(echo "$response" | grep -o '"id":[0-9]*' | head -1 | cut -d':' -f2)

    if [ -n "$affiliate_id" ]; then
        log_success "Affiliate created - ID: $affiliate_id"

        # Update affiliate
        local update_dep='{
            "name": "Test Affiliate Updated"
        }'
        test_endpoint "PUT" "/api/affiliates/$affiliate_id" "200" "$update_dep" "$TOKEN" "PUT /api/affiliates/{id} - Update affiliate"

        # Delete affiliate
        test_endpoint "DELETE" "/api/affiliates/$affiliate_id" "200" "" "$TOKEN" "DELETE /api/affiliates/{id} - Delete affiliate"
    else
        log_fail "Failed to create affiliate"
    fi

    # Delete client (cleanup)
    test_endpoint "DELETE" "/api/clients/$TEST_CLIENT_ID" "200" "" "$TOKEN" "DELETE /api/clients/{id} - Delete client"
}

test_categories_api() {
    log_section "5. Categories API"

    # List categories
    test_endpoint "GET" "/api/categories" "200" "" "$TOKEN" "GET /api/categories - List all categories"

    test_endpoint "GET" "/api/categories?include_archived=true" "200" "" "$TOKEN" "GET /api/categories?include_archived=true"

    # Create category
    local category_data='{
        "name": "API Test Category",
        "description": "Test category from API"
    }'

    log_test "POST /api/categories - Create category"
    TESTS_RUN=$((TESTS_RUN + 1))

    response=$(curl -s -X POST \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $TOKEN" \
        -d "$category_data" \
        "$BACKEND_URL/api/categories")

    TEST_CATEGORY_ID=$(echo "$response" | grep -o '"id":[0-9]*' | head -1 | cut -d':' -f2)

    if [ -n "$TEST_CATEGORY_ID" ]; then
        log_success "Category created - ID: $TEST_CATEGORY_ID"
    else
        log_fail "Failed to create category"
        log_info "Response: $response"
    fi

    # Get category
    test_endpoint "GET" "/api/categories/$TEST_CATEGORY_ID" "200" "" "$TOKEN" "GET /api/categories/{id} - Get category details"

    # Update category
    local update_data='{
        "name": "API Test Category Updated",
        "description": "Updated description"
    }'
    test_endpoint "PUT" "/api/categories/$TEST_CATEGORY_ID" "200" "$update_data" "$TOKEN" "PUT /api/categories/{id} - Update category"

    # Get category lines
    test_endpoint "GET" "/api/categories/$TEST_CATEGORY_ID/lines" "200" "" "$TOKEN" "GET /api/categories/{id}/lines - List lines"

    # Delete category (cleanup)
    test_endpoint "DELETE" "/api/categories/$TEST_CATEGORY_ID" "200" "" "$TOKEN" "DELETE /api/categories/{id} - Delete category"
}

test_lines_api() {
    log_section "6. Lines API"

    # Create category first
    local category_data='{"name":"Line Test Category","description":"For line testing"}'
    response=$(curl -s -X POST \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $TOKEN" \
        -d "$category_data" \
        "$BACKEND_URL/api/categories")

    local cat_id=$(echo "$response" | grep -o '"id":[0-9]*' | head -1 | cut -d':' -f2)

    if [ -n "$cat_id" ]; then
        log_info "Test category created: $cat_id"

        # List lines
        test_endpoint "GET" "/api/lines" "200" "" "$TOKEN" "GET /api/lines - List all lines"

        # Create line
        local line_data="{
            \"category_id\": $cat_id,
            \"name\": \"API Test Line\",
            \"description\": \"Test line from API\"
        }"

        log_test "POST /api/lines - Create line"
        TESTS_RUN=$((TESTS_RUN + 1))

        response=$(curl -s -X POST \
            -H "Content-Type: application/json" \
            -H "Authorization: Bearer $TOKEN" \
            -d "$line_data" \
            "$BACKEND_URL/api/lines")

        TEST_LINE_ID=$(echo "$response" | grep -o '"id":[0-9]*' | head -1 | cut -d':' -f2)

        if [ -n "$TEST_LINE_ID" ]; then
            log_success "Line created - ID: $TEST_LINE_ID"

            # Get line
            test_endpoint "GET" "/api/lines/$TEST_LINE_ID" "200" "" "$TOKEN" "GET /api/lines/{id} - Get line details"

            # Update line
            local update_data='{
                "name": "API Test Line Updated"
            }'
            test_endpoint "PUT" "/api/lines/$TEST_LINE_ID" "200" "$update_data" "$TOKEN" "PUT /api/lines/{id} - Update line"

            # Delete line
            test_endpoint "DELETE" "/api/lines/$TEST_LINE_ID" "200" "" "$TOKEN" "DELETE /api/lines/{id} - Delete line"
        else
            log_fail "Failed to create line"
        fi

        # Cleanup category
        curl -s -X DELETE -H "Authorization: Bearer $TOKEN" "$BACKEND_URL/api/categories/$cat_id" > /dev/null
    else
        log_fail "Failed to create test category for lines"
    fi
}

test_contracts_api() {
    log_section "7. Contracts API"

    # Create client first
    local client_data='{"name":"Contract Test Client","cpf":"11111111111","phone":"11999999999"}'
    response=$(curl -s -X POST \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $TOKEN" \
        -d "$client_data" \
        "$BACKEND_URL/api/clients")

    local client_id=$(echo "$response" | grep -o '"id":[0-9]*' | head -1 | cut -d':' -f2)

    if [ -n "$client_id" ]; then
        log_info "Test client created: $client_id"

        # List contracts
        test_endpoint "GET" "/api/contracts" "200" "" "$TOKEN" "GET /api/contracts - List all contracts"

        # Create contract
        local contract_data="{
            \"client_id\": $client_id,
            \"number\": \"API-$(date +%s)\",
            \"description\": \"API Test Contract\",
            \"value\": 1000.00,
            \"start_date\": \"2025-01-01\",
            \"end_date\": \"2025-12-31\"
        }"

        log_test "POST /api/contracts - Create contract"
        TESTS_RUN=$((TESTS_RUN + 1))

        response=$(curl -s -X POST \
            -H "Content-Type: application/json" \
            -H "Authorization: Bearer $TOKEN" \
            -d "$contract_data" \
            "$BACKEND_URL/api/contracts")

        TEST_CONTRACT_ID=$(echo "$response" | grep -o '"id":[0-9]*' | head -1 | cut -d':' -f2)

        if [ -n "$TEST_CONTRACT_ID" ]; then
            log_success "Contract created - ID: $TEST_CONTRACT_ID"

            # Get contract
            test_endpoint "GET" "/api/contracts/$TEST_CONTRACT_ID" "200" "" "$TOKEN" "GET /api/contracts/{id} - Get contract details"

            # Update contract
            local update_data='{
                "description": "API Test Contract Updated",
                "value": 1500.00
            }'
            test_endpoint "PUT" "/api/contracts/$TEST_CONTRACT_ID" "200" "$update_data" "$TOKEN" "PUT /api/contracts/{id} - Update contract"

            # Archive contract
            test_endpoint "POST" "/api/contracts/$TEST_CONTRACT_ID/archive" "200" "" "$TOKEN" "POST /api/contracts/{id}/archive - Archive contract"

            # Unarchive contract
            test_endpoint "POST" "/api/contracts/$TEST_CONTRACT_ID/unarchive" "200" "" "$TOKEN" "POST /api/contracts/{id}/unarchive - Unarchive contract"

            # Delete contract
            test_endpoint "DELETE" "/api/contracts/$TEST_CONTRACT_ID" "200" "" "$TOKEN" "DELETE /api/contracts/{id} - Delete contract"
        else
            log_fail "Failed to create contract"
        fi

        # Cleanup client
        curl -s -X DELETE -H "Authorization: Bearer $TOKEN" "$BACKEND_URL/api/clients/$client_id" > /dev/null
    else
        log_fail "Failed to create test client for contracts"
    fi
}

test_audit_logs_api() {
    log_section "8. Audit Logs API (Root Only)"

    # List audit logs
    test_endpoint "GET" "/api/audit-logs" "200" "" "$TOKEN" "GET /api/audit-logs - List audit logs"

    test_endpoint "GET" "/api/audit-logs?limit=20" "200" "" "$TOKEN" "GET /api/audit-logs?limit=20 - List with limit"
}

test_error_cases() {
    log_section "9. Error Handling Tests"

    # 404 for non-existent endpoints
    test_endpoint "GET" "/api/nonexistent" "404" "" "" "GET /api/nonexistent - Should return 404"

    # 401 for protected endpoints without auth
    test_endpoint "GET" "/api/users" "401" "" "" "GET /api/users (no auth) - Should return 401"

    # 401 for invalid token
    test_endpoint "GET" "/api/users" "401" "" "invalid.token.here" "GET /api/users (bad token) - Should return 401"

    # 400 for invalid JSON
    log_test "POST /api/login (invalid JSON) - Should return 400"
    TESTS_RUN=$((TESTS_RUN + 1))

    response=$(curl -s -w "\n%{http_code}" -X POST \
        -H "Content-Type: application/json" \
        -d "invalid json{" \
        "$BACKEND_URL/api/login")

    status=$(echo "$response" | tail -n1)

    if [ "$status" = "400" ]; then
        log_success "Invalid JSON returns 400"
    else
        log_fail "Expected 400, got $status"
    fi
}

# ============================================================================
# Main Test Runner
# ============================================================================

main() {
    echo ""
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                                                                ║${NC}"
    echo -e "${CYAN}║        Client-Hub Complete API Test Suite                     ║${NC}"
    echo -e "${CYAN}║                                                                ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${BLUE}Backend URL:${NC} $BACKEND_URL"
    echo -e "${BLUE}Admin User:${NC} $ADMIN_USER"
    echo ""

    # Check backend
    if ! curl -s -f "$BACKEND_URL/health" > /dev/null 2>&1; then
        echo -e "${RED}ERROR: Backend not accessible at $BACKEND_URL${NC}"
        exit 1
    fi

    # Run all tests
    test_health_and_status
    test_authentication
    test_users_api
    test_clients_api
    test_categories_api
    test_lines_api
    test_contracts_api
    test_audit_logs_api
    test_error_cases

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

    success_rate=$((TESTS_PASSED * 100 / TESTS_RUN))
    echo -e "  ${BLUE}Success Rate:${NC}    $success_rate%"
    echo ""

    if [ $TESTS_FAILED -eq 0 ]; then
        echo -e "${GREEN}╔════════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${GREEN}║              ✓  ALL API TESTS PASSED  ✓                       ║${NC}"
        echo -e "${GREEN}╚════════════════════════════════════════════════════════════════╝${NC}"
        echo ""
        exit 0
    else
        echo -e "${RED}╔════════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${RED}║              ✗  SOME TESTS FAILED  ✗                          ║${NC}"
        echo -e "${RED}╚════════════════════════════════════════════════════════════════╝${NC}"
        echo ""
        exit 1
    fi
}

# Run tests
main "$@"
