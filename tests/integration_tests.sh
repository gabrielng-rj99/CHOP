#!/bin/bash

# ============================================================================
# Client-Hub Integration Tests
# ============================================================================
# Comprehensive test suite for backend API endpoints
# ============================================================================

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

# Configuration
BACKEND_URL="${BACKEND_URL:-http://localhost:3000}"
ADMIN_USERNAME=""
ADMIN_PASSWORD=""
AUTH_TOKEN=""
REFRESH_TOKEN=""

# ============================================================================
# Helper Functions
# ============================================================================

log_info() {
    echo -e "${BLUE}ℹ ${NC} $1"
}

log_success() {
    echo -e "${GREEN}✓${NC} $1"
    TESTS_PASSED=$((TESTS_PASSED + 1))
}

log_error() {
    echo -e "${RED}✗${NC} $1"
    TESTS_FAILED=$((TESTS_FAILED + 1))
}

log_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

log_section() {
    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
}

test_endpoint() {
    TESTS_RUN=$((TESTS_RUN + 1))
    local name="$1"
    local method="$2"
    local endpoint="$3"
    local expected_status="$4"
    local data="$5"
    local headers="$6"

    log_info "Testing: $name"

    if [ -z "$data" ]; then
        response=$(curl -s -w "\n%{http_code}" -X "$method" \
            ${headers:+-H "$headers"} \
            "$BACKEND_URL$endpoint" 2>&1)
    else
        response=$(curl -s -w "\n%{http_code}" -X "$method" \
            -H "Content-Type: application/json" \
            ${headers:+-H "$headers"} \
            -d "$data" \
            "$BACKEND_URL$endpoint" 2>&1)
    fi

    status=$(echo "$response" | tail -n1)
    body=$(echo "$response" | sed '$d')

    if [ "$status" = "$expected_status" ]; then
        log_success "$name - Status: $status"
        echo "$body"
        return 0
    else
        log_error "$name - Expected: $expected_status, Got: $status"
        echo "Response: $body"
        return 1
    fi
}

# ============================================================================
# Test Suites
# ============================================================================

test_health_endpoint() {
    log_section "Health Check Tests"

    test_endpoint \
        "Health endpoint should return 200" \
        "GET" \
        "/health" \
        "200"
}

test_initialize_status() {
    log_section "Initialization Status Tests"

    local response=$(test_endpoint \
        "Initialize status endpoint" \
        "GET" \
        "/api/initialize/status" \
        "200")

    echo "$response" | grep -q "is_initialized" && log_success "Response contains is_initialized field"
    echo "$response" | grep -q "has_database" && log_success "Response contains has_database field"
    echo "$response" | grep -q "has_users" && log_success "Response contains has_users field"
}

test_database_connection() {
    log_section "Database Connection Tests"

    log_info "Checking if database is accessible..."

    if command -v docker &> /dev/null; then
        if docker ps | grep -q ehop_db; then
            log_success "Database container is running"

            # Test database tables
            tables=$(docker exec ehop_db psql -U ehopuser -d ehopdb -t -c "SELECT COUNT(*) FROM pg_tables WHERE schemaname='public';" 2>/dev/null | tr -d ' ')

            if [ "$tables" -ge 7 ]; then
                log_success "Database has $tables tables (expected >= 7)"
            else
                log_error "Database has $tables tables (expected >= 7)"
            fi

            # Test each expected table
            for table in users clients affiliates contracts categories lines audit_logs; do
                if docker exec ehop_db psql -U ehopuser -d ehopdb -t -c "SELECT 1 FROM pg_tables WHERE tablename='$table' LIMIT 1;" 2>/dev/null | grep -q 1; then
                    log_success "Table '$table' exists"
                else
                    log_error "Table '$table' does not exist"
                fi
            done
        else
            log_warning "Database container not running (testing without Docker?)"
        fi
    else
        log_warning "Docker not available - skipping database container checks"
    fi
}

test_initialize_admin() {
    log_section "Admin User Initialization Tests"

    # Check if database is empty (admin can only be created on empty database)
    local status=$(curl -s "$BACKEND_URL/api/initialize/status")
    local db_empty=$(echo "$status" | grep -o '"database_empty":[^,}]*' | cut -d':' -f2 | tr -d ' ')

    if [ "$db_empty" = "false" ]; then
        log_success "Database has data - admin already exists"
        ADMIN_USERNAME="admin"
        ADMIN_PASSWORD="Admin@123456"
    else
        log_info "Creating admin user..."

        ADMIN_USERNAME="admin"
        ADMIN_PASSWORD="Admin@12345678901234567890"

        local admin_config="{
            \"username\": \"$ADMIN_USERNAME\",
            \"password\": \"$ADMIN_PASSWORD\",
            \"display_name\": \"System Administrator\",
            \"email\": \"admin@clienthub.local\"
        }"

        local response=$(test_endpoint \
            "Create admin user" \
            "POST" \
            "/api/initialize/admin" \
            "200" \
            "$admin_config")

        if echo "$response" | grep -q "success"; then
            log_success "Admin user created successfully"
        else
            log_error "Failed to create admin user"
        fi
    fi
}

test_authentication() {
    log_section "Authentication Tests"

    # Test invalid credentials
    test_endpoint \
        "Login with invalid credentials should fail" \
        "POST" \
        "/api/login" \
        "401" \
        '{"username":"invalid","password":"invalid"}'

    # Test login with valid credentials
    if [ -n "$ADMIN_USERNAME" ] && [ -n "$ADMIN_PASSWORD" ]; then
        log_info "Attempting login with admin credentials..."
        local response=$(curl -s -X POST \
            -H "Content-Type: application/json" \
            -d "{\"username\":\"$ADMIN_USERNAME\",\"password\":\"$ADMIN_PASSWORD\"}" \
            "$BACKEND_URL/api/login")

        # Try to extract token from nested "data" object
        AUTH_TOKEN=$(echo "$response" | grep -o '"token":"[^"]*' | cut -d'"' -f4)
        REFRESH_TOKEN=$(echo "$response" | grep -o '"refresh_token":"[^"]*' | cut -d'"' -f4)

        if [ -n "$AUTH_TOKEN" ]; then
            log_success "Login successful - Token received"
            log_info "Token preview: ${AUTH_TOKEN:0:30}..."
            TESTS_PASSED=$((TESTS_PASSED + 1))
        else
            log_error "Login failed - No token received"
            log_info "Response: $response"
            TESTS_FAILED=$((TESTS_FAILED + 1))
        fi
        TESTS_RUN=$((TESTS_RUN + 1))
    else
        log_warning "Skipping login test - no admin credentials"
    fi

    # Test missing credentials
    # Note: Backend returns 401 for missing credentials, not 400
    test_endpoint \
        "Login without username should fail" \
        "POST" \
        "/api/login" \
        "401" \
        '{"password":"test"}'

    test_endpoint \
        "Login without password should fail" \
        "POST" \
        "/api/login" \
        "401" \
        '{"username":"test"}'
}

test_protected_endpoints_without_auth() {
    log_section "Protected Endpoints Without Authentication"

    test_endpoint \
        "GET /api/users without auth should fail" \
        "GET" \
        "/api/users" \
        "401"

    test_endpoint \
        "GET /api/clients without auth should fail" \
        "GET" \
        "/api/clients" \
        "401"

    test_endpoint \
        "GET /api/contracts without auth should fail" \
        "GET" \
        "/api/contracts" \
        "401"

    test_endpoint \
        "GET /api/categories without auth should fail" \
        "GET" \
        "/api/categories" \
        "401"
}

test_users_endpoints() {
    log_section "Users Endpoints Tests"

    if [ -z "$AUTH_TOKEN" ]; then
        log_warning "Skipping users tests - no auth token"
        return
    fi

    # List users
    test_endpoint \
        "GET /api/users with auth" \
        "GET" \
        "/api/users" \
        "200" \
        "" \
        "Authorization: Bearer $AUTH_TOKEN"

    # Create new user
    local new_user='{
        "username": "testuser",
        "password": "Test@123456",
        "full_name": "Test User",
        "email": "test@example.com",
        "role": "user"
    }'

    test_endpoint \
        "POST /api/users - Create user" \
        "POST" \
        "/api/users" \
        "201" \
        "$new_user" \
        "Authorization: Bearer $AUTH_TOKEN"

    # Get specific user
    test_endpoint \
        "GET /api/users/testuser" \
        "GET" \
        "/api/users/testuser" \
        "200" \
        "" \
        "Authorization: Bearer $AUTH_TOKEN"

    # Update user
    local update_user='{
        "full_name": "Test User Updated",
        "email": "testupdated@example.com"
    }'

    test_endpoint \
        "PUT /api/users/testuser - Update user" \
        "PUT" \
        "/api/users/testuser" \
        "200" \
        "$update_user" \
        "Authorization: Bearer $AUTH_TOKEN"
}

test_clients_endpoints() {
    log_section "Clients Endpoints Tests"

    if [ -z "$AUTH_TOKEN" ]; then
        log_warning "Skipping clients tests - no auth token"
        return
    fi

    # List clients
    test_endpoint \
        "GET /api/clients with auth" \
        "GET" \
        "/api/clients" \
        "200" \
        "" \
        "Authorization: Bearer $AUTH_TOKEN"

    # Create new client
    local new_client='{
        "name": "Test Client",
        "cpf": "12345678901",
        "phone": "11999999999",
        "email": "client@example.com",
        "address": "Test Street, 123"
    }'

    local response=$(curl -s -X POST \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $AUTH_TOKEN" \
        -d "$new_client" \
        "$BACKEND_URL/api/clients")

    local client_id=$(echo "$response" | grep -o '"id":[0-9]*' | head -1 | cut -d':' -f2)

    if [ -n "$client_id" ]; then
        log_success "POST /api/clients - Client created with ID: $client_id"
        TESTS_PASSED=$((TESTS_PASSED + 1))

        # Get specific client
        test_endpoint \
            "GET /api/clients/$client_id" \
            "GET" \
            "/api/clients/$client_id" \
            "200" \
            "" \
            "Authorization: Bearer $AUTH_TOKEN"

        # Update client
        local update_client='{
            "name": "Test Client Updated",
            "phone": "11988888888"
        }'

        test_endpoint \
            "PUT /api/clients/$client_id" \
            "PUT" \
            "/api/clients/$client_id" \
            "200" \
            "$update_client" \
            "Authorization: Bearer $AUTH_TOKEN"

        # Archive client
        test_endpoint \
            "POST /api/clients/$client_id/archive" \
            "POST" \
            "/api/clients/$client_id/archive" \
            "200" \
            "" \
            "Authorization: Bearer $AUTH_TOKEN"

        # Unarchive client
        test_endpoint \
            "POST /api/clients/$client_id/unarchive" \
            "POST" \
            "/api/clients/$client_id/unarchive" \
            "200" \
            "" \
            "Authorization: Bearer $AUTH_TOKEN"
    else
        log_error "POST /api/clients - Failed to create client"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
    TESTS_RUN=$((TESTS_RUN + 1))
}

test_categories_endpoints() {
    log_section "Categories Endpoints Tests"

    if [ -z "$AUTH_TOKEN" ]; then
        log_warning "Skipping categories tests - no auth token"
        return
    fi

    # List categories
    test_endpoint \
        "GET /api/categories" \
        "GET" \
        "/api/categories" \
        "200" \
        "" \
        "Authorization: Bearer $AUTH_TOKEN"

    # Create new category
    local new_category='{
        "name": "Test Category",
        "description": "Category for testing"
    }'

    local response=$(curl -s -X POST \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $AUTH_TOKEN" \
        -d "$new_category" \
        "$BACKEND_URL/api/categories")

    local category_id=$(echo "$response" | grep -o '"id":[0-9]*' | head -1 | cut -d':' -f2)

    if [ -n "$category_id" ]; then
        log_success "POST /api/categories - Category created with ID: $category_id"
        TESTS_PASSED=$((TESTS_PASSED + 1))

        # Get specific category
        test_endpoint \
            "GET /api/categories/$category_id" \
            "GET" \
            "/api/categories/$category_id" \
            "200" \
            "" \
            "Authorization: Bearer $AUTH_TOKEN"
    else
        log_error "POST /api/categories - Failed to create category"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
    TESTS_RUN=$((TESTS_RUN + 1))
}

test_cors_headers() {
    log_section "CORS Headers Tests"

    # Test preflight request
    local response=$(curl -s -i -X OPTIONS \
        -H "Origin: https://ehop.home.arpa" \
        -H "Access-Control-Request-Method: POST" \
        -H "Access-Control-Request-Headers: Content-Type,Authorization" \
        "$BACKEND_URL/api/login")

    if echo "$response" | grep -q "Access-Control-Allow-Origin"; then
        log_success "CORS preflight - Access-Control-Allow-Origin header present"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        log_error "CORS preflight - Access-Control-Allow-Origin header missing"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
    TESTS_RUN=$((TESTS_RUN + 1))

    if echo "$response" | grep -q "Access-Control-Allow-Methods"; then
        log_success "CORS preflight - Access-Control-Allow-Methods header present"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        log_error "CORS preflight - Access-Control-Allow-Methods header missing"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
    TESTS_RUN=$((TESTS_RUN + 1))
}

test_error_handling() {
    log_section "Error Handling Tests"

    # Test 404
    test_endpoint \
        "Non-existent endpoint should return 404" \
        "GET" \
        "/api/nonexistent" \
        "404"

    # Test invalid JSON
    test_endpoint \
        "Invalid JSON should return 400" \
        "POST" \
        "/api/login" \
        "400" \
        "invalid json"

    # Test malformed data
    test_endpoint \
        "Malformed data should return error" \
        "POST" \
        "/api/login" \
        "400" \
        '{"username":123,"password":456}'
}

# ============================================================================
# Main Test Runner
# ============================================================================

main() {
    log_section "Client-Hub Integration Tests"
    log_info "Backend URL: $BACKEND_URL"
    echo ""

    # Check if backend is accessible
    if ! curl -s -f "$BACKEND_URL/health" > /dev/null 2>&1; then
        log_error "Backend is not accessible at $BACKEND_URL"
        log_info "Make sure the backend is running:"
        log_info "  - Docker: docker ps | grep ehop_server"
        log_info "  - Local: go run backend/cmd/server/main.go"
        exit 1
    fi

    log_success "Backend is accessible"
    echo ""

    # Run test suites
    test_health_endpoint
    test_database_connection
    test_initialize_status
    test_initialize_admin
    test_authentication
    test_protected_endpoints_without_auth
    test_users_endpoints
    test_clients_endpoints
    test_categories_endpoints
    test_cors_headers
    test_error_handling

    # Summary
    log_section "Test Summary"
    echo ""
    echo -e "  Total Tests:  ${BLUE}$TESTS_RUN${NC}"
    echo -e "  Passed:       ${GREEN}$TESTS_PASSED${NC}"
    echo -e "  Failed:       ${RED}$TESTS_FAILED${NC}"
    echo ""

    if [ $TESTS_FAILED -eq 0 ]; then
        log_success "All tests passed! 🎉"
        exit 0
    else
        log_error "Some tests failed"
        exit 1
    fi
}

# Run tests
main "$@"
