#!/bin/bash

# Script para executar testes de segurança da API com stack isolada
# Gerencia: PostgreSQL (porta 65432), Backend (porta 63000), Frontend (porta 65080 se necessário)
# Usage: ./run_security_tests.sh [options]

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m' # No Color

# Configuration
TEST_DB_PORT=65432
TEST_SERVER_PORT=63000
TEST_FRONTEND_PORT=65080
TEST_DB_CONTAINER="contracts-test-db"
TEST_DB_VOLUME="contracts-test-db-volume"
TEST_NETWORK="contracts-test-network"
COMPOSE_FILE="docker-compose.test.yml"
SERVER_PID=""

# Default values
VERBOSE=false
COVERAGE=false
SPECIFIC_TEST=""
TIMEOUT="60s"
KEEP_ALIVE=false
NO_CLEANUP=false

# Cleanup function
cleanup() {
    local exit_code=$?

    if [ "$NO_CLEANUP" = true ]; then
        echo -e "${YELLOW}Skipping cleanup (--no-cleanup flag set)${NC}"
        return
    fi

    echo ""
    echo -e "${YELLOW}Cleaning up test environment...${NC}"

    # Kill server if running
    if [ -n "$SERVER_PID" ]; then
        echo -e "${YELLOW}  → Stopping test server (PID: $SERVER_PID)${NC}"
        kill $SERVER_PID 2>/dev/null || true
        wait $SERVER_PID 2>/dev/null || true
    fi

    # Stop and remove Docker containers
    if docker ps -q -f name=$TEST_DB_CONTAINER | grep -q .; then
        echo -e "${YELLOW}  → Stopping Docker container: $TEST_DB_CONTAINER${NC}"
        docker stop $TEST_DB_CONTAINER >/dev/null 2>&1 || true
    fi

    if docker ps -aq -f name=$TEST_DB_CONTAINER | grep -q .; then
        echo -e "${YELLOW}  → Removing Docker container: $TEST_DB_CONTAINER${NC}"
        docker rm $TEST_DB_CONTAINER >/dev/null 2>&1 || true
    fi

    # Remove Docker volume
    if docker volume ls -q -f name=$TEST_DB_VOLUME | grep -q .; then
        echo -e "${YELLOW}  → Removing Docker volume: $TEST_DB_VOLUME${NC}"
        docker volume rm $TEST_DB_VOLUME >/dev/null 2>&1 || true
    fi

    # Remove Docker network
    if docker network ls -q -f name=$TEST_NETWORK | grep -q .; then
        echo -e "${YELLOW}  → Removing Docker network: $TEST_NETWORK${NC}"
        docker network rm $TEST_NETWORK >/dev/null 2>&1 || true
    fi

    echo -e "${GREEN}✓ Cleanup complete${NC}"

    exit $exit_code
}

# Set trap for cleanup
trap cleanup EXIT INT TERM

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -c|--coverage)
            COVERAGE=true
            shift
            ;;
        -t|--test)
            SPECIFIC_TEST="$2"
            shift 2
            ;;
        --timeout)
            TIMEOUT="$2"
            shift 2
            ;;
        --keep-alive)
            KEEP_ALIVE=true
            NO_CLEANUP=true
            shift
            ;;
        --no-cleanup)
            NO_CLEANUP=true
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [options]"
            echo ""
            echo "Options:"
            echo "  -v, --verbose       Run tests with verbose output"
            echo "  -c, --coverage      Run tests with coverage report"
            echo "  -t, --test NAME     Run specific test (e.g., TestTokenManipulation)"
            echo "  --timeout DURATION  Set test timeout (default: 60s)"
            echo "  --keep-alive        Keep test environment running after tests"
            echo "  --no-cleanup        Don't cleanup on exit (for debugging)"
            echo "  -h, --help          Show this help message"
            echo ""
            echo "Test Environment:"
            echo "  PostgreSQL:  localhost:$TEST_DB_PORT"
            echo "  Backend API: localhost:$TEST_SERVER_PORT"
            echo "  Frontend:    localhost:$TEST_FRONTEND_PORT (if needed)"
            echo ""
            echo "Examples:"
            echo "  $0                              # Run all tests"
            echo "  $0 -v                           # Run with verbose output"
            echo "  $0 -c                           # Run with coverage"
            echo "  $0 -t TestSQLInjection          # Run specific test"
            echo "  $0 --keep-alive                 # Keep environment running"
            echo "  $0 -v -c                        # Verbose with coverage"
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            exit 1
            ;;
    esac
done

# Banner
echo -e "${BLUE}"
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║                                                                ║"
echo "║        CONTRACT MANAGER - SECURITY TESTS                       ║"
echo "║              Isolated Test Stack                               ║"
echo "║                                                                ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Check dependencies
echo -e "${CYAN}Checking dependencies...${NC}"

if ! command -v go &> /dev/null; then
    echo -e "${RED}✗ Go is not installed or not in PATH${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Go: $(go version | awk '{print $3}')${NC}"

if ! command -v docker &> /dev/null; then
    echo -e "${RED}✗ Docker is not installed or not in PATH${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Docker: $(docker --version | awk '{print $3}' | sed 's/,//')${NC}"

if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
    echo -e "${RED}✗ Docker Compose is not installed${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Docker Compose: available${NC}"

# Check if Docker daemon is running
if ! docker info >/dev/null 2>&1; then
    echo -e "${RED}✗ Docker daemon is not running${NC}"
    echo -e "${YELLOW}Please start Docker and try again${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Docker daemon: running${NC}"
echo ""

# Navigate to tests directory
cd "$(dirname "$0")"

# Step 1: Start PostgreSQL test database
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}Step 1: Starting PostgreSQL test database (port $TEST_DB_PORT)${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"

# Stop existing container if running
if docker ps -q -f name=$TEST_DB_CONTAINER | grep -q .; then
    echo -e "${YELLOW}Stopping existing test database container...${NC}"
    docker stop $TEST_DB_CONTAINER >/dev/null 2>&1 || true
fi

# Remove existing container
if docker ps -aq -f name=$TEST_DB_CONTAINER | grep -q .; then
    echo -e "${YELLOW}Removing existing test database container...${NC}"
    docker rm $TEST_DB_CONTAINER >/dev/null 2>&1 || true
fi

# Remove existing volume
if docker volume ls -q -f name=$TEST_DB_VOLUME | grep -q .; then
    echo -e "${YELLOW}Removing existing test database volume...${NC}"
    docker volume rm $TEST_DB_VOLUME >/dev/null 2>&1 || true
fi

# Start PostgreSQL with docker-compose
echo -e "${YELLOW}Starting PostgreSQL container...${NC}"
if command -v docker-compose &> /dev/null; then
    docker-compose -f $COMPOSE_FILE up -d postgres-test
else
    docker compose -f $COMPOSE_FILE up -d postgres-test
fi

# Wait for PostgreSQL to be ready
echo -e "${YELLOW}Waiting for PostgreSQL to be ready...${NC}"
MAX_WAIT=30
WAIT_COUNT=0
until docker exec $TEST_DB_CONTAINER pg_isready -U test_user -d contracts_test >/dev/null 2>&1; do
    WAIT_COUNT=$((WAIT_COUNT + 1))
    if [ $WAIT_COUNT -ge $MAX_WAIT ]; then
        echo -e "${RED}✗ PostgreSQL failed to start in time${NC}"
        exit 1
    fi
    echo -n "."
    sleep 1
done
echo ""
echo -e "${GREEN}✓ PostgreSQL is ready on port $TEST_DB_PORT${NC}"

# Verify migrations ran
echo -e "${YELLOW}Verifying database schema...${NC}"
if docker exec $TEST_DB_CONTAINER psql -U test_user -d contracts_test -c "\dt" | grep -q "users"; then
    echo -e "${GREEN}✓ Database schema initialized${NC}"
else
    echo -e "${RED}✗ Database schema not initialized${NC}"
    echo -e "${YELLOW}Attempting to run migrations manually...${NC}"

    # Run migrations manually if they didn't run
    for migration in ../migrations/*.sql; do
        if [ -f "$migration" ]; then
            echo -e "${YELLOW}  → Running $(basename $migration)${NC}"
            docker exec -i $TEST_DB_CONTAINER psql -U test_user -d contracts_test < "$migration"
        fi
    done

    # Verify again
    if docker exec $TEST_DB_CONTAINER psql -U test_user -d contracts_test -c "\dt" | grep -q "users"; then
        echo -e "${GREEN}✓ Migrations applied successfully${NC}"
    else
        echo -e "${RED}✗ Failed to initialize database schema${NC}"
        exit 1
    fi
fi
echo ""

# Step 2: Build and start test server
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}Step 2: Starting test server (port $TEST_SERVER_PORT)${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"

# Set environment variables for test server
export TEST_MODE=true
export PORT=$TEST_SERVER_PORT
export DATABASE_URL="postgres://test_user:test_password@localhost:$TEST_DB_PORT/contracts_test?sslmode=disable"

# Build server
echo -e "${YELLOW}Building test server...${NC}"
cd ../cmd/server
if go build -o ../../tests/test-server .; then
    echo -e "${GREEN}✓ Server built successfully${NC}"
else
    echo -e "${RED}✗ Failed to build server${NC}"
    exit 1
fi
cd ../../tests

# Start server in background
echo -e "${YELLOW}Starting test server on port $TEST_SERVER_PORT...${NC}"
./test-server > server.log 2>&1 &
SERVER_PID=$!

# Wait for server to be ready
echo -e "${YELLOW}Waiting for server to be ready...${NC}"
MAX_WAIT=30
WAIT_COUNT=0
until curl -s http://localhost:$TEST_SERVER_PORT/api/health >/dev/null 2>&1 || [ $WAIT_COUNT -ge $MAX_WAIT ]; do
    if ! kill -0 $SERVER_PID 2>/dev/null; then
        echo -e "${RED}✗ Server failed to start${NC}"
        echo -e "${YELLOW}Server logs:${NC}"
        cat server.log
        exit 1
    fi
    WAIT_COUNT=$((WAIT_COUNT + 1))
    echo -n "."
    sleep 1
done

if [ $WAIT_COUNT -ge $MAX_WAIT ]; then
    echo ""
    echo -e "${RED}✗ Server failed to respond in time${NC}"
    echo -e "${YELLOW}Server logs:${NC}"
    cat server.log
    exit 1
fi

echo ""
echo -e "${GREEN}✓ Test server is running (PID: $SERVER_PID)${NC}"
echo ""

# Display stack information
echo -e "${MAGENTA}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${MAGENTA}Test Stack Information:${NC}"
echo -e "${MAGENTA}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}PostgreSQL:${NC}  postgres://test_user:test_password@localhost:$TEST_DB_PORT/contracts_test"
echo -e "${CYAN}Backend API:${NC} http://localhost:$TEST_SERVER_PORT"
echo -e "${CYAN}Health Check:${NC} http://localhost:$TEST_SERVER_PORT/api/health"
echo -e "${MAGENTA}═══════════════════════════════════════════════════════════════${NC}"
echo ""

# Step 3: Run security tests
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}Step 3: Running Security Tests${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo ""

# Set environment variables for tests
export TEST_DATABASE_URL="postgres://test_user:test_password@localhost:$TEST_DB_PORT/contracts_test?sslmode=disable"
export TEST_SERVER_URL="http://localhost:$TEST_SERVER_PORT"

# Build test flags
TEST_FLAGS="-timeout=$TIMEOUT -count=1"

if [ "$VERBOSE" = true ]; then
    TEST_FLAGS="$TEST_FLAGS -v"
fi

if [ "$COVERAGE" = true ]; then
    TEST_FLAGS="$TEST_FLAGS -cover -coverprofile=coverage.out"
fi

if [ -n "$SPECIFIC_TEST" ]; then
    TEST_FLAGS="$TEST_FLAGS -run=$SPECIFIC_TEST"
fi

if [ "$VERBOSE" = true ]; then
    echo -e "${YELLOW}Test flags: $TEST_FLAGS${NC}"
    echo ""
fi

# Execute tests
TEST_RESULT=0
if go test $TEST_FLAGS 2>&1; then
    TEST_RESULT=0
else
    TEST_RESULT=$?
fi

echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"

# Generate coverage report if requested
if [ "$COVERAGE" = true ] && [ -f "coverage.out" ]; then
    echo ""
    echo -e "${YELLOW}Generating coverage report...${NC}"
    go tool cover -func=coverage.out | tail -20

    # Generate HTML coverage report
    go tool cover -html=coverage.out -o coverage.html
    echo -e "${GREEN}✓ HTML coverage report: coverage.html${NC}"

    # Calculate coverage percentage
    COVERAGE_PCT=$(go tool cover -func=coverage.out | grep total | awk '{print $3}')
    echo -e "${CYAN}Total coverage: $COVERAGE_PCT${NC}"
fi

# Display server logs if tests failed
if [ $TEST_RESULT -ne 0 ] && [ "$VERBOSE" = true ]; then
    echo ""
    echo -e "${YELLOW}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}Server Logs (last 50 lines):${NC}"
    echo -e "${YELLOW}═══════════════════════════════════════════════════════════════${NC}"
    tail -50 server.log
fi

# Summary
echo ""
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}                      TEST SUMMARY                            ${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"

if [ $TEST_RESULT -eq 0 ]; then
    echo -e "${GREEN}"
    echo "  ✓ ALL SECURITY TESTS PASSED"
    echo ""
    echo "  The API is protected against:"
    echo "    • Token manipulation attacks"
    echo "    • Privilege escalation attempts"
    echo "    • SQL injection vulnerabilities"
    echo "    • Data leakage issues"
    echo "    • Authentication bypass"
    echo "    • Password security weaknesses"
    echo "    • XSS attacks"
    echo -e "${NC}"
else
    echo -e "${RED}"
    echo "  ✗ SOME SECURITY TESTS FAILED"
    echo ""
    echo "  Please review the failures above and fix vulnerabilities"
    echo "  before deploying to production."
    echo -e "${NC}"
fi

echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo ""

# Keep alive mode
if [ "$KEEP_ALIVE" = true ]; then
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}Keep-Alive Mode Enabled${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "${GREEN}Test environment is still running!${NC}"
    echo ""
    echo -e "${YELLOW}Connection Details:${NC}"
    echo -e "  Database:  psql postgres://test_user:test_password@localhost:$TEST_DB_PORT/contracts_test"
    echo -e "  API:       curl http://localhost:$TEST_SERVER_PORT/api/health"
    echo -e "  Logs:      tail -f $(pwd)/server.log"
    echo ""
    echo -e "${YELLOW}To stop the environment:${NC}"
    echo -e "  1. Kill server: kill $SERVER_PID"
    echo -e "  2. Stop database: docker stop $TEST_DB_CONTAINER"
    echo -e "  3. Cleanup: docker rm $TEST_DB_CONTAINER && docker volume rm $TEST_DB_VOLUME"
    echo ""
    echo -e "${RED}Press Ctrl+C to cleanup and exit${NC}"

    # Wait indefinitely
    wait $SERVER_PID
fi

# Test categories summary
if [ "$VERBOSE" = true ]; then
    echo -e "${YELLOW}Test Categories:${NC}"
    echo "  • TestTokenManipulation      - JWT token security"
    echo "  • TestPrivilegeEscalation    - Permission bypasses"
    echo "  • TestSQLInjection           - Database injection attacks"
    echo "  • TestDataLeakage            - Sensitive data exposure"
    echo "  • TestAuthenticationFlows    - Login security"
    echo "  • TestPasswordSecurity       - Password handling"
    echo "  • TestXSSPrevention          - Cross-site scripting"
    echo ""
fi

exit $TEST_RESULT
