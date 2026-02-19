#!/bin/bash

################################################################################
# EHOP - Test Runner
#
# Executes all tests with proper configuration and reporting
# Usage: ./tests/run_all_tests.sh [OPTIONS]
# Options:
#   -v, --verbose     Verbose output
#   -m, --markers     Run specific marker (security, unit, integration, etc)
#   -k, --keyword     Run tests matching keyword
#   --coverage        Generate coverage report
#   --html           Generate HTML report
################################################################################

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Parse arguments
VERBOSE=""
MARKER=""
KEYWORD=""
COVERAGE=""
HTML_REPORT=""

show_help() {
    cat << EOF
EHOP Test Runner - Run all tests with proper configuration

USAGE:
    ./run_all_tests.sh [OPTIONS]

OPTIONS:
    -h, --help          Show this help message
    -v, --verbose       Verbose output (very verbose)
    -m, --markers       Run tests with specific marker (e.g., security, login_blocking)
    -k, --keyword       Run tests matching keyword (e.g., blocking, jwt)
    --coverage          Generate coverage report (HTML and terminal)
    --html              Generate HTML test report

EXAMPLES:
    ./run_all_tests.sh                          # Run all tests
    ./run_all_tests.sh -v                       # Verbose output
    ./run_all_tests.sh -m security              # Security tests only
    ./run_all_tests.sh -k blocking              # Tests matching "blocking"
    ./run_all_tests.sh --coverage               # With coverage report
    ./run_all_tests.sh -v -m security --coverage  # Combined options

EOF
}

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            show_help
            exit 0
            ;;
        -v|--verbose)
            VERBOSE="-vv"
            shift
            ;;
        -m|--markers)
            MARKER="-m $2"
            shift 2
            ;;
        -k|--keyword)
            KEYWORD="-k $2"
            shift 2
            ;;
        --coverage)
            COVERAGE="--cov=backend --cov-report=html --cov-report=term-missing"
            shift
            ;;
        --html)
            HTML_REPORT="--html=tests/report.html --self-contained-html"
            shift
            ;;
        *)
            echo "Unknown option: $1"
            echo "Run with -h or --help for usage information"
            exit 1
            ;;
    esac
done

echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║${NC}         EHOP - Comprehensive Test Suite Runner            ${BLUE}║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Check if pytest is installed
if ! command -v pytest &> /dev/null; then
    echo -e "${RED}❌ pytest not found. Installing dependencies...${NC}"
    cd "$PROJECT_ROOT"
    pip install -q -r tests/requirements.txt
fi

echo -e "${YELLOW}📋 Test Configuration:${NC}"
echo "   Project Root: $PROJECT_ROOT"
echo "   Test Directory: $SCRIPT_DIR"
echo "   Verbose: ${VERBOSE:- no}"
echo "   Marker Filter: ${MARKER:- none}"
echo "   Keyword Filter: ${KEYWORD:- none}"
echo "   Coverage: ${COVERAGE:- no}"
echo ""

# Change to project root
cd "$PROJECT_ROOT"

# Run pytest with configuration
echo -e "${BLUE}🚀 Running test suite...${NC}"
echo ""

pytest \
    -v \
    $VERBOSE \
    $MARKER \
    $KEYWORD \
    $COVERAGE \
    $HTML_REPORT \
    --tb=short \
    --strict-markers \
    --disable-warnings \
    -c "$SCRIPT_DIR/pytest.ini" \
    tests/

TEST_EXIT_CODE=$?

echo ""
echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"

if [ $TEST_EXIT_CODE -eq 0 ]; then
    echo -e "${GREEN}✅ All tests passed!${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
else
    echo -e "${RED}❌ Some tests failed (exit code: $TEST_EXIT_CODE)${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
fi

if [ -n "$COVERAGE" ]; then
    echo ""
    echo -e "${YELLOW}📊 Coverage report generated in htmlcov/index.html${NC}"
fi

if [ -n "$HTML_REPORT" ]; then
    echo -e "${YELLOW}📊 HTML report generated in tests/report.html${NC}"
fi

echo ""
exit $TEST_EXIT_CODE
