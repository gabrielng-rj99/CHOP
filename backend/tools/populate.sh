#!/bin/bash

################################################################################
# Client Hub - Database Population Script
################################################################################
#
# Populates the database with realistic test data using the official APIs.
# This script creates:
#   - 25 Categories
#   - 60 Subcategories
#   - 165 Clients (with distributed birthdays)
#   - 165 Affiliates (with distributed birthdays)
#   - 10+ Contracts with various statuses
#   - Financial records
#
# Usage:
#   ./backend/tools/populate.sh [--dry-run] [--verbose]
#
# Environment Variables:
#   BASE_URL          API base URL (default: http://localhost:3000/api)
#   USERNAME          Login username (default: root)
#   PASSWORD          Login password (default: THIS_IS_A_DEV_ENVIRONMENT_PASSWORD!123abc)
#   TIMESTAMP         Custom timestamp (auto-generated if not set)
#
################################################################################

set -euo pipefail

# Configuration
SERVER_URL="${SERVER_URL:-http://localhost:3000}"
BASE_URL="${BASE_URL:-http://localhost:3000/api}"
USERNAME="${USERNAME:-root}"
PASSWORD="${PASSWORD:-THIS_IS_A_DEV_ENVIRONMENT_PASSWORD!123abc}"
DB_USER="${DB_USER:-chopuser_dev}"
DB_PASSWORD="${DB_PASSWORD:-THIS_IS_A_DEV_ENVIRONMENT_PASSWORD!123abc}"
TIMESTAMP=$(date +%s%N | cut -b1-10)
DRY_RUN="${DRY_RUN:-false}"
VERBOSE="${VERBOSE:-false}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Counters
CREATED_CATEGORIES=0
CREATED_SUBCATEGORIES=0
CREATED_CLIENTS=0
CREATED_AFFILIATES=0
CREATED_CONTRACTS=0
CREATED_FINANCIALS=0
FAILED_REQUESTS=0

################################################################################
# Functions
################################################################################

log_info() {
    echo -e "${BLUE}ℹ️${NC}  $1"
}

log_success() {
    echo -e "${GREEN}✅${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}⚠️${NC}  $1"
}

log_error() {
    echo -e "${RED}❌${NC} $1" >&2
}

log_debug() {
    if [ "$VERBOSE" = "true" ]; then
        echo -e "${BLUE}🔍${NC} $1"
    fi
}

# Make an API call
api_call() {
    local method=$1
    local endpoint=$2
    local data=${3:-"{}"}

    if [ "$DRY_RUN" = "true" ]; then
        log_debug "DRY-RUN: $method $endpoint"
        echo "{\"data\":{\"id\":\"dry-run-id-$RANDOM\"}}"
        return 0
    fi

    local response
    response=$(curl -s -w "\n%{http_code}" -X "$method" "$BASE_URL$endpoint" \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d "$data" 2>/dev/null || echo "")

    local http_code=$(echo "$response" | tail -n1)
    local body=$(echo "$response" | sed '$d')

    if [ -z "$http_code" ] || [ "$http_code" -lt 200 ] || [ "$http_code" -ge 300 ]; then
        log_debug "API Error ($http_code): $endpoint"
        FAILED_REQUESTS=$((FAILED_REQUESTS + 1))
        echo "{}"
        return 1
    fi

    echo "$body"
    return 0
}

# Extract ID from API response
extract_id() {
    local response=$1
    echo "$response" | jq -r '.data.id // empty' 2>/dev/null || echo ""
}

# Ensure database user exists
ensure_db_user() {
    log_info "Ensuring database user exists..."

    if sudo -u postgres psql -c "CREATE USER $DB_USER WITH PASSWORD '$DB_PASSWORD' SUPERUSER;" 2>/dev/null; then
        log_success "Database user created"
    else
        log_warning "Database user may already exist or failed to create"
    fi
}

# Check server health
check_server() {
    log_info "Checking server health..."

    if ! curl -s -f "$SERVER_URL/health" > /dev/null 2>&1; then
        log_error "Server is not responding at $SERVER_URL"
        log_error "Make sure the server is running: cd backend && go run main.go"
        exit 1
    fi

    log_success "Server is healthy"
}

# Login and get token
login() {
    log_info "Logging in as $USERNAME..."

    local response
    response=$(curl -s -X POST "$BASE_URL/login" \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"$USERNAME\",\"password\":\"$PASSWORD\"}" 2>/dev/null)

    TOKEN=$(echo "$response" | jq -r '.data.token // empty' 2>/dev/null || echo "")

    if [ -z "$TOKEN" ]; then
        log_error "Login failed!"
        log_error "Response: $response"
        exit 1
    fi

    log_success "Logged in successfully"
}

# Create categories
create_categories() {
    log_info "Creating 25 categories..."

    local categories=(
        "Software" "Hardware" "Infraestrutura" "Cloud" "Segurança"
        "Rede" "Banco de Dados" "ERP" "CRM" "Business Intelligence"
        "Mobile" "Web" "Desktop" "DevOps" "Suporte"
        "Consultoria" "Treinamento" "Manutenção" "Licenças" "SaaS"
        "Telecomunicações" "IoT" "Automação" "Integração" "Analytics"
    )

    CATEGORY_IDS=()

    for category in "${categories[@]}"; do
        local response
        response=$(api_call POST "/categories" "{\"name\":\"$category\"}")
        local id=$(extract_id "$response")

        if [ -n "$id" ]; then
            CATEGORY_IDS+=("$id")
            CREATED_CATEGORIES=$((CREATED_CATEGORIES + 1))
            echo -n "."
        else
            log_debug "Failed to create category: $category"
        fi
    done

    echo ""
    log_success "Created $CREATED_CATEGORIES categories"
}

# Create subcategories
create_subcategories() {
    log_info "Creating 60 subcategories..."

    local names=(
        "Básico" "Avançado" "Enterprise" "Premium" "Standard"
        "Lite" "Pro" "Ultimate" "Starter" "Growth"
        "Mensal" "Anual" "Trimestral" "Semestral" "Bienal"
        "Local" "Remoto" "Híbrido" "On-Premise" "Cloud Native"
        "Individual" "Equipe" "Corporativo" "Ilimitado" "Por Usuário"
        "Nacional" "Internacional" "Regional" "Global" "Multi-região"
    )

    SUBCATEGORY_IDS=()

    for i in {0..59}; do
        local cat_idx=$((i % ${#CATEGORY_IDS[@]}))
        local name_idx=$((i % ${#names[@]}))
        local name="${names[$name_idx]}"
        local suffix=$((i / ${#names[@]} + 1))

        if [ $suffix -gt 1 ]; then
            name="$name v$suffix"
        fi

        local response
        response=$(api_call POST "/subcategories" "{\"name\":\"$name\",\"category_id\":\"${CATEGORY_IDS[$cat_idx]}\"}")
        local id=$(extract_id "$response")

        if [ -n "$id" ]; then
            SUBCATEGORY_IDS+=("$id")
            CREATED_SUBCATEGORIES=$((CREATED_SUBCATEGORIES + 1))
            [ $((($i + 1) % 10)) -eq 0 ] && echo -n "."
        fi
    done

    echo ""
    log_success "Created $CREATED_SUBCATEGORIES subcategories"
}

# Create clients
create_clients() {
    log_info "Creating 165 clients with distributed birthdays..."

    local first_names=("João" "Maria" "Pedro" "Ana" "Carlos" "Fernanda" "Lucas" "Julia" "Marcos" "Patricia"
                      "Rafael" "Camila" "Bruno" "Leticia" "Diego" "Amanda" "Gustavo" "Bruna" "Felipe" "Larissa")
    local last_names=("Silva" "Santos" "Oliveira" "Souza" "Rodrigues" "Ferreira" "Alves" "Pereira" "Lima" "Gomes"
                     "Costa" "Ribeiro" "Martins" "Carvalho" "Almeida" "Lopes" "Soares" "Fernandes" "Vieira" "Barbosa")
    local cities=("São Paulo" "Rio de Janeiro" "Belo Horizonte" "Curitiba" "Porto Alegre" "Salvador" "Brasília" "Fortaleza")

    CLIENT_IDS=()

    local current_year=$(date +%Y)
    local current_month=$(date +%m)
    local current_day=$(date +%d)

    for i in {1..165}; do
        local fname="${first_names[$((RANDOM % ${#first_names[@]}))]}"
        local lname="${last_names[$((RANDOM % ${#last_names[@]}))]}"
        local name="$fname $lname $i"
        local city="${cities[$((RANDOM % ${#cities[@]}))]}"
        local phone="119$(printf '%08d' $((RANDOM % 100000000)))"

        # Distribute birthdays across the year
        local birth_year=$((current_year - 25 - (i % 40)))
        local birth_month=$(( (i * 7 / 30) % 12 + 1 ))
        local birth_day=$(( (i * 7) % 28 + 1 ))
        local birth_date=$(printf "%04d-%02d-%02dT00:00:00Z" $birth_year $birth_month $birth_day)

        local response
        response=$(api_call POST "/clients" "{\"name\":\"$name\",\"email\":\"client${i}_${TIMESTAMP}@example.com\",\"phone\":\"$phone\",\"address\":\"Rua $i, ${i}00 - $city\",\"birth_date\":\"$birth_date\"}")
        local id=$(extract_id "$response")

        if [ -n "$id" ]; then
            CLIENT_IDS+=("$id")
            CREATED_CLIENTS=$((CREATED_CLIENTS + 1))
            [ $((($i) % 20)) -eq 0 ] && echo -n "."
        fi
    done

    echo ""
    log_success "Created $CREATED_CLIENTS clients"
}

# Create affiliates
create_affiliates() {
    log_info "Creating 165 affiliates..."

    local first_names=("São" "Centro" "Unidade" "Filial" "Departamento")
    local cities=("São Paulo" "Rio de Janeiro" "Belo Horizonte" "Curitiba" "Porto Alegre" "Salvador" "Brasília" "Fortaleza")

    AFFILIATE_IDS=()

    local current_year=$(date +%Y)

    for i in {1..165}; do
        local client_idx=$((i % ${#CLIENT_IDS[@]}))
        local prefix="${first_names[$((i % ${#first_names[@]}))]}"
        local name="$prefix $(( (i % 3) + 1 ))"
        local city="${cities[$((RANDOM % ${#cities[@]}))]}"
        local phone="119$(printf '%08d' $((RANDOM % 100000000)))"

        local birth_year=$((current_year - 25 - (i % 40)))
        local birth_month=$(( (i * 7 / 30) % 12 + 1 ))
        local birth_day=$(( (i * 7) % 28 + 1 ))
        local birth_date=$(printf "%04d-%02d-%02dT00:00:00Z" $birth_year $birth_month $birth_day)

        local response
        response=$(api_call POST "/clients/${CLIENT_IDS[$client_idx]}/affiliates" "{\"name\":\"$name\",\"email\":\"affiliate${i}_${TIMESTAMP}@example.com\",\"phone\":\"$phone\",\"address\":\"Av. $i, ${i}00 - $city\",\"birth_date\":\"$birth_date\"}")
        local id=$(extract_id "$response")

        if [ -n "$id" ]; then
            AFFILIATE_IDS+=("$id")
            CREATED_AFFILIATES=$((CREATED_AFFILIATES + 1))
            [ $((($i) % 20)) -eq 0 ] && echo -n "."
        fi
    done

    echo ""
    log_success "Created $CREATED_AFFILIATES affiliates"
}

# Create contracts
create_contracts() {
    log_info "Creating 10+ contracts..."

    local current_date=$(date -u +%Y-%m-%dT00:00:00Z)

    for i in {1..10}; do
        local client_idx=$((i % ${#CLIENT_IDS[@]}))
        local sub_idx=$((i % ${#SUBCATEGORY_IDS[@]}))
        local affiliate_idx=$((i % ${#AFFILIATE_IDS[@]}))

        local start_date=$(date -u -d "+$((i)) days" +%Y-%m-%dT00:00:00Z 2>/dev/null || date -u -v+${i}d +%Y-%m-%dT00:00:00Z 2>/dev/null || echo "$current_date")
        local end_date=$(date -u -d "+$((i + 365)) days" +%Y-%m-%dT00:00:00Z 2>/dev/null || date -u -v+$((i + 365))d +%Y-%m-%dT00:00:00Z 2>/dev/null || echo "2025-12-31T00:00:00Z")

        local response
        response=$(api_call POST "/contracts" "{\"model\":\"Contract $i\",\"item_key\":\"CONTRACT-$i-$TIMESTAMP\",\"start_date\":\"$start_date\",\"end_date\":\"$end_date\",\"subcategory_id\":\"${SUBCATEGORY_IDS[$sub_idx]}\",\"client_id\":\"${CLIENT_IDS[$client_idx]}\",\"affiliate_id\":\"${AFFILIATE_IDS[$affiliate_idx]}\"}")
        local id=$(extract_id "$response")

        if [ -n "$id" ]; then
            CREATED_CONTRACTS=$((CREATED_CONTRACTS + 1))
            echo -n "."
        fi
    done

    echo ""
    log_success "Created $CREATED_CONTRACTS contracts"
}

# Print summary
print_summary() {
    echo ""
    echo "╔════════════════════════════════════════════════════════════╗"
    echo "║           Database Population Summary                      ║"
    echo "╚════════════════════════════════════════════════════════════╝"
    echo ""
    echo "  📊 Created:"
    echo "    • Categories:      $CREATED_CATEGORIES"
    echo "    • Subcategories:   $CREATED_SUBCATEGORIES"
    echo "    • Clients:         $CREATED_CLIENTS"
    echo "    • Affiliates:      $CREATED_AFFILIATES"
    echo "    • Contracts:       $CREATED_CONTRACTS"
    echo "    • Financials:      $CREATED_FINANCIALS"
    echo ""
    echo "  ⚠️  Failed Requests:   $FAILED_REQUESTS"
    echo ""
    if [ "$DRY_RUN" = "true" ]; then
        log_warning "This was a DRY-RUN. No data was actually created."
    fi
    echo ""
}

# Print usage
usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Options:
  --dry-run         Show what would be created without actually creating
  --verbose         Show verbose debug output
  --help            Show this help message

Environment Variables:
  SERVER_URL        Server base URL (default: http://localhost:3000)
  BASE_URL          API base URL (default: http://localhost:3000/api)
  USERNAME          Login username (default: root)
  PASSWORD          Login password (default: THIS_IS_A_DEV_ENVIRONMENT_PASSWORD!123abc)

Examples:
  # Populate with defaults
  $0

  # Dry run to see what would be created
  $0 --dry-run

  # Use custom server and API URLs
  SERVER_URL=http://api.example.com:3000 BASE_URL=http://api.example.com:3000/api $0

EOF
}

################################################################################
# Main Script
################################################################################

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --dry-run)
            DRY_RUN="true"
            shift
            ;;
        --verbose)
            VERBOSE="true"
            shift
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
done

# Run script
{
    echo ""
    echo "╔════════════════════════════════════════════════════════════╗"
    echo "║     Client Hub - Database Population Script                ║"
    echo "╚════════════════════════════════════════════════════════════╝"
    echo ""

    if [ "$DRY_RUN" = "true" ]; then
        log_warning "Running in DRY-RUN mode"
        echo ""
    fi

    log_info "API URL: $BASE_URL"
    log_info "Timestamp: $TIMESTAMP"
    echo ""

    ensure_db_user
    check_server
    login
    echo ""

    create_categories
    create_subcategories
    create_clients
    create_affiliates
    create_contracts

    print_summary

} || {
    log_error "Script failed"
    exit 1
}
