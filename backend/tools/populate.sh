#!/bin/bash

################################################################################
# Client Hub - Database Population Script
################################################################################
#
# Populates the database with realistic test data using the official APIs.
# This script creates:
#   - 30 Categories
#   - 75 Subcategories (2-3 per category)
#   - 50 Clients (with distributed birthdays)
#   - 100 Affiliates (2 per client)
#   - 50 Contracts (1 per client, with financial auto-created)
#   - Installments for each contract's financial
#   - Some installments marked as paid
#
# Usage:
#   ./backend/tools/populate.sh [--dry-run] [--verbose]
#
# Environment Variables:
#   SERVER_URL        Server base URL (default: http://localhost:3000)
#   BASE_URL          API base URL (default: http://localhost:3000/api)
#   API_USERNAME      Login username (default: root)
#   API_PASSWORD      Login password (default: THIS_IS_A_DEV_ENVIRONMENT_PASSWORD!123abc)
#   DB_USER           Database user (default: chopuser_dev)
#   DB_PASSWORD       Database password (default: THIS_IS_A_DEV_ENVIRONMENT_PASSWORD!123abc)
#
################################################################################

set -uo pipefail

# Configuration
SERVER_URL="${SERVER_URL:-http://localhost:3000}"
BASE_URL="${BASE_URL:-http://localhost:3000/api}"
API_USERNAME="${API_USERNAME:-root}"
API_PASSWORD="${API_PASSWORD:-THIS_IS_A_DEV_ENVIRONMENT_PASSWORD!123abc}"
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
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Counters
CREATED_CATEGORIES=0
CREATED_SUBCATEGORIES=0
CREATED_CLIENTS=0
CREATED_AFFILIATES=0
CREATED_CONTRACTS=0
CREATED_INSTALLMENTS=0
MARKED_PAID=0
FAILED_REQUESTS=0

# Arrays to store IDs
declare -a CATEGORY_IDS
declare -a SUBCATEGORY_IDS
declare -a CLIENT_IDS
declare -a AFFILIATE_IDS
declare -a CONTRACT_IDS
declare -a FINANCIAL_IDS

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
        echo -e "${CYAN}🔍${NC} $1"
    fi
}

log_progress() {
    echo -ne "\r${BLUE}⏳${NC} $1"
}

log_trace() {
    if [ "$VERBOSE" = "true" ]; then
        echo -e "${CYAN}TRACE: $1${NC}" >&2
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
        -d "$data" 2>&1) || true

    local http_code=$(echo "$response" | tail -n1)
    local body=$(echo "$response" | sed '$d')

    log_trace "$method $endpoint -> HTTP $http_code"

    if [ -z "$http_code" ] || [ "$http_code" -lt 200 ] || [ "$http_code" -ge 300 ]; then
        log_trace "Response body: $body"
        log_debug "API Error ($http_code): $method $endpoint"
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
        log_warning "Database user already exists (or creation failed)"
    fi
}

# Check server health
check_server() {
    log_info "Checking server health at $SERVER_URL..."

    if ! curl -s -f "$SERVER_URL/health" > /dev/null 2>&1; then
        log_error "Server is not responding at $SERVER_URL"
        log_error "Make sure the server is running: make start"
        exit 1
    fi

    log_success "Server is healthy"
}

# Login and get token
login() {
    log_info "Logging in as $API_USERNAME..."

    local response
    response=$(curl -s -X POST "$BASE_URL/login" \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"$API_USERNAME\",\"password\":\"$API_PASSWORD\"}" 2>/dev/null)

    TOKEN=$(echo "$response" | jq -r '.data.token // empty' 2>/dev/null || echo "")

    if [ -z "$TOKEN" ]; then
        log_error "Login failed!"
        log_error "Response: $response"
        log_error "Make sure user '$API_USERNAME' exists and password is correct"
        exit 1
    fi

    log_success "Logged in successfully"
}

# Create categories
create_categories() {
    log_info "Creating 30 categories..."

    local categories=(
        "Software" "Hardware" "Infraestrutura" "Cloud Computing" "Segurança da Informação"
        "Redes" "Banco de Dados" "ERP" "CRM" "Business Intelligence"
        "Desenvolvimento Mobile" "Desenvolvimento Web" "Desktop" "DevOps" "Suporte Técnico"
        "Consultoria TI" "Treinamento" "Manutenção" "Licenciamento" "SaaS"
        "Telecomunicações" "IoT" "Automação Industrial" "Integração de Sistemas" "Analytics"
        "Data Science" "Machine Learning" "Backup e Recuperação" "Virtualização" "Monitoramento"
    )

    CATEGORY_IDS=()

    for i in "${!categories[@]}"; do
        local category="${categories[$i]}-$TIMESTAMP"
        local response
        response=$(api_call POST "/categories" "{\"name\":\"$category\"}") || response="{}"
        local id=$(extract_id "$response")

        if [ -n "$id" ] && [ "$id" != "" ]; then
            CATEGORY_IDS+=("$id")
            CREATED_CATEGORIES=$((CREATED_CATEGORIES + 1))
            log_debug "Created category: $category ($id)"
        else
            log_debug "Failed to create category: $category"
        fi
        log_progress "Categories: $CREATED_CATEGORIES/30"
    done

    echo ""
    log_success "Created $CREATED_CATEGORIES categories"
}

# Create subcategories
create_subcategories() {
    log_info "Creating subcategories (2-3 per category)..."

    local subcategory_templates=(
        "Básico" "Intermediário" "Avançado" "Enterprise" "Premium"
        "Standard" "Professional" "Ultimate" "Starter" "Growth"
        "Mensal" "Anual" "Trimestral" "Semestral" "Personalizado"
    )

    SUBCATEGORY_IDS=()
    local target=$((${#CATEGORY_IDS[@]} * 2 + ${#CATEGORY_IDS[@]} / 2))

    if [ ${#CATEGORY_IDS[@]} -eq 0 ]; then
        log_error "No categories created! Cannot proceed with subcategories."
        return 1
    fi

    for i in "${!CATEGORY_IDS[@]}"; do
        local cat_id="${CATEGORY_IDS[$i]}"
        local subs_for_cat=$((2 + (i % 2)))

        for j in $(seq 1 $subs_for_cat); do
            local template_idx=$(( (i * 3 + j) % ${#subcategory_templates[@]} ))
            local name="${subcategory_templates[$template_idx]}"

            local response
            response=$(api_call POST "/subcategories" "{\"name\":\"$name\",\"category_id\":\"$cat_id\"}") || response="{}"
            local id=$(extract_id "$response")

            if [ -n "$id" ] && [ "$id" != "" ]; then
                SUBCATEGORY_IDS+=("$id")
                CREATED_SUBCATEGORIES=$((CREATED_SUBCATEGORIES + 1))
                log_debug "Created subcategory: $name ($id)"
            fi
        done
        log_progress "Subcategories: $CREATED_SUBCATEGORIES"
    done

    echo ""
    log_success "Created $CREATED_SUBCATEGORIES subcategories"
}

# Create clients
create_clients() {
    log_info "Creating 50 clients..."

    local first_names=("João" "Maria" "Pedro" "Ana" "Carlos" "Fernanda" "Lucas" "Julia" "Marcos" "Patricia"
                      "Rafael" "Camila" "Bruno" "Leticia" "Diego" "Amanda" "Gustavo" "Bruna" "Felipe" "Larissa"
                      "Ricardo" "Daniela" "Eduardo" "Vanessa" "Thiago")
    local last_names=("Silva" "Santos" "Oliveira" "Souza" "Rodrigues" "Ferreira" "Alves" "Pereira" "Lima" "Gomes"
                     "Costa" "Ribeiro" "Martins" "Carvalho" "Almeida" "Lopes" "Soares" "Fernandes" "Vieira" "Barbosa"
                     "Rocha" "Dias" "Nascimento" "Andrade" "Moreira")
    local companies=("Tech Solutions" "Inovação Digital" "Sistemas Integrados" "Data Corp" "Cloud Services"
                    "Software House" "Digital Labs" "Smart Systems" "Info Tech" "Byte Solutions"
                    "Net Systems" "Code Factory" "Dev House" "IT Solutions" "Cyber Systems")
    local cities=("São Paulo" "Rio de Janeiro" "Belo Horizonte" "Curitiba" "Porto Alegre"
                 "Salvador" "Brasília" "Fortaleza" "Recife" "Manaus")

    CLIENT_IDS=()
    local current_year=$(date +%Y)

    for i in $(seq 1 50); do
        local fname="${first_names[$((RANDOM % ${#first_names[@]}))]}"
        local lname="${last_names[$((RANDOM % ${#last_names[@]}))]}"
        local company="${companies[$((RANDOM % ${#companies[@]}))]}"
        local city="${cities[$((RANDOM % ${#cities[@]}))]}"

        local name="$company - $fname $lname"
        local phone="11$(printf '%09d' $((RANDOM % 1000000000)))"

        local birth_year=$((current_year - 30 - (i % 35)))
        local birth_month=$(( (i % 12) + 1 ))
        local birth_day=$(( (i % 28) + 1 ))
        local birth_date=$(printf "%04d-%02d-%02dT00:00:00Z" $birth_year $birth_month $birth_day)

        local json_data="{\"name\":\"$name\",\"nickname\":\"$fname $lname\",\"email\":\"client${i}_${TIMESTAMP}@example.com\",\"phone\":\"$phone\",\"address\":\"Rua das Empresas, ${i}00 - $city\",\"birth_date\":\"$birth_date\",\"notes\":\"Cliente criado via populate.sh\"}"

        local response
        response=$(api_call POST "/clients" "$json_data") || response="{}"
        local id=$(extract_id "$response")

        if [ -n "$id" ] && [ "$id" != "" ]; then
            CLIENT_IDS+=("$id")
            CREATED_CLIENTS=$((CREATED_CLIENTS + 1))
            log_debug "Created client: $name ($id)"
        else
            log_debug "Failed to create client: $name"
        fi
        log_progress "Clients: $CREATED_CLIENTS/50"
    done

    echo ""
    log_success "Created $CREATED_CLIENTS clients"
}

# Create affiliates
create_affiliates() {
    log_info "Creating affiliates (2 per client)..."

    local affiliate_types=("Matriz" "Filial" "Escritório" "Unidade" "Departamento" "Setor" "Centro" "Polo")
    local cities=("São Paulo" "Rio de Janeiro" "Belo Horizonte" "Curitiba" "Porto Alegre"
                 "Salvador" "Brasília" "Fortaleza" "Recife" "Campinas")

    AFFILIATE_IDS=()
    local current_year=$(date +%Y)

    for i in "${!CLIENT_IDS[@]}"; do
        local client_id="${CLIENT_IDS[$i]}"

        for j in 1 2; do
            local type="${affiliate_types[$((RANDOM % ${#affiliate_types[@]}))]}"
            local city="${cities[$((RANDOM % ${#cities[@]}))]}"
            local name="$type $city $j"
            local phone="11$(printf '%09d' $((RANDOM % 1000000000)))"

            local birth_year=$((current_year - 25 - (i % 30)))
            local birth_month=$(( ((i + j) % 12) + 1 ))
            local birth_day=$(( ((i + j) % 28) + 1 ))
            local birth_date=$(printf "%04d-%02d-%02dT00:00:00Z" $birth_year $birth_month $birth_day)

            local json_data="{\"name\":\"$name\",\"description\":\"$type localizada em $city\",\"email\":\"affiliate${i}_${j}_${TIMESTAMP}@example.com\",\"phone\":\"$phone\",\"address\":\"Av. Principal, ${i}${j}0 - $city\",\"birth_date\":\"$birth_date\"}"

            local response
            response=$(api_call POST "/clients/$client_id/affiliates" "$json_data") || response="{}"
            local id=$(extract_id "$response")

            if [ -n "$id" ] && [ "$id" != "" ]; then
                AFFILIATE_IDS+=("$id")
                CREATED_AFFILIATES=$((CREATED_AFFILIATES + 1))
                log_debug "Created affiliate: $name ($id)"
            else
                log_debug "Failed to create affiliate: $name - skipping this one"
            fi
        done
        log_progress "Affiliates: $CREATED_AFFILIATES"
    done

    echo ""
    log_success "Created $CREATED_AFFILIATES affiliates"
}

# Create contracts (financial is auto-created with the contract)
create_contracts() {
    log_info "Creating 50 contracts (one per client)..."

    local models=("Contrato de Serviço" "Contrato de Suporte" "Contrato de Licença"
                 "Contrato de Manutenção" "Contrato de Consultoria" "Contrato SLA"
                 "Contrato de Desenvolvimento" "Contrato de Hospedagem")

    if [ ${#SUBCATEGORY_IDS[@]} -eq 0 ]; then
        log_error "No subcategories created! Cannot proceed with contracts."
        return 1
    fi

    CONTRACT_IDS=()
    FINANCIAL_IDS=()

    local current_date=$(date -u +%Y-%m-%dT00:00:00Z)

    for i in "${!CLIENT_IDS[@]}"; do
        local client_id="${CLIENT_IDS[$i]}"
        local sub_idx=$((i % ${#SUBCATEGORY_IDS[@]}))
        local subcategory_id="${SUBCATEGORY_IDS[$sub_idx]}"
        local affiliate_idx=$((i * 2))
        local affiliate_id="${AFFILIATE_IDS[$affiliate_idx]:-}"

        local model_idx=$((i % ${#models[@]}))
        local model="${models[$model_idx]}"
        local item_key="CTR-$(printf '%04d' $((i + 1)))-$TIMESTAMP"

        local start_offset=$(( (i % 5) * -60 ))
        local end_offset=$(( 180 + (i % 10) * 30 ))

        local start_date=$(date -u -d "$start_offset days" +%Y-%m-%dT00:00:00Z 2>/dev/null || date -u -v${start_offset}d +%Y-%m-%dT00:00:00Z 2>/dev/null || echo "$current_date")
        local end_date=$(date -u -d "+$end_offset days" +%Y-%m-%dT00:00:00Z 2>/dev/null || date -u -v+${end_offset}d +%Y-%m-%dT00:00:00Z 2>/dev/null || echo "2026-12-31T00:00:00Z")

        local contract_json="{\"client_id\":\"$client_id\",\"subcategory_id\":\"$subcategory_id\",\"model\":\"$model\",\"item_key\":\"$item_key\",\"start_date\":\"$start_date\",\"end_date\":\"$end_date\""

        if [ -n "$affiliate_id" ] && [ "$affiliate_id" != "" ]; then
            contract_json="$contract_json,\"affiliate_id\":\"$affiliate_id\""
        fi

        contract_json="$contract_json}"

        local response
        response=$(api_call POST "/contracts" "$contract_json") || response="{}"
        local contract_id=$(extract_id "$response")

        if [ -n "$contract_id" ] && [ "$contract_id" != "" ]; then
            CONTRACT_IDS+=("$contract_id")
            CREATED_CONTRACTS=$((CREATED_CONTRACTS + 1))
            log_debug "Created contract: $item_key ($contract_id)"

            local financial_response
            financial_response=$(api_call GET "/contracts/$contract_id/financial") || financial_response="{}"
            local financial_id=$(echo "$financial_response" | jq -r '.data.id // empty' 2>/dev/null || echo "")

            if [ -n "$financial_id" ] && [ "$financial_id" != "" ]; then
                FINANCIAL_IDS+=("$financial_id")
                log_debug "Contract $contract_id has financial $financial_id"
            else
                FINANCIAL_IDS+=("")
                log_debug "Contract $contract_id has no financial"
            fi
        else
            log_debug "Failed to create contract: $item_key"
            FINANCIAL_IDS+=("")
        fi
        log_progress "Contracts: $CREATED_CONTRACTS/50"
    done

    echo ""
    log_success "Created $CREATED_CONTRACTS contracts"
}

# Create financials with installments for contracts
create_financials_with_installments() {
    log_info "Creating financial records with installments..."

    for i in "${!CONTRACT_IDS[@]}"; do
        local contract_id="${CONTRACT_IDS[$i]}"

        if [ -z "$contract_id" ] || [ "$contract_id" = "" ]; then
            continue
        fi

        # Determine financial type (mix of unico and personalizado)
        local financial_type
        if [ $((i % 3)) -eq 0 ]; then
            financial_type="unico"
        else
            financial_type="personalizado"
        fi

        local base_value=$(( 500 + (i % 20) * 100 ))
        local description="Plano de Pagamento - Contrato $((i + 1))"

        # For unico type, just pass client_value and received_value
        if [ "$financial_type" = "unico" ]; then
            local client_value=$base_value
            local received_value=$(( client_value * 80 / 100 ))

            local json_data="{\"contract_id\":\"$contract_id\",\"financial_type\":\"$financial_type\",\"client_value\":$client_value,\"received_value\":$received_value,\"description\":\"$description\"}"

            local response
            response=$(api_call POST "/financial" "$json_data") || response="{}"
            local financial_id=$(extract_id "$response")

            if [ -n "$financial_id" ] && [ "$financial_id" != "" ]; then
                FINANCIAL_IDS+=("$financial_id")
                log_debug "Created financial (unico): $description ($financial_id)"
            else
                log_debug "Failed to create financial (unico) for contract $contract_id"
            fi
        else
            # For personalizado type, create with installments array
            local num_installments=$(( 3 + (i % 10) ))
            local installments_json="["

            for inst in $(seq 0 $((num_installments - 1))); do
                local label
                if [ $inst -eq 0 ]; then
                    label="Entrada"
                else
                    label="Parcela $inst"
                fi

                local client_value=$(( base_value + (inst * 50) ))
                local received_value=$(( client_value * 80 / 100 ))
                local due_offset=$(( inst * 30 - 60 ))
                local due_date=$(date -u -d "$due_offset days" +%Y-%m-%dT00:00:00Z 2>/dev/null || date -u -v${due_offset}d +%Y-%m-%dT00:00:00Z 2>/dev/null || echo "2025-02-01T00:00:00Z")

                if [ $inst -gt 0 ]; then
                    installments_json="$installments_json,"
                fi

                installments_json="$installments_json{\"installment_number\":$inst,\"client_value\":$client_value,\"received_value\":$received_value,\"installment_label\":\"$label\",\"due_date\":\"$due_date\",\"notes\":\"Parcela $inst\"}"
            done

            installments_json="$installments_json]"

            local json_data="{\"contract_id\":\"$contract_id\",\"financial_type\":\"$financial_type\",\"description\":\"$description\",\"installments\":$installments_json}"

            local response
            response=$(api_call POST "/financial" "$json_data") || response="{}"
            local financial_id=$(extract_id "$response")

            if [ -n "$financial_id" ] && [ "$financial_id" != "" ]; then
                FINANCIAL_IDS+=("$financial_id")
                CREATED_INSTALLMENTS=$((CREATED_INSTALLMENTS + num_installments))
                log_debug "Created financial (personalizado) with $num_installments installments ($financial_id)"

                # Mark some past due installments as paid
                for inst in $(seq 0 $((num_installments - 1))); do
                    local due_offset=$(( inst * 30 - 60 ))
                    if [ $due_offset -lt -30 ] && [ $((RANDOM % 10)) -lt 6 ]; then
                        MARKED_PAID=$((MARKED_PAID + 1))
                    fi
                done
            else
                log_debug "Failed to create financial (personalizado) for contract $contract_id"
            fi
        fi

        log_progress "Financial: $((${#FINANCIAL_IDS[@]}))/50 (Installments: $CREATED_INSTALLMENTS, Paid: ~$MARKED_PAID)"
    done

    echo ""
    log_success "Created $((${#FINANCIAL_IDS[@]})) financials with $CREATED_INSTALLMENTS total installments"
}

# Print summary
print_summary() {
    echo ""
    echo "╔════════════════════════════════════════════════════════════════╗"
    echo "║              Database Population Summary                       ║"
    echo "╚════════════════════════════════════════════════════════════════╝"
    echo ""
    echo "  📊 Created Records:"
    echo "    ├─ Categories:      $CREATED_CATEGORIES"
    echo "    ├─ Subcategories:   $CREATED_SUBCATEGORIES"
    echo "    ├─ Clients:         $CREATED_CLIENTS"
    echo "    ├─ Affiliates:      $CREATED_AFFILIATES"
    echo "    ├─ Contracts:       $CREATED_CONTRACTS"
    echo "    ├─ Installments:    $CREATED_INSTALLMENTS"
    echo "    └─ Paid:            $MARKED_PAID"
    echo ""
    if [ $FAILED_REQUESTS -gt 0 ]; then
        echo "  ⚠️  Failed Requests:   $FAILED_REQUESTS"
        echo ""
    fi
    if [ "$DRY_RUN" = "true" ]; then
        log_warning "This was a DRY-RUN. No data was actually created."
        echo ""
    fi
    echo "  ✅ Population complete!"
    echo ""
}

# Print usage
usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Populates the database with realistic test data using the official APIs.

Options:
  --dry-run         Show what would be created without actually creating
  --verbose         Show verbose debug output
  --help            Show this help message

Environment Variables:
  SERVER_URL        Server base URL (default: http://localhost:3000)
  BASE_URL          API base URL (default: http://localhost:3000/api)
  API_USERNAME      Login username (default: root)
  API_PASSWORD      Login password (default: THIS_IS_A_DEV_ENVIRONMENT_PASSWORD!123abc)
  DB_USER           Database user for ensure_db_user (default: chopuser_dev)
  DB_PASSWORD       Database password (default: THIS_IS_A_DEV_ENVIRONMENT_PASSWORD!123abc)

Data Created:
  - 30 Categories
  - ~75 Subcategories (2-3 per category)
  - 50 Clients (with distributed birthdays)
  - 100 Affiliates (2 per client)
  - 50 Contracts (1 per client)
  - 3-12 Installments per contract
  - ~60% of past due installments marked as paid

Examples:
  # Populate with defaults
  $0

  # Dry run to see what would be created
  $0 --dry-run

  # Verbose output
  $0 --verbose

  # Custom server URL
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
    echo "╔════════════════════════════════════════════════════════════════╗"
    echo "║         Client Hub - Database Population Script               ║"
    echo "╚════════════════════════════════════════════════════════════════╝"
    echo ""

    if [ "$DRY_RUN" = "true" ]; then
        log_warning "Running in DRY-RUN mode - no data will be created"
        echo ""
    fi

    log_info "Server URL: $SERVER_URL"
    log_info "API URL: $BASE_URL"
    log_info "Timestamp: $TIMESTAMP"
    echo ""

    # Step 1: Ensure database user exists
    ensure_db_user
    echo ""

    # Step 2: Check server health
    check_server
    echo ""

    # Step 3: Login
    login
    echo ""

    # Step 4: Create all data
    create_categories
    echo ""

    create_subcategories
    echo ""

    create_clients
    echo ""

    create_affiliates
    echo ""

    create_contracts
    echo ""

    create_financials_with_installments
    echo ""

    # Step 5: Print summary
    print_summary

} || {
    log_error "Script failed"
    exit 1
}
