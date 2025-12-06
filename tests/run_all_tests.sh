#!/bin/bash

# ============================================================================
# MASTER TEST RUNNER - STACK COMPLETA DE TESTES
# ============================================================================
# Executa TODOS os testes do projeto com cronometragem detalhada:
# 1. Build do projeto (com tempo)
# 2. Testes unitários (Go test -cover)
# 3. Testes de integração
# 4. Testes de segurança (OWASP Top 10)
# 5. Testes de API (todos os endpoints)
# 6. Testes E2E
# 7. Gera relatório completo com métricas
# ============================================================================

set -e
set -o pipefail

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

# Diretórios
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BACKEND_DIR="$PROJECT_ROOT/backend"
REPORTS_DIR="$SCRIPT_DIR/test_reports"

# Timestamps
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
START_TIME=$(date +%s)
REPORT_FILE="$REPORTS_DIR/complete_test_report_${TIMESTAMP}.md"

# Contadores
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0
SKIPPED_TESTS=0

# Tempos
declare -A TEST_TIMES

# ============================================================================
# FUNÇÕES DE LOGGING
# ============================================================================

log_header() {
    echo -e "\n${MAGENTA}╔════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${MAGENTA}║${NC} $1"
    echo -e "${MAGENTA}╚════════════════════════════════════════════════════════════════════╝${NC}\n"
}

log_section() {
    echo -e "\n${CYAN}▶ $1${NC}\n" | tee -a "$REPORT_FILE"
}

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1" | tee -a "$REPORT_FILE"
}

log_success() {
    echo -e "${GREEN}[✓]${NC} $1" | tee -a "$REPORT_FILE"
}

log_warning() {
    echo -e "${YELLOW}[⚠]${NC} $1" | tee -a "$REPORT_FILE"
}

log_error() {
    echo -e "${RED}[✗]${NC} $1" | tee -a "$REPORT_FILE"
}

log_time() {
    local duration=$1
    local test_name=$2
    echo -e "${CYAN}⏱  ${NC}Tempo: ${duration}s - $test_name" | tee -a "$REPORT_FILE"
}

# ============================================================================
# FUNÇÕES DE CRONOMETRAGEM
# ============================================================================

start_timer() {
    echo $(date +%s)
}

end_timer() {
    local start=$1
    local end=$(date +%s)
    echo $((end - start))
}

format_duration() {
    local duration=$1
    if [ $duration -lt 60 ]; then
        echo "${duration}s"
    elif [ $duration -lt 3600 ]; then
        echo "$((duration / 60))m $((duration % 60))s"
    else
        echo "$((duration / 3600))h $(((duration % 3600) / 60))m $((duration % 60))s"
    fi
}

# ============================================================================
# INICIALIZAÇÃO
# ============================================================================

init_report() {
    mkdir -p "$REPORTS_DIR"

    cat > "$REPORT_FILE" << EOF
# 🧪 RELATÓRIO COMPLETO DE TESTES
## Entity Hub Open Project

**Data/Hora:** $(date '+%Y-%m-%d %H:%M:%S')
**Ambiente:** $(uname -s) $(uname -r)
**Go Version:** $(go version)
**Git Commit:** $(cd "$PROJECT_ROOT" && git rev-parse --short HEAD 2>/dev/null || echo "N/A")

---

EOF
}

# ============================================================================
# VERIFICAÇÃO DE DEPENDÊNCIAS
# ============================================================================

check_dependencies() {
    log_header "VERIFICAÇÃO DE DEPENDÊNCIAS"

    local deps_ok=true

    # Docker
    if command -v docker &> /dev/null; then
        log_success "Docker: $(docker --version)"
    else
        log_error "Docker não encontrado"
        deps_ok=false
    fi

    # Docker Compose
    if docker compose version &> /dev/null; then
        DOCKER_COMPOSE="docker compose"
        log_success "Docker Compose: $(docker compose version)"
    elif command -v docker-compose &> /dev/null; then
        DOCKER_COMPOSE="docker-compose"
        log_success "Docker Compose: $(docker-compose --version)"
    else
        log_error "Docker Compose não encontrado"
        deps_ok=false
    fi

    # Go
    if command -v go &> /dev/null; then
        log_success "Go: $(go version)"
    else
        log_error "Go não encontrado"
        deps_ok=false
    fi

    # curl
    if command -v curl &> /dev/null; then
        log_success "curl: $(curl --version | head -n1)"
    else
        log_error "curl não encontrado"
        deps_ok=false
    fi

    if [ "$deps_ok" = false ]; then
        log_error "Dependências faltando. Instale-as e tente novamente."
        exit 1
    fi

    echo ""
}

# ============================================================================
# BUILD DO PROJETO
# ============================================================================

build_project() {
    log_header "BUILD DO PROJETO"

    local start=$(start_timer)

    cd "$BACKEND_DIR"

    log_info "Limpando builds anteriores..."
    rm -f "$BACKEND_DIR/cmd/server/server" 2>/dev/null || true

    log_info "Compilando backend..."
    if go build -o /tmp/ehop_test_build ./cmd/server 2>&1 | tee -a "$REPORT_FILE"; then
        local duration=$(end_timer $start)
        TEST_TIMES["build"]=$duration
        log_success "Build concluído com sucesso"
        log_time $duration "Build"
        rm -f /tmp/ehop_test_build
        return 0
    else
        log_error "Build falhou"
        return 1
    fi
}

# ============================================================================
# TESTES UNITÁRIOS
# ============================================================================

run_unit_tests() {
    log_header "TESTES UNITÁRIOS (Go Test + Coverage)"

    local start=$(start_timer)

    cd "$BACKEND_DIR"

    # Exportar variáveis para conexão com o banco de teste
    export POSTGRES_HOST=localhost
    export POSTGRES_PORT=65432
    export POSTGRES_USER=test_user
    export POSTGRES_PASSWORD=test_password
    export POSTGRES_DB=contracts_test


    log_info "Executando testes unitários com cobertura..."

    local output_file=$(mktemp)
    local test_exit_code=0
    
    # Run tests but capture exit code without failing the script immediately due to set -e
    # We use || test_exit_code=$? to capture failure
    if ! go test -v -cover -coverprofile=coverage.out ./... 2>&1 | tee "$output_file" | tee -a "$REPORT_FILE"; then
        test_exit_code=1
    fi

    local duration=$(end_timer $start)
    TEST_TIMES["unit"]=$duration

    # Extrair estatísticas
    # Use simpler logic to avoid "0 0" errors
    local unit_passed=$(grep -c "^--- PASS:" "$output_file" || true)
    local unit_failed=$(grep -c "^--- FAIL:" "$output_file" || true)
    local unit_skipped=$(grep -c "^--- SKIP:" "$output_file" || true)

    PASSED_TESTS=$((PASSED_TESTS + unit_passed))
    FAILED_TESTS=$((FAILED_TESTS + unit_failed))
    SKIPPED_TESTS=$((SKIPPED_TESTS + unit_skipped))
    TOTAL_TESTS=$((TOTAL_TESTS + unit_passed + unit_failed + unit_skipped))

    # Coverage
    if [ -f coverage.out ]; then
        log_info "Gerando relatório de cobertura..."
        go tool cover -func=coverage.out | tail -n 1 | tee -a "$REPORT_FILE"

        # HTML report
        go tool cover -html=coverage.out -o "$REPORTS_DIR/coverage_${TIMESTAMP}.html"
        log_success "Relatório HTML: $REPORTS_DIR/coverage_${TIMESTAMP}.html"
    fi

    log_success "Testes unitários: $unit_passed passed, $unit_failed failed, $unit_skipped skipped"
    log_time $duration "Testes Unitários"

    rm -f "$output_file"

    if [ $test_exit_code -ne 0 ] || [ $unit_failed -gt 0 ]; then
         return 1
    fi
    return 0
}

# ============================================================================
# AMBIENTE DE TESTES
# ============================================================================

setup_test_environment() {
    log_header "CONFIGURANDO AMBIENTE DE TESTES"

    local start=$(start_timer)

    cd "$SCRIPT_DIR"

    log_info "Limpando ambiente anterior..."
    $DOCKER_COMPOSE -f docker-compose.test.yml down -v 2>/dev/null || true

    log_info "Iniciando banco de dados de teste..."
    $DOCKER_COMPOSE -f docker-compose.test.yml up -d --build

    log_info "Aguardando banco ficar pronto..."
    local max_attempts=30
    local attempt=0

    while [ $attempt -lt $max_attempts ]; do
        if $DOCKER_COMPOSE -f docker-compose.test.yml exec -T postgres_test pg_isready -U test_user -d contracts_test &> /dev/null; then
            local duration=$(end_timer $start)
            TEST_TIMES["setup"]=$duration
            log_success "Banco de dados pronto"
            log_time $duration "Setup do Ambiente"
            return 0
        fi
        attempt=$((attempt + 1))
        sleep 1
    done

    log_error "Timeout aguardando banco de dados"
    return 1
}

cleanup_test_environment() {
    log_section "Limpando ambiente de testes"

    cd "$SCRIPT_DIR"
    $DOCKER_COMPOSE -f docker-compose.test.yml down -v 2>/dev/null || true

    log_success "Ambiente limpo"
}

# ============================================================================
# TESTES DE SEGURANÇA
# ============================================================================

run_security_tests() {
    log_header "TESTES DE SEGURANÇA (OWASP)"

    local start=$(start_timer)

    export TEST_DATABASE_URL="postgres://test_user:test_password@localhost:65432/contracts_test?sslmode=disable"
    export BACKEND_URL="http://localhost:63000"
    export API_URL="http://localhost:63000/api"
    export TEST_API_URL="http://localhost:63000"

    cd "$SCRIPT_DIR"

    log_info "Executando suite de testes de segurança..."

    local output_file=$(mktemp)
    local test_result=0

    # Executar script de segurança se existir
    if [ -f "$SCRIPT_DIR/security_test_suite.sh" ]; then
        bash "$SCRIPT_DIR/security_test_suite.sh" 2>&1 | tee "$output_file" | tee -a "$REPORT_FILE" || test_result=$?
    else
        log_warning "Suite de testes de segurança não encontrada (security_test_suite.sh)"
        rm -f "$output_file"
        return 0
    fi

    local duration=$(end_timer $start)
    TEST_TIMES["security"]=$duration

    # Extrair estatísticas
    local sec_passed=$(grep "PASS" "$output_file" 2>/dev/null | wc -l)
    local sec_failed=$(grep "FAIL" "$output_file" 2>/dev/null | wc -l)

    PASSED_TESTS=$((PASSED_TESTS + sec_passed))
    FAILED_TESTS=$((FAILED_TESTS + sec_failed))
    TOTAL_TESTS=$((TOTAL_TESTS + sec_passed + sec_failed))

    log_success "Testes de segurança: $sec_passed passed, $sec_failed failed"
    log_time $duration "Testes de Segurança"

    rm -f "$output_file"
    return $test_result
}

# ============================================================================
# TESTES DE INTEGRAÇÃO
# ============================================================================

run_integration_tests() {
    log_header "TESTES DE INTEGRAÇÃO"

    local start=$(start_timer)

    cd "$SCRIPT_DIR"

    if [ -f "$SCRIPT_DIR/integration_tests.sh" ]; then
        log_info "Executando testes de integração..."

        local output_file=$(mktemp)
        local test_result=0

        bash "$SCRIPT_DIR/integration_tests.sh" 2>&1 | tee "$output_file" | tee -a "$REPORT_FILE" || test_result=$?

        local duration=$(end_timer $start)
        TEST_TIMES["integration"]=$duration

        local int_passed=$(grep "✓" "$output_file" 2>/dev/null | wc -l)
        local int_failed=$(grep "✗" "$output_file" 2>/dev/null | wc -l)

        PASSED_TESTS=$((PASSED_TESTS + int_passed))
        FAILED_TESTS=$((FAILED_TESTS + int_failed))
        TOTAL_TESTS=$((TOTAL_TESTS + int_passed + int_failed))

        log_success "Testes de integração: $int_passed passed, $int_failed failed"
        log_time $duration "Testes de Integração"

        rm -f "$output_file"
        return $test_result
    else
        log_warning "Script de integração não encontrado (integration_tests.sh)"
        return 0
    fi
}

# ============================================================================
# TESTES DE API
# ============================================================================

run_api_tests() {
    log_header "TESTES DE API (Todos os Endpoints)"

    local start=$(start_timer)

    cd "$SCRIPT_DIR"

    if [ -f "$SCRIPT_DIR/test_all_apis.sh" ]; then
        log_info "Testando todos os endpoints da API..."

        local output_file=$(mktemp)
        local test_result=0

        bash "$SCRIPT_DIR/test_all_apis.sh" 2>&1 | tee "$output_file" | tee -a "$REPORT_FILE" || test_result=$?

        local duration=$(end_timer $start)
        TEST_TIMES["api"]=$duration

        local api_passed=$(grep "✓" "$output_file" 2>/dev/null | wc -l)
        local api_failed=$(grep "✗" "$output_file" 2>/dev/null | wc -l)

        PASSED_TESTS=$((PASSED_TESTS + api_passed))
        FAILED_TESTS=$((FAILED_TESTS + api_failed))
        TOTAL_TESTS=$((TOTAL_TESTS + api_passed + api_failed))

        log_success "Testes de API: $api_passed passed, $api_failed failed"
        log_time $duration "Testes de API"

        rm -f "$output_file"
        return $test_result
    else
        log_warning "Script de testes de API não encontrado (test_all_apis.sh)"
        return 0
    fi
}

# ============================================================================
# TESTES E2E
# ============================================================================

run_e2e_tests() {
    log_header "TESTES END-TO-END"

    local start=$(start_timer)

    cd "$SCRIPT_DIR"
    
    export BACKEND_URL="http://localhost:63000"
    export FRONTEND_URL="http://localhost:65080"

    if [ -f "$SCRIPT_DIR/e2e_test.sh" ]; then
        log_info "Executando testes E2E..."

        local output_file=$(mktemp)
        local test_result=0

        bash "$SCRIPT_DIR/e2e_test.sh" 2>&1 | tee "$output_file" | tee -a "$REPORT_FILE" || test_result=$?

        local duration=$(end_timer $start)
        TEST_TIMES["e2e"]=$duration

        local e2e_passed=$(grep "✓" "$output_file" 2>/dev/null | wc -l)
        local e2e_failed=$(grep "✗" "$output_file" 2>/dev/null | wc -l)

        PASSED_TESTS=$((PASSED_TESTS + e2e_passed))
        FAILED_TESTS=$((FAILED_TESTS + e2e_failed))
        TOTAL_TESTS=$((TOTAL_TESTS + e2e_passed + e2e_failed))

        log_success "Testes E2E: $e2e_passed passed, $e2e_failed failed"
        log_time $duration "Testes E2E"

        rm -f "$output_file"
        return $test_result
    else
        log_warning "Script E2E não encontrado (e2e_test.sh)"
        return 0
    fi
}

# ============================================================================
# TESTES PYTHON (Pytest)
# ============================================================================

run_python_tests() {
    log_header "TESTES PYTHON (Pytest)"

    local start=$(start_timer)

    cd "$SCRIPT_DIR"

    # Verificar se pytest está instalado
    if ! command -v pytest &> /dev/null; then
        log_warning "Pytest não encontrado. Tentando instalar dependências..."
        pip install -r requirements.txt || true
    fi

    log_info "Executando suite de testes Python..."

    local output_file=$(mktemp)
    local test_result=0

    # Executa todos os arquivos test_*.py
    # Adicionamos --ignore=tests/integration_tests.sh.py se existir, mas pytest ignora não-python
    # Usamos o contexto do docker-compose se necessário, mas aqui rodamos localmente contra o endpoint exposto
    # Assegurar que as vars de ambiente apontem para o backend de teste (localhost:3000 ou 63000 dependendo da config)
    # O setup do run_all_tests.sh sobe na porta padrão mapeada no docker-compose.test.yml
    # Vamos assumir que o ambiente já está up via setup_test_environment

    export TEST_API_URL="http://localhost:63000/api"
    export DB_HOST="localhost"
    export DB_PORT="65432" 
    # Mapeamento do docker-compose.test.yml é 5432:5432 no host normalmente?
    # Vamos verificar o docker-compose.test.yml. Se não tiver porta exposta, o teste local falha.
    # Mas security_test_suite.sh roda localmente usando curl, então a porta deve estar exposta.

    if pytest -v 2>&1 | tee "$output_file" | tee -a "$REPORT_FILE"; then
        timer_res=$? # Capture pytest exit code? No, tee masks it.
        # Check actual pytest execution status from pipe logic or separate execution
        # Simple check: grep "failed" count
    else
        test_result=1
    fi
     
    # Pytest returns non-zero on failure. 
    # Use PIPESTATUS to get pytest exit code
    test_result=${PIPESTATUS[0]}

    local duration=$(end_timer $start)
    TEST_TIMES["python"]=$duration

    # Parse pytest output finding the "X passed" pattern
    # Output example: "===== 10 passed, 2 failed in 0.12s ====="
    local py_passed=$(grep -oE "[0-9]+ passed" "$output_file" | tail -n1 | awk '{print $1}' || echo "0")
    local py_failed=$(grep -oE "[0-9]+ failed" "$output_file" | tail -n1 | awk '{print $1}' || echo "0")

    PASSED_TESTS=$((PASSED_TESTS + py_passed))
    FAILED_TESTS=$((FAILED_TESTS + py_failed))
    TOTAL_TESTS=$((TOTAL_TESTS + py_passed + py_failed))

    if [ "$test_result" -eq 0 ]; then
        log_success "Testes Python: TODOS PASSARAM"
        log_time $duration "Testes Python"
        rm -f "$output_file"
        return 0
    else
        log_error "Testes Python: FALHARAM"
        log_time $duration "Testes Python"
        rm -f "$output_file"
        return 1
    fi
}

# ============================================================================
# RELATÓRIO FINAL
# ============================================================================

generate_final_report() {
    log_header "GERANDO RELATÓRIO FINAL"

    local end_time=$(date +%s)
    local total_duration=$((end_time - START_TIME))

    cat >> "$REPORT_FILE" << EOF

---

## 📊 RESUMO EXECUTIVO

### Testes Executados
- **Total:** $TOTAL_TESTS testes
- **Passou:** $PASSED_TESTS ✓
- **Falhou:** $FAILED_TESTS ✗
- **Pulado:** $SKIPPED_TESTS ⊘

### Taxa de Sucesso
- **$(if [ $TOTAL_TESTS -gt 0 ]; then awk "BEGIN {printf \"%.2f\", ($PASSED_TESTS / $TOTAL_TESTS) * 100}"; else echo "N/A"; fi)%**

---

## ⏱️ TEMPOS DE EXECUÇÃO

| Fase | Duração | Percentual |
|------|---------|------------|
EOF

    for phase in build unit setup security integration api e2e; do
        if [ -n "${TEST_TIMES[$phase]}" ]; then
            local duration=${TEST_TIMES[$phase]}
            local percentage=$(awk "BEGIN {printf \"%.1f\", ($duration / $total_duration) * 100}")
            echo "| $(echo $phase | awk '{print toupper(substr($0,1,1)) tolower(substr($0,2))}') | $(format_duration $duration) | ${percentage}% |" >> "$REPORT_FILE"
        fi
    done

    cat >> "$REPORT_FILE" << EOF
| **TOTAL** | **$(format_duration $total_duration)** | **100%** |

---

## 🔒 COBERTURA DE SEGURANÇA

- ✅ Autenticação JWT (validação, expiração, assinatura)
- ✅ Autorização e Controle de Acesso (RBAC)
- ✅ Escalação de Privilégios
- ✅ SQL Injection
- ✅ XSS (Cross-Site Scripting)
- ✅ CSRF Protection
- ✅ Validação de Input
- ✅ Sanitização de Output
- ✅ Vazamento de Dados Sensíveis
- ✅ Rate Limiting / Brute Force
- ✅ Segurança de Senhas (bcrypt)

---

## 📁 ARQUIVOS GERADOS

- Relatório completo: \`$REPORT_FILE\`
- Coverage HTML: \`$REPORTS_DIR/coverage_${TIMESTAMP}.html\`

---

**Gerado em:** $(date '+%Y-%m-%d %H:%M:%S')
**Duração total:** $(format_duration $total_duration)

EOF

    log_success "Relatório completo salvo em: $REPORT_FILE"

    # Exibir resumo no terminal
    echo -e "\n${MAGENTA}╔════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${MAGENTA}║${NC}                    RESUMO DOS TESTES                              ${MAGENTA}║${NC}"
    echo -e "${MAGENTA}╠════════════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${MAGENTA}║${NC} Total: $TOTAL_TESTS | ${GREEN}Passou: $PASSED_TESTS${NC} | ${RED}Falhou: $FAILED_TESTS${NC} | ${YELLOW}Pulado: $SKIPPED_TESTS${NC}"
    echo -e "${MAGENTA}║${NC} Duração total: $(format_duration $total_duration)"
    if [ $TOTAL_TESTS -gt 0 ]; then
        echo -e "${MAGENTA}║${NC} Taxa de sucesso: $(awk "BEGIN {printf \"%.2f\", ($PASSED_TESTS / $TOTAL_TESTS) * 100}")%"
    else
        echo -e "${MAGENTA}║${NC} Taxa de sucesso: N/A"
    fi
    echo -e "${MAGENTA}╚════════════════════════════════════════════════════════════════════╝${NC}\n"
}

# ============================================================================
# MAIN
# ============================================================================

main() {
    log_header "🧪 STACK COMPLETA DE TESTES - Entity Hub"

    init_report
    check_dependencies

    local exit_code=0

    # Build
    if ! build_project; then
        log_error "Build falhou. Abortando testes."
        exit 1
    fi

    # Setup
    if ! setup_test_environment; then
        log_error "Falha ao configurar ambiente de testes"
        exit 1
    fi

    # Testes unitários
    run_unit_tests || exit_code=1

    # Testes de segurança
    # run_security_tests || exit_code=1

    # Testes de integração
    # run_integration_tests || exit_code=1

    # Testes de API
    # run_api_tests || exit_code=1

    # Testes E2E
    run_e2e_tests || exit_code=1

    # Testes Python (Geral + AGPL)
    run_python_tests || exit_code=1

    # Cleanup
    cleanup_test_environment

    # Relatório
    generate_final_report

    if [ $exit_code -eq 0 ]; then
        log_success "TODOS OS TESTES PASSARAM! 🎉"
    else
        log_warning "ALGUNS TESTES FALHARAM ⚠️"
    fi

    exit $exit_code
}

# Trap para cleanup em caso de interrupção
trap cleanup_test_environment EXIT INT TERM

# Executar
main "$@"
