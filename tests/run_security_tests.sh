#!/bin/bash

# ============================================================================
# SCRIPT DE EXECUÇÃO COMPLETA DE TESTES DE SEGURANÇA
# ============================================================================
# Este script:
# 1. Sobe o banco PostgreSQL na porta 65432
# 2. Aguarda o banco ficar pronto
# 3. Aplica o schema
# 4. Executa todos os testes de segurança
# 5. Gera relatório detalhado
# 6. Limpa tudo (banco, volumes, logs temporários)
# 7. Mantém apenas o relatório final
# ============================================================================

set -e  # Exit on error

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Diretórios
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
REPORTS_DIR="$SCRIPT_DIR/test_reports"

# Arquivo de relatório final
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
REPORT_FILE="$REPORTS_DIR/security_test_report_${TIMESTAMP}.txt"

# Criar diretório de relatórios
mkdir -p "$REPORTS_DIR"

# ============================================================================
# FUNÇÕES AUXILIARES
# ============================================================================

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

log_section() {
    echo "" | tee -a "$REPORT_FILE"
    echo "============================================================================" | tee -a "$REPORT_FILE"
    echo "$1" | tee -a "$REPORT_FILE"
    echo "============================================================================" | tee -a "$REPORT_FILE"
    echo "" | tee -a "$REPORT_FILE"
}

cleanup() {
    log_section "LIMPEZA DO AMBIENTE"

    log_info "Parando containers Docker..."
    cd "$SCRIPT_DIR"
    $DOCKER_COMPOSE -f docker-compose.test.yml down -v 2>/dev/null || true

    log_info "Removendo volumes Docker..."
    docker volume rm backend_postgres_test_data 2>/dev/null || true

    log_info "Removendo logs temporários..."
    rm -f "$SCRIPT_DIR/server.log" 2>/dev/null || true
    rm -f "$SCRIPT_DIR/test.log" 2>/dev/null || true

    log_info "Removendo binários de teste..."
    rm -f "$SCRIPT_DIR/tests/tests.test" 2>/dev/null || true

    log_success "Limpeza concluída"
}

check_dependencies() {
    log_section "VERIFICAÇÃO DE DEPENDÊNCIAS"

    # Verificar Docker
    if ! command -v docker &> /dev/null; then
        log_error "Docker não encontrado. Instale o Docker para continuar."
        exit 1
    fi
    log_success "Docker encontrado: $(docker --version)"

    # Verificar Docker Compose (tenta moderno primeiro, depois legacy)
    if docker compose version &> /dev/null; then
        DOCKER_COMPOSE="docker compose"
        log_success "Docker Compose encontrado: $(docker compose version)"
    elif command -v docker-compose &> /dev/null; then
        DOCKER_COMPOSE="docker-compose"
        log_success "Docker Compose encontrado: $(docker-compose --version)"
    else
        log_error "Docker Compose não encontrado. Instale Docker Desktop ou docker-compose plugin."
        exit 1
    fi

    # Verificar Go
    if ! command -v go &> /dev/null; then
        log_error "Go não encontrado. Instale o Go para continuar."
        exit 1
    fi
    log_success "Go encontrado: $(go version)"
}

start_database() {
    log_section "INICIANDO BANCO DE DADOS DE TESTE"

    cd "$SCRIPT_DIR"

    # Verificar se docker-compose.test.yml existe
    if [ ! -f "docker-compose.test.yml" ]; then
        log_error "Arquivo docker-compose.test.yml não encontrado!"
        exit 1
    fi

    log_info "Subindo container PostgreSQL..."
    $DOCKER_COMPOSE -f docker-compose.test.yml up -d

    if [ $? -eq 0 ]; then
        log_success "Container iniciado"
    else
        log_error "Falha ao iniciar container"
        exit 1
    fi

    # Aguardar banco ficar pronto
    log_info "Aguardando banco de dados ficar pronto..."
    MAX_ATTEMPTS=30
    ATTEMPT=0

    while [ $ATTEMPT -lt $MAX_ATTEMPTS ]; do
        if $DOCKER_COMPOSE -f docker-compose.test.yml exec -T postgres_test pg_isready -U test_user -d contracts_test &> /dev/null; then
            log_success "Banco de dados está pronto!"
            return 0
        fi

        ATTEMPT=$((ATTEMPT + 1))
        echo -n "." | tee -a "$REPORT_FILE"
        sleep 1
    done

    log_error "Timeout aguardando banco de dados ficar pronto"
    $DOCKER_COMPOSE -f docker-compose.test.yml logs postgres_test | tee -a "$REPORT_FILE"
    exit 1
}

verify_schema() {
    log_section "VERIFICANDO SCHEMA DO BANCO"

    cd "$SCRIPT_DIR"

    log_info "Verificando se schema foi aplicado..."

    # Verificar tabelas principais
    TABLES=("users" "clients" "categories" "lines" "contracts" "audit_logs" "dependents")

    for table in "${TABLES[@]}"; do
        RESULT=$($DOCKER_COMPOSE -f docker-compose.test.yml exec -T postgres_test \
            psql -U test_user -d contracts_test -tAc \
            "SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_schema = 'public' AND table_name = '$table');" 2>/dev/null)

        if [ "$RESULT" = "t" ]; then
            log_success "Tabela '$table' encontrada"
        else
            log_error "Tabela '$table' NÃO encontrada!"
            return 1
        fi
    done

    log_success "Schema verificado com sucesso"
}

run_tests() {
    log_section "EXECUTANDO TESTES DE SEGURANÇA"

    cd "$SCRIPT_DIR"

    # Definir variável de ambiente para conexão com banco de teste
    export TEST_DATABASE_URL="postgres://test_user:test_password@localhost:65432/contracts_test?sslmode=disable"

    log_info "Executando suite completa de testes..."
    log_info "Database URL: $TEST_DATABASE_URL"
    echo "" | tee -a "$REPORT_FILE"

    # Executar testes e capturar output
    TEST_OUTPUT=$(mktemp)

    if go test -v ./tests/... 2>&1 | tee "$TEST_OUTPUT"; then
        TEST_EXIT_CODE=0
    else
        TEST_EXIT_CODE=$?
    fi

    # Adicionar output dos testes ao relatório
    cat "$TEST_OUTPUT" >> "$REPORT_FILE"

    # Analisar resultados
    TOTAL_TESTS=$(grep -c "^=== RUN" "$TEST_OUTPUT" || echo "0")
    PASSED_TESTS=$(grep -c "^--- PASS:" "$TEST_OUTPUT" || echo "0")
    FAILED_TESTS=$(grep -c "^--- FAIL:" "$TEST_OUTPUT" || echo "0")
    SKIPPED_TESTS=$(grep -c "^--- SKIP:" "$TEST_OUTPUT" || echo "0")

    rm "$TEST_OUTPUT"

    echo "" | tee -a "$REPORT_FILE"
    log_section "RESULTADO DOS TESTES"
    log_info "Total de testes executados: $TOTAL_TESTS"
    log_success "Testes passaram: $PASSED_TESTS"

    if [ "$FAILED_TESTS" -gt 0 ]; then
        log_error "Testes falharam: $FAILED_TESTS"
    else
        log_info "Testes falharam: $FAILED_TESTS"
    fi

    if [ "$SKIPPED_TESTS" -gt 0 ]; then
        log_warning "Testes pulados: $SKIPPED_TESTS"
    else
        log_info "Testes pulados: $SKIPPED_TESTS"
    fi

    return $TEST_EXIT_CODE
}

generate_summary() {
    log_section "RESUMO DA EXECUÇÃO"

    END_TIME=$(date '+%Y-%m-%d %H:%M:%S')
    DURATION=$(($(date +%s) - $(date -d "$START_TIME" +%s 2>/dev/null || echo "0")))

    {
        echo ""
        echo "Início: $START_TIME"
        echo "Fim: $END_TIME"
        echo "Duração: ${DURATION}s"
        echo ""
        echo "Relatório completo salvo em:"
        echo "$REPORT_FILE"
        echo ""
        echo "============================================================================"
        echo "TESTES DE SEGURANÇA COBERTOS:"
        echo "============================================================================"
        echo "✓ Manipulação de Tokens JWT (CVE-2015-9235, tokens expirados, inválidos)"
        echo "✓ SQL Injection (prepared statements, payloads maliciosos)"
        echo "✓ XSS (Cross-Site Scripting) em todos os campos de entrada"
        echo "✓ Escalação de Privilégios (user → admin → root)"
        echo "✓ Vazamento de Dados Sensíveis (password_hash, auth_secret, stack traces)"
        echo "✓ Brute Force Protection (tentativas falhadas, bloqueio de conta)"
        echo "✓ Autenticação e Fluxos de Login"
        echo "✓ Segurança de Senhas (bcrypt, força, armazenamento)"
        echo "✓ Timing Attacks"
        echo "✓ Validação de Input"
        echo "============================================================================"
        echo ""
    } | tee -a "$REPORT_FILE"
}

# ============================================================================
# SCRIPT PRINCIPAL
# ============================================================================

# Capturar tempo de início
START_TIME=$(date '+%Y-%m-%d %H:%M:%S')

# Iniciar relatório
{
    echo "============================================================================"
    echo "RELATÓRIO DE TESTES DE SEGURANÇA"
    echo "Contract Manager - Backend"
    echo "============================================================================"
    echo ""
    echo "Data/Hora: $START_TIME"
    echo "Ambiente: Testes Automatizados"
    echo "Banco de Dados: PostgreSQL 16 (porta 65432)"
    echo ""
} > "$REPORT_FILE"

# Registrar handler de limpeza para execução ao sair
trap cleanup EXIT

# Executar pipeline de testes
log_section "INICIANDO TESTES DE SEGURANÇA"

check_dependencies
start_database
verify_schema

# Executar testes e capturar resultado
if run_tests; then
    log_success "TODOS OS TESTES PASSARAM!"
    TEST_RESULT=0
else
    log_warning "ALGUNS TESTES FALHARAM OU FORAM PULADOS"
    TEST_RESULT=1
fi

# Gerar resumo final
generate_summary

# Exibir localização do relatório
echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Relatório salvo em:${NC}"
echo -e "${BLUE}$REPORT_FILE${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

# Retornar código de saída apropriado
exit $TEST_RESULT
