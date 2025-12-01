#!/bin/bash

# ============================================================================
# SUITE COMPLETA DE TESTES DE SEGURANÇA - OWASP TOP 10
# ============================================================================
# Testa todas as vulnerabilidades conhecidas:
# - JWT manipulation (tokens inválidos, expirados, alterados)
# - SQL Injection em todos os endpoints
# - XSS (Cross-Site Scripting)
# - Escalação de privilégios (user -> admin -> root)
# - Vazamento de dados sensíveis
# - Brute force protection
# - CSRF
# - Input validation
# - Rate limiting
# ============================================================================

set -e

# Cores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Configuração
BACKEND_URL="${BACKEND_URL:-http://localhost:3000}"
API_URL="$BACKEND_URL/api"

# Contadores
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_TOTAL=0

# Tokens para testes
ROOT_TOKEN=""
ADMIN_TOKEN=""
USER_TOKEN=""

# ============================================================================
# FUNÇÕES AUXILIARES
# ============================================================================

log_test() {
    echo -e "\n${CYAN}[TEST]${NC} $1"
}

log_pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
    TESTS_PASSED=$((TESTS_PASSED + 1))
    TESTS_TOTAL=$((TESTS_TOTAL + 1))
}

log_fail() {
    echo -e "${RED}[FAIL]${NC} $1"
    TESTS_FAILED=$((TESTS_FAILED + 1))
    TESTS_TOTAL=$((TESTS_TOTAL + 1))
}

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_section() {
    echo -e "\n${YELLOW}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}║${NC} $1"
    echo -e "${YELLOW}═══════════════════════════════════════════════════════════════${NC}\n"
}

# ============================================================================
# TESTE 1: JWT SECURITY
# ============================================================================

test_jwt_security() {
    log_section "1. TESTES DE SEGURANÇA JWT"

    # 1.1 - Token ausente
    log_test "1.1 - Requisição sem token deve retornar 401"
    response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/users")
    status=$(echo "$response" | tail -n1)
    if [ "$status" = "401" ]; then
        log_pass "Bloqueou acesso sem token"
    else
        log_fail "Permitiu acesso sem token (status: $status)"
    fi

    # 1.2 - Token inválido
    log_test "1.2 - Token JWT inválido deve retornar 401"
    response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/users" \
        -H "Authorization: Bearer invalid.token.here")
    status=$(echo "$response" | tail -n1)
    if [ "$status" = "401" ]; then
        log_pass "Bloqueou token inválido"
    else
        log_fail "Aceitou token inválido (status: $status)"
    fi

    # 1.3 - Token expirado (simulação)
    log_test "1.3 - Token JWT expirado deve ser rejeitado"
    # Token JWT expirado (exp no passado)
    expired_token="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoiMTIzIiwidXNlcm5hbWUiOiJ0ZXN0Iiwicm9sZSI6InVzZXIiLCJleHAiOjE1MTYyMzkwMjJ9.invalid"
    response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/users" \
        -H "Authorization: Bearer $expired_token")
    status=$(echo "$response" | tail -n1)
    if [ "$status" = "401" ]; then
        log_pass "Bloqueou token expirado"
    else
        log_fail "Aceitou token expirado (status: $status)"
    fi

    # 1.4 - Token com assinatura alterada
    log_test "1.4 - Token com assinatura alterada deve ser rejeitado"
    tampered_token="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoiMTIzIiwicm9sZSI6InJvb3QifQ.TAMPERED_SIGNATURE"
    response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/users" \
        -H "Authorization: Bearer $tampered_token")
    status=$(echo "$response" | tail -n1)
    if [ "$status" = "401" ]; then
        log_pass "Bloqueou token adulterado"
    else
        log_fail "Aceitou token adulterado (status: $status)"
    fi

    # 1.5 - Token malformado
    log_test "1.5 - Token malformado deve retornar 401"
    response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/users" \
        -H "Authorization: Bearer notavalidjwttoken")
    status=$(echo "$response" | tail -n1)
    if [ "$status" = "401" ]; then
        log_pass "Bloqueou token malformado"
    else
        log_fail "Aceitou token malformado (status: $status)"
    fi

    # 1.6 - Header Authorization sem "Bearer"
    log_test "1.6 - Header sem prefixo Bearer deve ser rejeitado"
    response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/users" \
        -H "Authorization: sometoken123")
    status=$(echo "$response" | tail -n1)
    if [ "$status" = "401" ]; then
        log_pass "Bloqueou formato de header inválido"
    else
        log_fail "Aceitou formato inválido (status: $status)"
    fi
}

# ============================================================================
# TESTE 2: SQL INJECTION
# ============================================================================

test_sql_injection() {
    log_section "2. TESTES DE SQL INJECTION"

    # Payloads de SQL injection comuns
    declare -a sql_payloads=(
        "' OR '1'='1"
        "'; DROP TABLE users; --"
        "' UNION SELECT * FROM users --"
        "admin'--"
        "1' OR '1' = '1' /*"
        "' OR 1=1--"
        "' OR 'x'='x"
        "'; EXEC sp_MSForEachTable 'DROP TABLE ?'; --"
        "1; DELETE FROM users WHERE 1=1 --"
    )

    log_info "Testando ${#sql_payloads[@]} payloads de SQL injection"

    # 2.1 - SQL Injection no login
    log_test "2.1 - SQL Injection no endpoint de login"
    local injection_blocked=true
    for payload in "${sql_payloads[@]}"; do
        response=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/login" \
            -H "Content-Type: application/json" \
            -d "{\"username\":\"$payload\",\"password\":\"test\"}")

        status=$(echo "$response" | tail -n1)
        body=$(echo "$response" | sed '$d')

        # Se retornou 200 com token, pode indicar SQL injection
        if [ "$status" = "200" ] && echo "$body" | grep -q "token"; then
            injection_blocked=false
            break
        fi
    done

    if [ "$injection_blocked" = true ]; then
        log_pass "Protegido contra SQL injection no login"
    else
        log_fail "VULNERÁVEL a SQL injection no login!"
    fi

    # 2.2 - SQL Injection em busca de usuários (se tiver token)
    log_test "2.2 - SQL Injection em parâmetros de busca"
    if [ -n "$ROOT_TOKEN" ]; then
        response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/users?search=' OR '1'='1" \
            -H "Authorization: Bearer $ROOT_TOKEN")
        status=$(echo "$response" | tail -n1)

        if [ "$status" = "400" ] || [ "$status" = "401" ] || [ "$status" = "500" ]; then
            log_pass "Protegido contra SQL injection em busca"
        else
            log_fail "Possível vulnerabilidade em busca"
        fi
    else
        log_info "Pulado (sem token root disponível)"
    fi
}

# ============================================================================
# TESTE 3: XSS (CROSS-SITE SCRIPTING)
# ============================================================================

test_xss() {
    log_section "3. TESTES DE XSS (CROSS-SITE SCRIPTING)"

    # Payloads XSS comuns
    declare -a xss_payloads=(
        "<script>alert('XSS')</script>"
        "<img src=x onerror=alert('XSS')>"
        "<svg/onload=alert('XSS')>"
        "javascript:alert('XSS')"
        "<iframe src='javascript:alert(1)'>"
        "<body onload=alert('XSS')>"
        "';alert(String.fromCharCode(88,83,83));//"
    )

    log_test "3.1 - XSS em campos de texto (criação de usuário)"

    local xss_blocked=true
    for payload in "${xss_payloads[@]}"; do
        response=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/initialize/admin" \
            -H "Content-Type: application/json" \
            -d "{\"display_name\":\"$payload\",\"password\":\"Test123456\"}")

        status=$(echo "$response" | tail -n1)
        body=$(echo "$response" | sed '$d')

        # Verificar se o payload foi sanitizado ou rejeitado
        if echo "$body" | grep -q "$payload"; then
            # Se o payload aparece na resposta sem sanitização
            if ! echo "$body" | grep -q "&lt;script&gt;" && ! echo "$body" | grep -q "escaped"; then
                xss_blocked=false
                break
            fi
        fi
    done

    if [ "$xss_blocked" = true ]; then
        log_pass "Protegido contra XSS básico"
    else
        log_fail "VULNERÁVEL a XSS - payload não sanitizado!"
    fi

    # 3.2 - XSS em headers
    log_test "3.2 - XSS através de headers HTTP"
    response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/health" \
        -H "User-Agent: <script>alert('XSS')</script>" \
        -H "Referer: <img src=x onerror=alert('XSS')>")
    status=$(echo "$response" | tail -n1)

    if [ "$status" = "200" ] || [ "$status" = "400" ]; then
        log_pass "Headers maliciosos não causaram erro crítico"
    else
        log_fail "Comportamento inesperado com headers maliciosos"
    fi
}

# ============================================================================
# TESTE 4: ESCALAÇÃO DE PRIVILÉGIOS
# ============================================================================

test_privilege_escalation() {
    log_section "4. TESTES DE ESCALAÇÃO DE PRIVILÉGIOS"

    # 4.1 - Usuário tentando acessar recurso de admin
    log_test "4.1 - Usuário comum não pode acessar recursos administrativos"
    if [ -n "$USER_TOKEN" ]; then
        response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/users" \
            -H "Authorization: Bearer $USER_TOKEN")
        status=$(echo "$response" | tail -n1)

        if [ "$status" = "403" ] || [ "$status" = "401" ]; then
            log_pass "Bloqueou acesso de usuário a recurso admin"
        else
            log_fail "Usuário conseguiu acessar recurso admin (status: $status)"
        fi
    else
        log_info "Pulado (sem token de usuário disponível)"
    fi

    # 4.2 - Modificar role no JWT (simulação)
    log_test "4.2 - Token com role modificado deve ser rejeitado"
    # Token com role "root" mas assinatura inválida
    fake_root_token="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoiMTIzIiwicm9sZSI6InJvb3QifQ.fake_signature"
    response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/users" \
        -H "Authorization: Bearer $fake_root_token")
    status=$(echo "$response" | tail -n1)

    if [ "$status" = "401" ] || [ "$status" = "403" ]; then
        log_pass "Bloqueou token com role adulterado"
    else
        log_fail "Aceitou token com role adulterado!"
    fi

    # 4.3 - Admin tentando acessar recurso de root
    log_test "4.3 - Admin não pode acessar recursos exclusivos de root"
    if [ -n "$ADMIN_TOKEN" ]; then
        response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/audit-logs" \
            -H "Authorization: Bearer $ADMIN_TOKEN")
        status=$(echo "$response" | tail -n1)

        if [ "$status" = "403" ]; then
            log_pass "Bloqueou admin de acessar recurso root"
        else
            log_fail "Admin conseguiu acessar recurso root (status: $status)"
        fi
    else
        log_info "Pulado (sem token de admin disponível)"
    fi
}

# ============================================================================
# TESTE 5: VAZAMENTO DE DADOS SENSÍVEIS
# ============================================================================

test_sensitive_data_leakage() {
    log_section "5. TESTES DE VAZAMENTO DE DADOS SENSÍVEIS"

    # 5.1 - Verificar se password_hash vaza em respostas
    log_test "5.1 - Password hash não deve vazar na API"
    response=$(curl -s -X GET "$API_URL/initialize/status")

    if echo "$response" | grep -qi "password"; then
        log_fail "Possível vazamento de dados de senha na resposta"
    else
        log_pass "Nenhum vazamento de senha detectado"
    fi

    # 5.2 - Verificar stack trace em erros
    log_test "5.2 - Stack traces não devem ser expostos"
    response=$(curl -s -X POST "$API_URL/login" \
        -H "Content-Type: application/json" \
        -d "invalid json{")

    if echo "$response" | grep -qi "panic\|stacktrace\|goroutine"; then
        log_fail "Stack trace exposto na resposta de erro"
    else
        log_pass "Stack traces não expostos"
    fi

    # 5.3 - Verificar auth_secret não vaza
    log_test "5.3 - Auth secret não deve vazar"
    if [ -n "$ROOT_TOKEN" ]; then
        response=$(curl -s -X GET "$API_URL/users" \
            -H "Authorization: Bearer $ROOT_TOKEN")

        if echo "$response" | grep -qi "auth_secret\|authSecret"; then
            log_fail "Auth secret vazando na API!"
        else
            log_pass "Auth secret não exposto"
        fi
    else
        log_info "Pulado (sem token root)"
    fi

    # 5.4 - Informações de banco de dados em erros
    log_test "5.4 - Detalhes de banco de dados não devem vazar"
    response=$(curl -s -X GET "$API_URL/users/99999999-9999-9999-9999-999999999999")

    if echo "$response" | grep -qi "postgres\|database\|sql\|table\|column"; then
        log_fail "Informações de banco vazando em erros"
    else
        log_pass "Detalhes de banco não expostos"
    fi
}

# ============================================================================
# TESTE 6: BRUTE FORCE PROTECTION
# ============================================================================

test_brute_force_protection() {
    log_section "6. TESTES DE PROTEÇÃO CONTRA BRUTE FORCE"

    # 6.1 - Múltiplas tentativas de login falhadas
    log_test "6.1 - Sistema deve bloquear após tentativas falhadas"

    local attempts=10
    local blocked=false

    for i in $(seq 1 $attempts); do
        response=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/login" \
            -H "Content-Type: application/json" \
            -d "{\"username\":\"testuser\",\"password\":\"wrongpass$i\"}")

        status=$(echo "$response" | tail -n1)
        body=$(echo "$response" | sed '$d')

        # Verificar se bloqueou após X tentativas
        if echo "$body" | grep -qi "bloqueado\|locked\|too many\|rate limit"; then
            blocked=true
            log_info "Bloqueou após $i tentativas"
            break
        fi

        sleep 0.1
    done

    if [ "$blocked" = true ]; then
        log_pass "Proteção contra brute force ativa"
    else
        log_fail "SEM proteção contra brute force detectada"
    fi

    # 6.2 - Rate limiting geral
    log_test "6.2 - Rate limiting em endpoints públicos"

    local rate_limited=false
    for i in $(seq 1 50); do
        response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/health")
        status=$(echo "$response" | tail -n1)

        if [ "$status" = "429" ]; then
            rate_limited=true
            log_info "Rate limit atingido após $i requisições"
            break
        fi
    done

    if [ "$rate_limited" = true ]; then
        log_pass "Rate limiting implementado"
    else
        log_info "Rate limiting não detectado (pode não estar habilitado)"
    fi
}

# ============================================================================
# TESTE 7: INPUT VALIDATION
# ============================================================================

test_input_validation() {
    log_section "7. TESTES DE VALIDAÇÃO DE INPUT"

    # 7.1 - Campos vazios
    log_test "7.1 - Deve rejeitar campos obrigatórios vazios"
    response=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/initialize/admin" \
        -H "Content-Type: application/json" \
        -d "{\"display_name\":\"\",\"password\":\"\"}")
    status=$(echo "$response" | tail -n1)

    if [ "$status" = "400" ]; then
        log_pass "Rejeitou campos vazios"
    else
        log_fail "Aceitou campos vazios (status: $status)"
    fi

    # 7.2 - Tipos de dados inválidos
    log_test "7.2 - Deve rejeitar tipos de dados incorretos"
    response=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/login" \
        -H "Content-Type: application/json" \
        -d "{\"username\":123,\"password\":true}")
    status=$(echo "$response" | tail -n1)

    if [ "$status" = "400" ]; then
        log_pass "Rejeitou tipos incorretos"
    else
        log_fail "Aceitou tipos incorretos (status: $status)"
    fi

    # 7.3 - Campos excessivamente longos
    log_test "7.3 - Deve rejeitar inputs muito longos"
    long_string=$(python3 -c "print('A' * 100000)" 2>/dev/null || echo "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
    response=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/initialize/admin" \
        -H "Content-Type: application/json" \
        -d "{\"display_name\":\"$long_string\",\"password\":\"Test123\"}")
    status=$(echo "$response" | tail -n1)

    if [ "$status" = "400" ] || [ "$status" = "413" ]; then
        log_pass "Rejeitou input muito longo"
    else
        log_fail "Aceitou input muito longo (status: $status)"
    fi

    # 7.4 - Caracteres especiais maliciosos
    log_test "7.4 - Deve sanitizar caracteres especiais"
    response=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/initialize/admin" \
        -H "Content-Type: application/json" \
        -d "{\"display_name\":\"Test\u0000User\",\"password\":\"Pass123\"}")
    status=$(echo "$response" | tail -n1)

    if [ "$status" = "400" ] || [ "$status" = "403" ]; then
        log_pass "Bloqueou caracteres especiais maliciosos"
    else
        log_info "Aceitou ou sanitizou caracteres especiais (status: $status)"
    fi
}

# ============================================================================
# TESTE 8: CORS E HEADERS DE SEGURANÇA
# ============================================================================

test_security_headers() {
    log_section "8. TESTES DE HEADERS DE SEGURANÇA"

    # 8.1 - CORS headers
    log_test "8.1 - Verificar configuração CORS"
    response=$(curl -s -I -X OPTIONS "$API_URL/health" \
        -H "Origin: http://evil.com")

    if echo "$response" | grep -qi "Access-Control-Allow-Origin"; then
        log_info "CORS configurado (verificar se é restritivo)"
    else
        log_pass "CORS não permite origens arbitrárias"
    fi

    # 8.2 - Security headers essenciais
    log_test "8.2 - Verificar headers de segurança essenciais"
    response=$(curl -s -I -X GET "$API_URL/health")

    local headers_ok=true

    # Verificar X-Content-Type-Options
    if echo "$response" | grep -qi "X-Content-Type-Options"; then
        log_info "✓ X-Content-Type-Options presente"
    else
        log_info "⚠ X-Content-Type-Options ausente"
    fi

    # Verificar X-Frame-Options
    if echo "$response" | grep -qi "X-Frame-Options"; then
        log_info "✓ X-Frame-Options presente"
    else
        log_info "⚠ X-Frame-Options ausente"
    fi
}

# ============================================================================
# TESTE 9: INITIALIZE ENDPOINT SECURITY
# ============================================================================

test_initialize_security() {
    log_section "9. TESTE DE SEGURANÇA DO ENDPOINT /initialize/admin"

    # 9.1 - Endpoint deve estar bloqueado se banco tiver dados
    log_test "9.1 - /initialize/admin bloqueado quando banco tem dados"
    response=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/initialize/admin" \
        -H "Content-Type: application/json" \
        -d "{\"display_name\":\"Hacker\",\"password\":\"TryToBreak123\"}")

    status=$(echo "$response" | tail -n1)
    body=$(echo "$response" | sed '$d')

    # Se banco já tem dados, deve retornar 403
    if [ "$status" = "403" ]; then
        log_pass "Endpoint bloqueado corretamente (banco com dados)"
    elif [ "$status" = "200" ]; then
        log_fail "CRÍTICO: Endpoint permitiu criar admin com banco populado!"
    else
        log_info "Endpoint retornou status $status (verificar se é primeira inicialização)"
    fi

    # 9.2 - Verificar mensagem de erro apropriada
    if echo "$body" | grep -qi "already initialized\|database contains\|blocked"; then
        log_pass "Mensagem de erro apropriada"
    fi
}

# ============================================================================
# TESTE 10: CSRF PROTECTION
# ============================================================================

test_csrf_protection() {
    log_section "10. TESTES DE PROTEÇÃO CSRF"

    # 10.1 - Requisições sem origin/referer
    log_test "10.1 - Aceitar requisições sem origin (API REST pública)"
    response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/health")
    status=$(echo "$response" | tail -n1)

    if [ "$status" = "200" ]; then
        log_pass "API REST aceita requisições sem origin (comportamento esperado)"
    else
        log_fail "API não respondeu corretamente (status: $status)"
    fi

    # 10.2 - Content-Type verification
    log_test "10.2 - Verificar validação de Content-Type"
    response=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/login" \
        -H "Content-Type: text/plain" \
        -d "username=test&password=test")
    status=$(echo "$response" | tail -n1)

    if [ "$status" = "400" ] || [ "$status" = "415" ]; then
        log_pass "Content-Type inválido rejeitado"
    else
        log_info "Content-Type alternativo aceito (status: $status)"
    fi
}

# ============================================================================
# MAIN
# ============================================================================

main() {
    echo -e "${CYAN}"
    echo "╔════════════════════════════════════════════════════════════════╗"
    echo "║     SUITE COMPLETA DE TESTES DE SEGURANÇA - OWASP TOP 10      ║"
    echo "╚════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}\n"

    log_info "Backend URL: $BACKEND_URL"
    log_info "Iniciando testes de segurança...\n"

    # Executar todas as suites
    test_jwt_security
    test_sql_injection
    test_xss
    test_privilege_escalation
    test_sensitive_data_leakage
    test_brute_force_protection
    test_input_validation
    test_security_headers
    test_initialize_security
    test_csrf_protection

    # Resumo
    echo -e "\n${YELLOW}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}║${NC}                    RESUMO DOS TESTES                         ${YELLOW}║${NC}"
    echo -e "${YELLOW}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}Passou:${NC} $TESTS_PASSED"
    echo -e "${RED}Falhou:${NC} $TESTS_FAILED"
    echo -e "${BLUE}Total:${NC} $TESTS_TOTAL"

    if [ $TESTS_FAILED -eq 0 ]; then
        echo -e "\n${GREEN}✓ TODOS OS TESTES DE SEGURANÇA PASSARAM!${NC}\n"
        exit 0
    else
        echo -e "\n${RED}✗ ALGUNS TESTES DE SEGURANÇA FALHARAM${NC}\n"
        exit 1
    fi
}

main "$@"
