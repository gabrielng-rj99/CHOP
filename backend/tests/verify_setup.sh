#!/bin/bash

# Script de verificação da configuração dos testes de segurança
# Verifica se todas as correções foram aplicadas corretamente

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}  Verificação da Configuração - Testes de Segurança${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo ""

ERRORS=0
WARNINGS=0
CHECKS=0

check() {
    ((CHECKS++))
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓${NC} $1"
    else
        echo -e "${RED}✗${NC} $1"
        ((ERRORS++))
    fi
}

warn() {
    echo -e "${YELLOW}⚠${NC} $1"
    ((WARNINGS++))
}

info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

# ==============================================================================
# 1. Verificar Porta do Banco
# ==============================================================================
echo -e "\n${YELLOW}[1/10]${NC} Verificando porta do banco de dados..."

if grep -q "65432:5432" docker-compose.test.yml; then
    check "Porta 65432 configurada em docker-compose.test.yml"
else
    check "ERRO: Porta 65432 NÃO encontrada em docker-compose.test.yml"
fi

if grep -q "localhost:65432" security__main.go; then
    check "Porta 65432 configurada em security__main.go"
else
    check "ERRO: Porta 65432 NÃO encontrada em security__main.go"
fi

if grep -q "TEST_DB_PORT=65432" run_security_tests.sh; then
    check "Porta 65432 configurada em run_security_tests.sh"
else
    check "ERRO: Porta 65432 NÃO encontrada em run_security_tests.sh"
fi

# ==============================================================================
# 2. Verificar Schema SQL
# ==============================================================================
echo -e "\n${YELLOW}[2/10]${NC} Verificando aplicação do schema.sql..."

if grep -q "schema.sql:/docker-entrypoint-initdb.d/01-schema.sql" docker-compose.test.yml; then
    check "Schema SQL montado em docker-compose.test.yml"
else
    check "ERRO: Schema SQL NÃO montado corretamente"
fi

if [ -f "../database/schema.sql" ]; then
    check "Arquivo schema.sql existe em ../database/"
else
    check "ERRO: Arquivo schema.sql NÃO encontrado"
fi

# ==============================================================================
# 3. Verificar Funções de População
# ==============================================================================
echo -e "\n${YELLOW}[3/10]${NC} Verificando funções de população do banco..."

if grep -q "func populateTestDatabase" security__main.go; then
    check "Função populateTestDatabase implementada"
else
    check "ERRO: Função populateTestDatabase NÃO encontrada"
fi

if grep -q "func createTestUser" security__main.go; then
    check "Função createTestUser implementada"
else
    check "ERRO: Função createTestUser NÃO encontrada"
fi

if grep -q "func createTestClients" security__main.go; then
    check "Função createTestClients implementada"
else
    check "ERRO: Função createTestClients NÃO encontrada"
fi

if grep -q "func createTestCategories" security__main.go; then
    check "Função createTestCategories implementada"
else
    check "ERRO: Função createTestCategories NÃO encontrada"
fi

if grep -q "func cleanupTestData" security__main.go; then
    check "Função cleanupTestData implementada"
else
    check "ERRO: Função cleanupTestData NÃO encontrada"
fi

# ==============================================================================
# 4. Verificar Testes de JWT Vazio (CVE-2015-9235)
# ==============================================================================
echo -e "\n${YELLOW}[4/10]${NC} Verificando testes de JWT vazio (CVE-2015-9235)..."

if grep -q "TestEmptyJWTVulnerability" security_token_manipulation_test.go; then
    check "Teste de JWT vazio implementado"
else
    check "ERRO: Teste de JWT vazio NÃO encontrado"
fi

if grep -q "alg=none" security_token_manipulation_test.go; then
    check "Teste de algoritmo 'none' implementado"
else
    check "ERRO: Teste de algoritmo 'none' NÃO encontrado"
fi

if grep -q "TestJWTAlgorithmConfusion" security_token_manipulation_test.go; then
    check "Teste de algorithm confusion implementado"
else
    check "ERRO: Teste de algorithm confusion NÃO encontrado"
fi

# ==============================================================================
# 5. Verificar Testes de Requests Sem Senha
# ==============================================================================
echo -e "\n${YELLOW}[5/10]${NC} Verificando testes de requests sem senha..."

if grep -q "TestRequestWithoutPassword" security_privilege_escalation_test.go; then
    check "Teste de request sem senha implementado"
else
    check "ERRO: Teste de request sem senha NÃO encontrado"
fi

if grep -q "Criar usuário sem senha deve falhar" security_privilege_escalation_test.go; then
    check "Subteste de criação sem senha implementado"
else
    check "ERRO: Subteste de criação sem senha NÃO encontrado"
fi

if grep -q "Login sem senha deve falhar" security_privilege_escalation_test.go; then
    check "Subteste de login sem senha implementado"
else
    check "ERRO: Subteste de login sem senha NÃO encontrado"
fi

# ==============================================================================
# 6. Verificar Testes de Manipulação de Role
# ==============================================================================
echo -e "\n${YELLOW}[6/10]${NC} Verificando testes de manipulação de role..."

if grep -q "TestRoleManipulationInRequest" security_privilege_escalation_test.go; then
    check "Teste de manipulação de role implementado"
else
    check "ERRO: Teste de manipulação de role NÃO encontrado"
fi

if grep -q "Mass assignment" security_privilege_escalation_test.go; then
    check "Teste de mass assignment implementado"
else
    check "ERRO: Teste de mass assignment NÃO encontrado"
fi

# ==============================================================================
# 7. Verificar Cobertura de SQL Injection
# ==============================================================================
echo -e "\n${YELLOW}[7/10]${NC} Verificando cobertura completa de SQL Injection..."

REQUIRED_TESTS=(
    "TestSQLInjectionLogin"
    "TestSQLInjectionUserQueries"
    "TestSQLInjectionClientQueries"
    "TestSQLInjectionCategoryQueries"
    "TestSQLInjectionContractQueries"
    "TestSQLInjectionAuditLogs"
    "TestSQLInjectionEmptyAndNullInputs"
    "TestSQLInjectionSpecialCharacters"
    "TestSQLInjectionBatchOperations"
    "TestSQLInjectionSecondOrderAttacks"
)

for test in "${REQUIRED_TESTS[@]}"; do
    if grep -q "func $test" security_sql_injection_test.go; then
        check "Teste $test implementado"
    else
        check "ERRO: Teste $test NÃO encontrado"
    fi
done

# ==============================================================================
# 8. Verificar Testes de Edge Cases
# ==============================================================================
echo -e "\n${YELLOW}[8/10]${NC} Verificando testes de edge cases..."

if grep -q "Query com string vazia" security_sql_injection_test.go; then
    check "Teste de string vazia implementado"
else
    check "ERRO: Teste de string vazia NÃO encontrado"
fi

if grep -q "Query com NULL explícito" security_sql_injection_test.go; then
    check "Teste de NULL implementado"
else
    check "ERRO: Teste de NULL NÃO encontrado"
fi

if grep -q "Unicode e caracteres multibyte" security_sql_injection_test.go; then
    check "Teste de Unicode implementado"
else
    check "ERRO: Teste de Unicode NÃO encontrado"
fi

if grep -q "Query retornando lista vazia" security_sql_injection_test.go; then
    check "Teste de query vazia implementado"
else
    check "ERRO: Teste de query vazia NÃO encontrado"
fi

# ==============================================================================
# 9. Verificar Helpers Adicionais
# ==============================================================================
echo -e "\n${YELLOW}[9/10]${NC} Verificando helpers adicionais..."

if grep -q "func generateMaliciousPayloads" security__main.go; then
    check "Helper generateMaliciousPayloads implementado"
else
    check "ERRO: Helper generateMaliciousPayloads NÃO encontrado"
fi

if grep -q "func assertNoSensitiveData" security__main.go; then
    check "Helper assertNoSensitiveData implementado"
else
    check "ERRO: Helper assertNoSensitiveData NÃO encontrado"
fi

if grep -q "func assertNoStackTrace" security__main.go; then
    check "Helper assertNoStackTrace implementado"
else
    check "ERRO: Helper assertNoStackTrace NÃO encontrado"
fi

# ==============================================================================
# 10. Verificar Arquivos de Documentação
# ==============================================================================
echo -e "\n${YELLOW}[10/10]${NC} Verificando documentação..."

if [ -f "README.md" ]; then
    if grep -q "CVE-2015-9235" README.md; then
        check "README.md atualizado com CVE-2015-9235"
    else
        warn "README.md não menciona CVE-2015-9235"
    fi
else
    check "ERRO: README.md NÃO encontrado"
fi

if [ -f "CHANGELOG.md" ]; then
    check "CHANGELOG.md criado"
else
    warn "CHANGELOG.md não encontrado (opcional)"
fi

if [ -f "Makefile" ]; then
    check "Makefile existe"
else
    check "ERRO: Makefile NÃO encontrado"
fi

# ==============================================================================
# Resumo Final
# ==============================================================================
echo -e "\n${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}  Resumo da Verificação${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "Verificações realizadas: ${CHECKS}"
echo -e "Erros encontrados:       ${RED}${ERRORS}${NC}"
echo -e "Avisos:                  ${YELLOW}${WARNINGS}${NC}"
echo ""

if [ $ERRORS -eq 0 ]; then
    echo -e "${GREEN}✓ TODOS OS TESTES DE CONFIGURAÇÃO PASSARAM!${NC}"
    echo ""
    echo -e "${BLUE}Próximos passos:${NC}"
    echo -e "  1. Execute: ${GREEN}make test${NC} para executar todos os testes"
    echo -e "  2. Execute: ${GREEN}make coverage${NC} para gerar relatório de cobertura"
    echo -e "  3. Execute: ${GREEN}make help${NC} para ver todos os comandos disponíveis"
    echo ""
    echo -e "${GREEN}🎉 O ambiente está pronto para testes de segurança!${NC}"
    echo ""
    exit 0
else
    echo -e "${RED}✗ ERROS ENCONTRADOS NA CONFIGURAÇÃO!${NC}"
    echo ""
    echo -e "${YELLOW}Por favor, corrija os erros acima antes de executar os testes.${NC}"
    echo ""
    exit 1
fi
