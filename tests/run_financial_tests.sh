#!/bin/bash

# =============================================================================
# Client Hub Open Project
# Copyright (C) 2025 Client Hub Contributors
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
# =============================================================================

# Script para executar testes de segurança das APIs de Financeiro
# Este script executa todos os testes relacionados à funcionalidade de financeiro

set -e  # Exit on error

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}================================================${NC}"
echo -e "${BLUE}   FINANCIAL API SECURITY TESTS${NC}"
echo -e "${BLUE}================================================${NC}"
echo ""

# Verificar se está no diretório tests
if [ ! -f "test_financial_security.py" ]; then
    echo -e "${RED}❌ Erro: Execute este script do diretório tests/${NC}"
    exit 1
fi

# Verificar se o venv existe
if [ ! -d ".venv" ]; then
    echo -e "${YELLOW}⚠️  Virtual environment não encontrado. Criando...${NC}"
    python3 -m venv .venv
fi

# Ativar venv
echo -e "${BLUE}🔧 Ativando virtual environment...${NC}"
source .venv/bin/activate

# Instalar dependências se necessário
if ! python -c "import pytest" 2>/dev/null; then
    echo -e "${YELLOW}📦 Instalando dependências...${NC}"
    pip install -q -r requirements.txt
fi

# Verificar se o backend está rodando
echo -e "${BLUE}🔍 Verificando se o backend está disponível...${NC}"
API_URL=${API_URL:-"http://localhost:3000/api"}
if ! curl -s -f "${API_URL%/api}/health" > /dev/null 2>&1; then
    echo -e "${RED}❌ Backend não está disponível em ${API_URL%/api}${NC}"
    echo -e "${YELLOW}   Por favor, inicie o backend antes de executar os testes.${NC}"
    exit 1
fi
echo -e "${GREEN}✅ Backend está disponível${NC}"
echo ""

# Executar testes
echo -e "${BLUE}================================================${NC}"
echo -e "${BLUE}   EXECUTANDO TESTES DE FINANCEIRO${NC}"
echo -e "${BLUE}================================================${NC}"
echo ""

# Opções do pytest
PYTEST_OPTS="-v --tb=short --color=yes"

# Se passar argumento --verbose ou -vv, aumenta verbosidade
if [[ "$*" == *"--verbose"* ]] || [[ "$*" == *"-vv"* ]]; then
    PYTEST_OPTS="-vv --tb=long --color=yes"
fi

# Se passar --quick, executa apenas testes rápidos
if [[ "$*" == *"--quick"* ]]; then
    echo -e "${YELLOW}⚡ Modo rápido: executando apenas testes básicos${NC}"
    PYTEST_OPTS="$PYTEST_OPTS -m 'not slow'"
fi

# Executar testes de financeiro
echo -e "${BLUE}📋 Executando: test_financial_security.py${NC}"
echo ""

pytest $PYTEST_OPTS test_financial_security.py

TEST_EXIT_CODE=$?

echo ""
echo -e "${BLUE}================================================${NC}"
echo -e "${BLUE}   RESUMO DOS TESTES${NC}"
echo -e "${BLUE}================================================${NC}"
echo ""

if [ $TEST_EXIT_CODE -eq 0 ]; then
    echo -e "${GREEN}✅ TODOS OS TESTES DE FINANCEIRO PASSARAM!${NC}"
    echo ""
    echo -e "${GREEN}Categorias testadas:${NC}"
    echo -e "  ✓ Autenticação e Autorização"
    echo -e "  ✓ SQL Injection"
    echo -e "  ✓ XSS (Cross-Site Scripting)"
    echo -e "  ✓ Requisições vazias e NULL handling"
    echo -e "  ✓ Overflow e limites"
    echo -e "  ✓ Validação de UUID"
    echo -e "  ✓ Parcelas (Installments)"
    echo -e "  ✓ Marcar como pago/pendente"
    echo -e "  ✓ Dashboard endpoints"
    echo -e "  ✓ Casos extremos e resiliência"
    echo ""
    echo -e "${GREEN}🛡️  A API de Financeiro está segura!${NC}"
else
    echo -e "${RED}❌ ALGUNS TESTES FALHARAM!${NC}"
    echo ""
    echo -e "${RED}⚠️  ATENÇÃO: Vulnerabilidades de segurança detectadas!${NC}"
    echo -e "${YELLOW}   Por favor, revise os erros acima e corrija antes de fazer deploy.${NC}"
fi

echo ""
echo -e "${BLUE}================================================${NC}"

# Desativar venv
deactivate

exit $TEST_EXIT_CODE
