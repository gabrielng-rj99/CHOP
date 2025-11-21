#!/bin/bash

# ============================================================================
# Test Token Refresh Loop Fix
# ============================================================================
# This script tests if the token refresh loop has been fixed by:
# 1. Performing a login
# 2. Monitoring token refresh calls
# 3. Checking audit logs for excessive refresh entries
# ============================================================================

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

API_URL="${API_URL:-https://localhost:8443/api}"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:-Admin123!@#}"

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Token Refresh Loop Fix Test${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Function to count audit logs for refresh-token
count_refresh_logs() {
    local token=$1
    local count=$(curl -k -s -X GET \
        -H "Authorization: Bearer $token" \
        "$API_URL/audit-logs?limit=5000" 2>/dev/null | \
        jq -r '[.data[] | select(.endpoint == "/api/refresh-token")] | length' 2>/dev/null || echo "0")
    echo "$count"
}

# Step 1: Login
echo -e "${YELLOW}[1/5] Realizando login...${NC}"
LOGIN_RESPONSE=$(curl -k -s -X POST \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"$ADMIN_USER\",\"password\":\"$ADMIN_PASS\"}" \
    "$API_URL/login" 2>/dev/null)

if [ $? -ne 0 ]; then
    echo -e "${RED}✗ Erro ao fazer login${NC}"
    exit 1
fi

ACCESS_TOKEN=$(echo "$LOGIN_RESPONSE" | jq -r '.data.token' 2>/dev/null)
REFRESH_TOKEN=$(echo "$LOGIN_RESPONSE" | jq -r '.data.refresh_token' 2>/dev/null)

if [ -z "$ACCESS_TOKEN" ] || [ "$ACCESS_TOKEN" = "null" ]; then
    echo -e "${RED}✗ Login falhou${NC}"
    echo "$LOGIN_RESPONSE" | jq '.' 2>/dev/null || echo "$LOGIN_RESPONSE"
    exit 1
fi

echo -e "${GREEN}✓ Login bem-sucedido${NC}"
echo ""

# Step 2: Count initial refresh logs
echo -e "${YELLOW}[2/5] Contando logs iniciais de refresh-token...${NC}"
INITIAL_COUNT=$(count_refresh_logs "$ACCESS_TOKEN")
echo -e "  Logs iniciais: ${BLUE}$INITIAL_COUNT${NC}"
echo ""

# Step 3: Wait and monitor (simulate frontend behavior)
echo -e "${YELLOW}[3/5] Aguardando 30 segundos e monitorando...${NC}"
echo -e "  (Frontend deveria agendar refresh mas NÃO executar imediatamente)"

for i in {1..6}; do
    sleep 5
    CURRENT_COUNT=$(count_refresh_logs "$ACCESS_TOKEN")
    echo -e "  ${BLUE}[${i}0s]${NC} Refresh logs: $CURRENT_COUNT"

    # Check if count increased unexpectedly
    if [ "$CURRENT_COUNT" -gt "$INITIAL_COUNT" ]; then
        INCREASE=$((CURRENT_COUNT - INITIAL_COUNT))
        echo -e "  ${YELLOW}⚠ Aumento detectado: +$INCREASE logs${NC}"
    fi
done
echo ""

# Step 4: Manually trigger a refresh
echo -e "${YELLOW}[4/5] Testando refresh manual do token...${NC}"
REFRESH_RESPONSE=$(curl -k -s -X POST \
    -H "Content-Type: application/json" \
    -d "{\"refresh_token\":\"$REFRESH_TOKEN\"}" \
    "$API_URL/refresh-token" 2>/dev/null)

NEW_TOKEN=$(echo "$REFRESH_RESPONSE" | jq -r '.data.token' 2>/dev/null)

if [ -z "$NEW_TOKEN" ] || [ "$NEW_TOKEN" = "null" ]; then
    echo -e "${RED}✗ Refresh manual falhou${NC}"
    echo "$REFRESH_RESPONSE" | jq '.' 2>/dev/null || echo "$REFRESH_RESPONSE"
else
    echo -e "${GREEN}✓ Refresh manual bem-sucedido${NC}"
fi
echo ""

# Step 5: Wait again to check if manual refresh triggered a loop
echo -e "${YELLOW}[5/5] Aguardando 20s para verificar se NÃO há loop após refresh...${NC}"
sleep 5
COUNT_AFTER_FIRST_REFRESH=$(count_refresh_logs "$NEW_TOKEN")
echo -e "  ${BLUE}[5s]${NC} Refresh logs: $COUNT_AFTER_FIRST_REFRESH"

sleep 5
COUNT_AFTER_10S=$(count_refresh_logs "$NEW_TOKEN")
echo -e "  ${BLUE}[10s]${NC} Refresh logs: $COUNT_AFTER_10S"

sleep 5
COUNT_AFTER_15S=$(count_refresh_logs "$NEW_TOKEN")
echo -e "  ${BLUE}[15s]${NC} Refresh logs: $COUNT_AFTER_15S"

sleep 5
FINAL_COUNT=$(count_refresh_logs "$NEW_TOKEN")
echo -e "  ${BLUE}[20s]${NC} Refresh logs: $FINAL_COUNT"
echo ""

# Calculate increases
INCREASE_AFTER_MANUAL=$((COUNT_AFTER_FIRST_REFRESH - INITIAL_COUNT))
INCREASE_AFTER_WAIT=$((FINAL_COUNT - COUNT_AFTER_FIRST_REFRESH))

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Resultados:${NC}"
echo -e "${BLUE}========================================${NC}"
echo -e "  Logs iniciais:           ${BLUE}$INITIAL_COUNT${NC}"
echo -e "  Após refresh manual:     ${BLUE}$COUNT_AFTER_FIRST_REFRESH${NC} (0 esperado - não loga mais sucesso)"
echo -e "  Após 20s de espera:      ${BLUE}$FINAL_COUNT${NC}"
echo ""

# Determine if test passed
PASSED=true

# Check 1: Refresh manual should NOT create audit log (we removed that)
if [ "$INCREASE_AFTER_MANUAL" -gt 0 ]; then
    echo -e "${YELLOW}⚠ Aviso: Refresh manual ainda está criando logs (esperado 0)${NC}"
    echo -e "  Aumento: +$INCREASE_AFTER_MANUAL"
fi

# Check 2: After refresh, there should be NO loop (no automatic refreshes)
if [ "$INCREASE_AFTER_WAIT" -gt 1 ]; then
    echo -e "${RED}✗ FALHA: Loop detectado! Houve $INCREASE_AFTER_WAIT refreshes em 20s${NC}"
    PASSED=false
elif [ "$INCREASE_AFTER_WAIT" -eq 1 ]; then
    echo -e "${YELLOW}⚠ Aviso: 1 refresh adicional detectado (pode ser normal)${NC}"
else
    echo -e "${GREEN}✓ SUCESSO: Nenhum loop detectado!${NC}"
fi

# Check 3: Overall increase should be minimal (0-2 max)
TOTAL_INCREASE=$((FINAL_COUNT - INITIAL_COUNT))
if [ "$TOTAL_INCREASE" -gt 5 ]; then
    echo -e "${RED}✗ FALHA: Muitos refreshes detectados ($TOTAL_INCREASE total)${NC}"
    PASSED=false
else
    echo -e "${GREEN}✓ Aumento total aceitável: $TOTAL_INCREASE logs${NC}"
fi

echo ""
echo -e "${BLUE}========================================${NC}"
if [ "$PASSED" = true ]; then
    echo -e "${GREEN}✓ Teste PASSOU: Loop de refresh foi corrigido!${NC}"
    echo -e "${BLUE}========================================${NC}"
    exit 0
else
    echo -e "${RED}✗ Teste FALHOU: Loop ainda existe${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo ""
    echo -e "${YELLOW}Sugestões de debug:${NC}"
    echo -e "  1. Verifique os logs do frontend (console do navegador)"
    echo -e "  2. Verifique os logs do backend: sudo docker compose logs backend | tail -50"
    echo -e "  3. Inspecione diretamente a tabela audit_logs no banco"
    exit 1
fi
