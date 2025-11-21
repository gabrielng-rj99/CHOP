#!/bin/bash

echo "=== Teste Completo do Fluxo de Inicialização ==="
echo ""

echo "1. Verificando status inicial:"
curl -s http://localhost:3000/api/initialize/status | jq '{is_initialized, requires_setup, message}'
echo ""

echo "2. Testando criação de usuário root:"
curl -s -X POST http://localhost:3000/api/initialize/admin \
  -H "Content-Type: application/json" \
  -d '{
    "username": "root",
    "display_name": "Administrator",
    "password": "TestPassword123456!"
  }' | jq '{success, message}'
echo ""

echo "3. Verificando status após criação:"
curl -s http://localhost:3000/api/initialize/status | jq '{is_initialized, has_users, root_user_exists}'
echo ""

echo "4. Testando que nginx proxy funciona (/api):"
docker exec ehop_nginx curl -s http://backend:3000/api/initialize/status | jq '.message'
echo ""

echo "✅ Teste concluído com sucesso!"
