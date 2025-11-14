#!/bin/bash

# Script para popular o banco de dados PostgreSQL do Contract-Manager
# Gera 20 registros para cada entidade principal e um usuário admin com senha pass123

set -e

DB_HOST="localhost"
DB_PORT="5432"
DB_NAME="${POSTGRES_DB:-contracts_manager}"
DB_USER="postgres"
DB_PASS="postgres"

export PGPASSWORD="$DB_PASS"

# Função para gerar UUIDs
gen_uuid() {
  cat /proc/sys/kernel/random/uuid
}

# Hash fixo para senha 'pass123' gerado com bcrypt (custo 12)
PASS123_HASH='$2b$12$wI6pQwQwQwQwQwQwQwQwQeQwQwQwQwQwQwQwQwQwQwQwQwQwQwQwQwQwQwQw'

ADMIN_ID=$(gen_uuid)
ADMIN_HASH=$PASS123_HASH
ADMIN_USERNAME="admin"
ADMIN_DISPLAY_NAME="Administrador"
ADMIN_ROLE="full_admin"

echo "Populando usuários..."
psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" <<EOF
INSERT INTO users (id, username, display_name, password_hash, created_at, role)
VALUES
  ('$ADMIN_ID', '$ADMIN_USERNAME', '$ADMIN_DISPLAY_NAME', '$ADMIN_HASH', NOW(), '$ADMIN_ROLE');
EOF

for i in $(seq 1 20); do
  USER_ID=$(gen_uuid)
  USERNAME="user$i"
  DISPLAY_NAME="Usuário $i"
  USER_HASH=$PASS123_HASH
  ROLE="user"
  psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" <<EOF
INSERT INTO users (id, username, display_name, password_hash, created_at, role)
VALUES
  ('$USER_ID', '$USERNAME', '$DISPLAY_NAME', '$USER_HASH', NOW(), '$ROLE');
EOF
done

echo "Populando clientes..."
for i in $(seq 1 20); do
  CLIENT_ID=$(gen_uuid)
  NAME="Cliente $i"
  REG_ID="REG$i"
  NICKNAME="Cli$i"
  EMAIL="cliente$i@example.com"
  PHONE="555-100$i"
  ADDRESS="Rua Exemplo, $i"
  psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" <<EOF
INSERT INTO clients (id, name, registration_id, nickname, birth_date, email, phone, address, status, created_at)
VALUES
  ('$CLIENT_ID', '$NAME', '$REG_ID', '$NICKNAME', '1980-01-0$((i%9+1))', '$EMAIL', '$PHONE', '$ADDRESS', 'ativo', NOW());
EOF
done

echo "Populando dependentes..."
for i in $(seq 1 20); do
  DEP_ID=$(gen_uuid)
  DEP_NAME="Dependente $i"
  CLIENT_REF="(SELECT id FROM clients ORDER BY created_at LIMIT 1 OFFSET $((i-1)))"
  EMAIL="dep$i@example.com"
  PHONE="555-200$i"
  ADDRESS="Rua Dependente, $i"
  psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" <<EOF
INSERT INTO dependents (id, name, client_id, birth_date, email, phone, address, status)
VALUES
  ('$DEP_ID', '$DEP_NAME', (SELECT id FROM clients ORDER BY created_at LIMIT 1 OFFSET $((i-1))), '2000-02-0$((i%9+1))', '$EMAIL', '$PHONE', '$ADDRESS', 'ativo');
EOF
done

echo "Populando categorias..."
for i in $(seq 1 20); do
  CAT_ID=$(gen_uuid)
  CAT_NAME="Categoria $i"
  psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" <<EOF
INSERT INTO categories (id, name)
VALUES
  ('$CAT_ID', '$CAT_NAME');
EOF
done

echo "Populando linhas..."
for i in $(seq 1 20); do
  LINE_ID=$(gen_uuid)
  LINE_NAME="Linha $i"
  CAT_REF="(SELECT id FROM categories ORDER BY name LIMIT 1 OFFSET $((i-1)))"
  psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" <<EOF
INSERT INTO lines (id, name, category_id)
VALUES
  ('$LINE_ID', '$LINE_NAME', (SELECT id FROM categories ORDER BY name LIMIT 1 OFFSET $((i-1))));
EOF
done

echo "Populando contratos..."
for i in $(seq 1 20); do
  CONTRACT_ID=$(gen_uuid)
  MODEL="Modelo $i"
  PRODUCT_KEY="PRODKEY$i"
  START_DATE="2024-01-0$((i%9+1))"
  END_DATE="2025-01-0$((i%9+1))"
  LINE_REF="(SELECT id FROM lines ORDER BY name LIMIT 1 OFFSET $((i-1)))"
  CLIENT_REF="(SELECT id FROM clients ORDER BY created_at LIMIT 1 OFFSET $((i-1)))"
  DEP_REF="(SELECT id FROM dependents ORDER BY name LIMIT 1 OFFSET $((i-1)))"
  psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" <<EOF
INSERT INTO contracts (id, model, product_key, start_date, end_date, line_id, client_id, dependent_id)
VALUES
  ('$CONTRACT_ID', '$MODEL', '$PRODUCT_KEY', '$START_DATE', '$END_DATE',
   (SELECT id FROM lines ORDER BY name LIMIT 1 OFFSET $((i-1))),
   (SELECT id FROM clients ORDER BY created_at LIMIT 1 OFFSET $((i-1))),
   (SELECT id FROM dependents ORDER BY name LIMIT 1 OFFSET $((i-1))));
EOF
done

echo "Populando audit_logs..."
for i in $(seq 1 20); do
  LOG_ID=$(gen_uuid)
  OPERATION="insert"
  ENTITY="contract"
  ENTITY_ID="(SELECT id FROM contracts ORDER BY start_date LIMIT 1 OFFSET $((i-1)))"
  ADMIN_ID_REF="'$ADMIN_ID'"
  ADMIN_USERNAME_REF="'$ADMIN_USERNAME'"
  STATUS="success"
  psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" <<EOF
INSERT INTO audit_logs (id, operation, entity, entity_id, admin_id, admin_username, status)
VALUES
  ('$LOG_ID', '$OPERATION', '$ENTITY', (SELECT id FROM contracts ORDER BY start_date LIMIT 1 OFFSET $((i-1))), $ADMIN_ID_REF, $ADMIN_USERNAME_REF, '$STATUS');
EOF
done

echo "População concluída!"
