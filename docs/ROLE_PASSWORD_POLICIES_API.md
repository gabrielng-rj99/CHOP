# Role Password Policies API

Esta documentação descreve a API de políticas de senha por role (papel/função), incluindo exemplos de requisições para testes manuais.

## Visão Geral

O sistema permite configurar políticas de senha específicas para cada role, permitindo requisitos mais rigorosos para funções privilegiadas (como root e admin) e requisitos mais leves para funções com menos acesso (como viewer).

**Prioridade de aplicação:**
1. Política específica do role (se existir e estiver ativa)
2. Configurações globais de `system_settings`
3. Valores padrão do sistema (fallback)

## Política Global Padrão

A política global padrão aplica-se a todos os roles que **não possuem política personalizada**:

```json
{
  "min_length": 8,
  "max_length": 128,
  "require_uppercase": true,
  "require_lowercase": true,
  "require_numbers": true,
  "require_special": true,
  "max_age_days": 0,
  "history_count": 0,
  "min_age_hours": 0,
  "min_unique_chars": 0,
  "no_username_in_password": true,
  "no_common_passwords": true
}
```

**Entropia resultante:** `8 × log₂(94) ≈ 52 bits` (Básica)

> **Nota:** A entropia é uma métrica informativa calculada como `min_length × log₂(charset_size)`. Ver `docs/PASSWORD_ENTROPY.md` para detalhes completos sobre cálculo de entropia.

## Autenticação

Todas as rotas requerem autenticação via Bearer token JWT. Apenas usuários **root** podem gerenciar políticas de senha.

```bash
# Header de autenticação
Authorization: Bearer <seu_token_jwt>
```

---

## Endpoints

### 1. Listar Todas as Políticas de Senha

**GET** `/api/roles/password-policies`

Lista todas as políticas de senha de todos os roles (incluindo roles sem política personalizada).

#### Requisição

```bash
curl -X GET http://localhost:8080/api/roles/password-policies \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json"
```

#### Resposta de Sucesso (200)

```json
[
  {
    "id": "550e8400-e29b-41d4-a716-446655440001",
    "role_id": "a0000000-0000-0000-0000-000000000001",
    "role_name": "root",
    "min_length": 24,
    "max_length": 128,
    "require_uppercase": true,
    "require_lowercase": true,
    "require_numbers": true,
    "require_special": true,
    "allowed_special_chars": "!@#$%^&*()_+-=[]{}|;:,.<>?",
    "max_age_days": 90,
    "history_count": 5,
    "min_age_hours": 24,
    "min_unique_chars": 12,
    "no_username_in_password": true,
    "no_common_passwords": true,
    "description": "Política de senha para Super Administradores (root). Máxima segurança requerida.",
    "is_active": true
  },
  {
    "id": "550e8400-e29b-41d4-a716-446655440004",
    "role_id": "a0000000-0000-0000-0000-000000000004",
    "role_name": "viewer",
    "min_length": 8,
    "max_length": 128,
    "require_uppercase": true,
    "require_lowercase": true,
    "require_numbers": false,
    "require_special": false,
    "max_age_days": 0,
    "history_count": 0,
    "min_age_hours": 0,
    "min_unique_chars": 4,
    "no_username_in_password": true,
    "no_common_passwords": true,
    "is_active": true
  }
]
```

> **Nota:** Roles sem política personalizada retornam `is_active: false` e `id: ""`, indicando que usam as configurações globais.

---

### 2. Obter Política de Senha de um Role

**GET** `/api/roles/{role_id}/password-policy`

Obtém a política de senha de um role específico.

#### Requisição

```bash
# Obter política do role root
curl -X GET http://localhost:8080/api/roles/a0000000-0000-0000-0000-000000000001/password-policy \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json"
```

#### Resposta de Sucesso (200)

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440001",
  "role_id": "a0000000-0000-0000-0000-000000000001",
  "role_name": "root",
  "min_length": 24,
  "max_length": 128,
  "require_uppercase": true,
  "require_lowercase": true,
  "require_numbers": true,
  "require_special": true,
  "allowed_special_chars": "!@#$%^&*()_+-=[]{}|;:,.<>?",
  "max_age_days": 90,
  "history_count": 5,
  "min_age_hours": 24,
  "min_unique_chars": 12,
  "no_username_in_password": true,
  "no_common_passwords": true,
  "description": "Política de senha para Super Administradores (root). Máxima segurança requerida.",
  "is_active": true,
  "created_at": "2025-01-15T10:30:00Z",
  "updated_at": "2025-01-15T14:20:00Z"
}
```

#### Resposta para Role sem Política Personalizada (200)

Se o role não tiver uma política personalizada, retorna valores padrão indicando uso das configurações globais:

```json
{
  "id": "",
  "role_id": "a0000000-0000-0000-0000-000000custom1",
  "role_name": "custom_role",
  "min_length": 16,
  "max_length": 128,
  "require_uppercase": true,
  "require_lowercase": true,
  "require_numbers": true,
  "require_special": true,
  "allowed_special_chars": "!@#$%^&*()_+-=[]{}|;:,.<>?",
  "max_age_days": 0,
  "history_count": 0,
  "min_age_hours": 0,
  "min_unique_chars": 0,
  "no_username_in_password": true,
  "no_common_passwords": true,
  "is_active": false
}
```

> **Nota:** `is_active: false` com `id: ""` indica que o role não possui política específica e usará as configurações globais de `system_settings`.

#### Erros

| Código | Mensagem | Descrição |
|--------|----------|-----------|
| 401 | Token inválido ou expirado | Token JWT inválido |
| 403 | Apenas root pode gerenciar políticas de senha | Usuário não é root |
| 404 | Role não encontrado | UUID do role não existe |

---

### 3. Criar/Atualizar Política de Senha

**PUT** `/api/roles/{role_id}/password-policy`

Cria ou atualiza a política de senha de um role.

#### Campos do Request

| Campo | Tipo | Obrigatório | Descrição |
|-------|------|-------------|-----------|
| `min_length` | int | Sim | Tamanho mínimo (8-128) |
| `max_length` | int | Não | Tamanho máximo (até 256, default: 128) |
| `require_uppercase` | bool | Não | Exigir maiúsculas (A-Z) |
| `require_lowercase` | bool | Não | Exigir minúsculas (a-z) |
| `require_numbers` | bool | Não | Exigir números (0-9) |
| `require_special` | bool | Não | Exigir caracteres especiais |
| `allowed_special_chars` | string | Não | Caracteres especiais permitidos |
| `max_age_days` | int | Não | Dias até expirar (0 = nunca, 0-365) |
| `history_count` | int | Não | Senhas no histórico (0 = não verificar, 0-24) |
| `min_age_hours` | int | Não | Horas mínimas entre mudanças (0-720) |
| `min_unique_chars` | int | Não | Caracteres únicos mínimos (0-64) |
| `no_username_in_password` | bool | Não | Bloquear username na senha |
| `no_common_passwords` | bool | Não | Verificar senhas comuns |
| `description` | string | Não | Descrição da política |

#### Requisição - Criar Política Rigorosa (Root)

```bash
curl -X PUT http://localhost:8080/api/roles/a0000000-0000-0000-0000-000000000001/password-policy \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "min_length": 24,
    "max_length": 128,
    "require_uppercase": true,
    "require_lowercase": true,
    "require_numbers": true,
    "require_special": true,
    "allowed_special_chars": "!@#$%^&*()_+-=[]{}|;:,.<>?",
    "max_age_days": 90,
    "history_count": 5,
    "min_age_hours": 24,
    "min_unique_chars": 12,
    "no_username_in_password": true,
    "no_common_passwords": true,
    "description": "Política de senha para Super Administradores. Máxima segurança."
  }'
```

#### Requisição - Criar Política Moderada (User)

```bash
curl -X PUT http://localhost:8080/api/roles/a0000000-0000-0000-0000-000000000003/password-policy \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "min_length": 12,
    "max_length": 128,
    "require_uppercase": true,
    "require_lowercase": true,
    "require_numbers": true,
    "require_special": false,
    "max_age_days": 365,
    "history_count": 0,
    "min_age_hours": 0,
    "min_unique_chars": 6,
    "no_username_in_password": true,
    "no_common_passwords": true,
    "description": "Política de senha para usuários comuns. Segurança moderada."
  }'
```

#### Requisição - Criar Política Básica (Viewer)

```bash
curl -X PUT http://localhost:8080/api/roles/a0000000-0000-0000-0000-000000000004/password-policy \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "min_length": 8,
    "max_length": 128,
    "require_uppercase": true,
    "require_lowercase": true,
    "require_numbers": false,
    "require_special": false,
    "max_age_days": 0,
    "history_count": 0,
    "min_age_hours": 0,
    "min_unique_chars": 4,
    "no_username_in_password": true,
    "no_common_passwords": true,
    "description": "Política de senha para visualizadores. Segurança básica."
  }'
```

#### Resposta de Sucesso (200)

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440002",
  "role_id": "a0000000-0000-0000-0000-000000000003",
  "role_name": "user",
  "min_length": 12,
  "max_length": 128,
  "require_uppercase": true,
  "require_lowercase": true,
  "require_numbers": true,
  "require_special": false,
  "max_age_days": 365,
  "history_count": 0,
  "min_age_hours": 0,
  "min_unique_chars": 6,
  "no_username_in_password": true,
  "no_common_passwords": true,
  "description": "Política de senha para usuários comuns. Segurança moderada.",
  "is_active": true
}
```

#### Erros de Validação

| Código | Mensagem | Causa |
|--------|----------|-------|
| 400 | Tamanho mínimo de senha deve estar entre 8 e 128 caracteres | `min_length` fora do range |
| 400 | Tamanho máximo de senha deve ser maior que o mínimo e no máximo 256 | `max_length` inválido |
| 400 | Dias de expiração deve estar entre 0 e 365 | `max_age_days` fora do range |
| 400 | Histórico de senhas deve estar entre 0 e 24 | `history_count` fora do range |
| 400 | Intervalo mínimo de mudança deve estar entre 0 e 720 horas | `min_age_hours` fora do range |
| 400 | Caracteres únicos mínimos deve estar entre 0 e 64 | `min_unique_chars` fora do range |

---

### 4. Remover Política de Senha (Usar Global)

**DELETE** `/api/roles/{role_id}/password-policy`

Remove a política personalizada de um role, fazendo-o usar as configurações globais.

#### Requisição

```bash
# Exemplo: remover política do role user para que use configuração global
curl -X DELETE http://localhost:8080/api/roles/a0000000-0000-0000-0000-000000000003/password-policy \
  -H "Authorization: Bearer <token>"
```

#### Resposta de Sucesso (200)

```json
{
  "message": "Política de senha removida com sucesso. O role usará as configurações globais."
}
```

#### Erros

| Código | Mensagem | Descrição |
|--------|----------|-----------|
| 404 | Role não encontrado | UUID do role não existe |
| 404 | Política de senha não encontrada para este role | Role não tem política personalizada |

---

## Cenários de Teste Manual

### Cenário 1: Fluxo Completo de CRUD

```bash
# 1. Obter token de autenticação como root
TOKEN=$(curl -s -X POST http://localhost:8080/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "sua_senha_root"}' | jq -r '.token')

# 2. Listar todas as políticas
curl -s http://localhost:8080/api/roles/password-policies \
  -H "Authorization: Bearer $TOKEN" | jq

# 3. Obter política específica do role admin
curl -s http://localhost:8080/api/roles/a0000000-0000-0000-0000-000000000002/password-policy \
  -H "Authorization: Bearer $TOKEN" | jq

# 4. Criar/atualizar política para o role admin
curl -s -X PUT http://localhost:8080/api/roles/a0000000-0000-0000-0000-000000000002/password-policy \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "min_length": 16,
    "require_uppercase": true,
    "require_lowercase": true,
    "require_numbers": true,
    "require_special": true,
    "max_age_days": 180,
    "history_count": 3,
    "min_age_hours": 1,
    "no_username_in_password": true,
    "no_common_passwords": true,
    "description": "Política atualizada para Admin"
  }' | jq

# 5. Verificar a política atualizada
curl -s http://localhost:8080/api/roles/a0000000-0000-0000-0000-000000000002/password-policy \
  -H "Authorization: Bearer $TOKEN" | jq

# 6. Remover política (voltar para global)
curl -s -X DELETE http://localhost:8080/api/roles/a0000000-0000-0000-0000-000000000002/password-policy \
  -H "Authorization: Bearer $TOKEN" | jq

# 7. Verificar que voltou ao padrão
curl -s http://localhost:8080/api/roles/a0000000-0000-0000-0000-000000000002/password-policy \
  -H "Authorization: Bearer $TOKEN" | jq
```

### Cenário 2: Teste de Validação

```bash
# Teste com min_length muito pequeno (deve falhar)
curl -s -X PUT http://localhost:8080/api/roles/a0000000-0000-0000-0000-000000000003/password-policy \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"min_length": 4}' | jq

# Teste com max_age_days inválido (deve falhar)
curl -s -X PUT http://localhost:8080/api/roles/a0000000-0000-0000-0000-000000000003/password-policy \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"min_length": 12, "max_age_days": 500}' | jq

# Teste com max_length menor que min_length (deve falhar)
curl -s -X PUT http://localhost:8080/api/roles/a0000000-0000-0000-0000-000000000003/password-policy \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"min_length": 20, "max_length": 16}' | jq
```

### Cenário 3: Teste de Permissões

```bash
# Obter token como usuário não-root (ex: admin)
ADMIN_TOKEN=$(curl -s -X POST http://localhost:8080/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin_user", "password": "admin_password"}' | jq -r '.token')

# Tentar listar políticas (deve retornar 403 se não for root)
curl -s http://localhost:8080/api/roles/password-policies \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq

# Tentar criar política (deve retornar 403 se não for root)
curl -s -X PUT http://localhost:8080/api/roles/a0000000-0000-0000-0000-000000000003/password-policy \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"min_length": 12}' | jq
```

### Cenário 4: Teste de Role Inexistente

```bash
# Tentar obter política de role que não existe
curl -s http://localhost:8080/api/roles/99999999-9999-9999-9999-999999999999/password-policy \
  -H "Authorization: Bearer $TOKEN" | jq

# Tentar criar política para role inexistente
curl -s -X PUT http://localhost:8080/api/roles/99999999-9999-9999-9999-999999999999/password-policy \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"min_length": 12}' | jq
```

---

## UUIDs dos Roles Padrão

| Role | UUID | Descrição |
|------|------|-----------|
| root | `a0000000-0000-0000-0000-000000000001` | Super Administrador |
| admin | `a0000000-0000-0000-0000-000000000002` | Administrador |
| user | `a0000000-0000-0000-0000-000000000003` | Usuário Padrão |
| viewer | `a0000000-0000-0000-0000-000000000004` | Visualizador (somente leitura) |

> **Nota:** Roles personalizados podem ser criados via interface administrativa e terão UUIDs gerados automaticamente.

---

## Recomendações de Segurança por Role

| Role | Min Length | Expiração | Histórico | Especiais |
|------|------------|-----------|-----------|-----------|
| **root** | 24 chars | 90 dias | 5 senhas | Obrigatório |
| **admin** | 16 chars | 180 dias | 3 senhas | Obrigatório |
| **user** | 12 chars | 365 dias | Opcional | Opcional |
| **viewer** | 8 chars | Nunca | Não | Opcional |

---

## Auditoria

Todas as operações (criar, atualizar, deletar) são registradas no log de auditoria com:
- ID do administrador que executou a ação
- Valores antigos e novos
- IP de origem
- User-Agent
- Timestamp

Para consultar o histórico de alterações:

```bash
curl -s "http://localhost:8080/api/audit-logs?entity=role_password_policy" \
  -H "Authorization: Bearer $TOKEN" | jq
```
