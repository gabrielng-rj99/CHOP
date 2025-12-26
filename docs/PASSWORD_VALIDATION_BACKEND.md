# Validações de Políticas de Senha - Backend

## Visão Geral

O backend implementa validações rigorosas para garantir que as políticas de senha sejam consistentes, seguras e aplicáveis. As validações ocorrem em **dois níveis**:

1. **Validação de Request** (entrada do API)
2. **Validação de Banco de Dados** (constraints SQL)

---

## Validações de Request (Go)

### Localização
`backend/server/role_password_handlers.go` - Função `HandleUpdateRolePasswordPolicy()`

### Campos e Ranges Validados

#### 1. **min_length** (Obrigatório)
```go
if policy.MinLength < 8 || policy.MinLength > 128 {
    return "Tamanho mínimo de senha deve estar entre 8 e 128 caracteres"
}
```
- **Range:** 8 a 128
- **Razão:** Abrange desde políticas leves (viewer) até rigorosas (root)
- **Padrão global:** 8 caracteres

#### 2. **max_length** (Opcional, padrão: 128)
```go
if policy.MaxLength != 0 && (policy.MaxLength < policy.MinLength || policy.MaxLength > 256) {
    return "Tamanho máximo deve ser maior que o mínimo e no máximo 256"
}
```
- **Range:** min_length até 256
- **Padrão:** 128
- **Razão:** Algumas senhas geradas podem exceder 128 (ex: passphrases)

#### 3. **max_age_days** (Opcional, padrão: 0)
```go
if policy.MaxAgeDays != nil && (*policy.MaxAgeDays < 0 || *policy.MaxAgeDays > 365) {
    return "Dias de expiração deve estar entre 0 e 365 (0 = nunca expira)"
}
```
- **Range:** 0 a 365
- **0 = nunca expira**
- **Razão:** Limita expiração a 1 ano máximo (NIST SP 800-63B)

#### 4. **history_count** (Opcional, padrão: 0)
```go
if policy.HistoryCount != nil && (*policy.HistoryCount < 0 || *policy.HistoryCount > 24) {
    return "Histórico de senhas deve estar entre 0 e 24"
}
```
- **Range:** 0 a 24
- **0 = não verifica histórico**
- **Razão:** Evita reutilização excessiva; 24 é limite prático

#### 5. **min_age_hours** (Opcional, padrão: 0)
```go
if policy.MinAgeHours != nil && (*policy.MinAgeHours < 0 || *policy.MinAgeHours > 720) {
    return "Intervalo mínimo de mudança deve estar entre 0 e 720 horas"
}
```
- **Range:** 0 a 720 (30 dias)
- **0 = pode trocar imediatamente**
- **Razão:** Previne abuse (trocar múltiplas vezes em minutos)

#### 6. **min_unique_chars** (Opcional, padrão: 0)
```go
if policy.MinUniqueChars != nil && (*policy.MinUniqueChars < 0 || *policy.MinUniqueChars > 64) {
    return "Caracteres únicos mínimos deve estar entre 0 e 64"
}
```
- **Range:** 0 a 64
- **0 = sem requisito**
- **Razão:** Evita senhas como "aaaaaaaa"

#### 7. **Booleanos** (require_uppercase, require_lowercase, require_numbers, require_special)
- Validados automaticamente pelo JSON decoder
- Pelo menos **1 requisito deve estar ativo** (regra recomendada, não é aplicada)

#### 8. **allowed_special_chars** (Opcional)
```go
// Se especificado, valida se são caracteres válidos
// Padrão: "!@#$%^&*()_+-=[]{}|;:,.<>?"
```
- Se vazio: aceita todos os especiais
- Se preenchido: deve conter caracteres válidos

#### 9. **description** (Opcional)
- Max 500 caracteres
- Apenas texto descritivo, sem validação especial

---

## Validações de Banco de Dados (SQL)

### Constraints da Tabela `role_password_policies`

```sql
CREATE TABLE role_password_policies (
    -- PK e FK
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    
    -- Campos de política
    min_length INTEGER NOT NULL DEFAULT 16,
    max_length INTEGER NOT NULL DEFAULT 128,
    -- ... outros campos ...
    
    -- Constraints
    UNIQUE(role_id)  -- Um role só pode ter uma política
);

CREATE INDEX idx_role_password_policies_active 
ON role_password_policies(is_active) 
WHERE is_active = TRUE;  -- Otimiza queries de política ativa
```

### Regras de Integridade

1. **UNIQUE(role_id):** Um role pode ter apenas UMA política personalizada
2. **NOT NULL role_id:** Toda política deve estar associada a um role
3. **Foreign Key:** Se role for deletado, política é deletada em cascata
4. **is_active:** Soft-delete (marca como inativo, não remove)

---

## Fluxo de Validação Completo

### Request: `PUT /api/roles/{role_id}/password-policy`

```
1. Autenticação
   ↓ Valida JWT
   ↓
2. Autorização
   ↓ Verifica se é ROOT (rootOnlyMiddleware)
   ↓
3. Parsing
   ↓ Decodifica JSON → RolePasswordPolicyRequest
   ↓
4. Validação de Negócio (Backend)
   ├─ min_length: 8-128?
   ├─ max_length: null ou > min_length?
   ├─ max_age_days: 0-365?
   ├─ history_count: 0-24?
   ├─ min_age_hours: 0-720?
   ├─ min_unique_chars: 0-64?
   └─ Role existe?
   ↓ Se erro → HTTP 400 com mensagem
   ↓
5. Verificação de Estado (BD)
   ├─ Busca role_id no banco
   ├─ Busca política anterior (para audit)
   └─ Se role não existe → HTTP 404
   ↓
6. Operação no BD
   ├─ INSERT com ON CONFLICT (role_id) para upsert
   ├─ Atualiza is_active = TRUE
   └─ Persiste em role_password_policies
   ↓
7. Auditoria
   ├─ Log operation: "update"
   ├─ old_value: política anterior (ou null)
   ├─ new_value: política enviada
   └─ admin_id, timestamp, IP, user_agent
   ↓
8. Resposta
   └─ HTTP 200 + política salva em JSON
```

---

## Exemplos de Validação

### Exemplo 1: Request Inválido (min_length muito pequeno)
```bash
curl -X PUT http://localhost:3000/api/roles/{id}/password-policy \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"min_length": 4}'
```

**Resposta:**
```json
{
  "error": "Tamanho mínimo de senha deve estar entre 8 e 128 caracteres"
}
```
**Status:** 400 Bad Request

---

### Exemplo 2: Request Inválido (max_length < min_length)
```bash
curl -X PUT http://localhost:3000/api/roles/{id}/password-policy \
  -d '{
    "min_length": 20,
    "max_length": 16
  }'
```

**Resposta:**
```json
{
  "error": "Tamanho máximo deve ser maior que o mínimo e no máximo 256"
}
```
**Status:** 400 Bad Request

---

### Exemplo 3: Request Inválido (history_count > 24)
```bash
curl -X PUT http://localhost:3000/api/roles/{id}/password-policy \
  -d '{
    "min_length": 12,
    "history_count": 50
  }'
```

**Resposta:**
```json
{
  "error": "Histórico de senhas deve estar entre 0 e 24"
}
```
**Status:** 400 Bad Request

---

### Exemplo 4: Role Não Existe
```bash
curl -X PUT http://localhost:3000/api/roles/99999999-9999-9999-9999-999999999999/password-policy \
  -d '{"min_length": 12}'
```

**Resposta:**
```json
{
  "error": "Role não encontrado"
}
```
**Status:** 404 Not Found

---

### Exemplo 5: Request Válido
```bash
curl -X PUT http://localhost:3000/api/roles/a0000000-0000-0000-0000-000000000001/password-policy \
  -d '{
    "min_length": 24,
    "max_length": 128,
    "require_uppercase": true,
    "require_lowercase": true,
    "require_numbers": true,
    "require_special": true,
    "max_age_days": 90,
    "history_count": 5,
    "min_age_hours": 24,
    "min_unique_chars": 12,
    "no_username_in_password": true,
    "no_common_passwords": true,
    "description": "Política para Root"
  }'
```

**Resposta:**
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
  "max_age_days": 90,
  "history_count": 5,
  "min_age_hours": 24,
  "min_unique_chars": 12,
  "no_username_in_password": true,
  "no_common_passwords": true,
  "description": "Política para Root",
  "is_active": true,
  "created_at": "2025-12-22T20:00:00Z",
  "updated_at": "2025-12-22T20:00:00Z"
}
```
**Status:** 200 OK

---

## Validações Ausentes (Futura Implementação)

### 1. Validação de Entropia (Informativa)
```go
// Futura: validar entropia mínima (ex: 90 bits recomendado)
entropy := float64(policy.MinLength) * math.Log2(charsetSize)
if entropy < 90 {
    log.Warn("Política com entropia baixa: %.2f bits", entropy)
    // Pode ser warning, não erro
}
```

### 2. Validação de Senha Comum
```go
// Quando no_common_passwords = true
// Validar contra lista NIST ou similar
if policy.NoCommonPasswords {
    // Verificar contra lista de senhas comuns (future)
}
```

### 3. Validação de Username em Senha
```go
// Quando no_username_in_password = true
// Precisaria do username do usuário para validar
// Isso é validado em CHANGE PASSWORD, não em política
```

---

## Estrutura de Resposta de Erro

Todos os erros de validação seguem este padrão:

```json
{
  "error": "Mensagem descritiva em Português"
}
```

| Campo | Tipo | Descrição |
|-------|------|-----------|
| `error` | string | Mensagem de erro clara e acionável |

---

## Mapeamento HTTP Status

| Status | Caso de Uso | Exemplo |
|--------|-----------|---------|
| **400** | Validação de negócio falhou | min_length < 8 |
| **401** | Token JWT inválido | Token expirado |
| **403** | Não é ROOT | Usuário é ADMIN |
| **404** | Role não existe | UUID inválido |
| **500** | Erro no servidor | Falha na query SQL |

---

## Testes Recomendados

### Unitários (Go)
```go
func TestValidateRolePasswordPolicy(t *testing.T) {
    tests := []struct {
        name    string
        policy  RolePasswordPolicyRequest
        wantErr string
    }{
        {"min_length too small", policy{MinLength: 4}, "8 e 128"},
        {"max_length too large", policy{MaxLength: 300}, "256"},
        {"max_age_days invalid", policy{MaxAgeDays: ptr(400)}, "0 e 365"},
        // ... mais testes ...
    }
}
```

### Integração (curl)
Veja `docs/ROLE_PASSWORD_POLICIES_API.md` - Seção "Cenários de Teste Manual"

---

## Notas de Implementação

1. **Validações são defensivas:** Se um valor não tem sentido, a API rejeita
2. **Mensagens são amigáveis:** Em Português, claras sobre o que está errado
3. **Nenhuma validação silenciosa:** Erros nunca são ignorados
4. **Auditoria completa:** Toda tentativa (sucesso ou falha) é registrada
5. **Princípio de menor privilégio:** Apenas ROOT pode modificar políticas