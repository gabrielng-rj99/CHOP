# 🐛 BUGS CRÍTICOS ENCONTRADOS NOS TESTES DE SEGURANÇA

Data: 2025-11-17  
Projeto: Contract Manager - Backend

---

## 🔴 CRÍTICO #1: Conta Bloqueada Consegue Fazer Login

**Teste:** `TestAuthenticationFlows/Conta_bloqueada_não_deve_permitir_login`  
**Arquivo:** `backend/tests/security_auth_flows_test.go:142`  
**Status:** ❌ FALHOU

### Problema:
Usuário com `lock_level = 2` e `locked_until` no futuro conseguiu autenticar com sucesso.

### Impacto de Segurança:
**ALTO** - Brute force protection não está funcionando. Atacantes podem continuar tentando senhas mesmo após bloqueio.

### Localização do Bug:
`backend/server/auth_handlers.go` - função `handleLogin`

### Correção Necessária:
```go
// Adicionar ANTES da linha que chama s.userStore.AuthenticateUser:

if req.Username == "" || req.Password == "" {
    respondError(w, http.StatusBadRequest, "Username e senha são obrigatórios")
    return
}

user, err := s.userStore.AuthenticateUser(req.Username, req.Password)
if err != nil {
    respondError(w, http.StatusUnauthorized, "Invalid credentials")
    return
}

// ADICIONAR AQUI:
if user.LockLevel != nil && *user.LockLevel > 0 {
    if user.LockedUntil != nil && time.Now().Before(*user.LockedUntil) {
        respondError(w, http.StatusForbidden, "Conta temporariamente bloqueada")
        return
    }
}
```

---

## 🟡 MÉDIO #2: Validação de Campos Vazios Incorreta

**Testes Afetados:**
- `TestAuthenticationFlows/Login_com_username_vazio_deve_falhar`
- `TestAuthenticationFlows/Login_com_senha_vazia_deve_falhar`

**Status:** ❌ FALHARAM

### Problema:
Sistema retorna 401 (Unauthorized) para username/password vazios, quando deveria retornar 400 (Bad Request).

### Impacto:
**BAIXO** - Acesso ainda é bloqueado, mas mensagem de erro não é semântica correta.

### Correção:
```go
// Em handleLogin, logo após decode do JSON:
if req.Username == "" || req.Password == "" {
    respondError(w, http.StatusBadRequest, "Username e senha são obrigatórios")
    return
}
```

---

## 🟡 MÉDIO #3: Possível Vazamento de auth_secret

**Testes Afetados:**
- `TestDataLeakage/Auth_secret_não_deve_vazar_na_listagem_de_usuários`
- `TestTokenInSensitiveData/GET_/api/users_não_deve_vazar_auth_secret_ou_password_hash`

**Status:** ❌ FALHARAM

### Problema:
Alguns endpoints podem estar retornando `auth_secret` ou `password_hash` nas responses.

### Impacto de Segurança:
**ALTO** - Se auth_secret vazar, atacantes podem gerar tokens JWT válidos.

### Ação Necessária:
1. Revisar TODOS os handlers que retornam dados de usuário
2. Garantir que DTOs não incluem campos sensíveis
3. Adicionar testes unitários para cada DTO

### Endpoints a Revisar:
- `GET /api/users` - Lista de usuários
- `GET /api/users/:username` - Dados de um usuário
- `PUT /api/users/:username` - Atualização retorna dados

---

## 🟡 MÉDIO #4: Permissões de Audit Logs

**Teste:** `TestAuditLogPermissions/Admin_pode_acessar_audit_logs`  
**Status:** ❌ FALHOU

### Problema:
Teste espera que admin possa acessar audit logs, mas implementação só permite root.

### Ação Necessária:
**Decidir política de acesso:**

**Opção A:** Apenas root pode acessar (mais seguro)
- Corrigir teste para esperar 403 para admin
- Manter implementação atual

**Opção B:** Admin e root podem acessar
- Alterar `backend/server/routes.go`
- Mudar verificação de `role != "root"` para `role != "root" && role != "admin"`

---

## 📋 RESUMO DE AÇÕES

### Prioridade IMEDIATA:
- [ ] Corrigir bug #1 (conta bloqueada)
- [ ] Revisar vazamento de dados (bug #3)

### Prioridade ALTA:
- [ ] Corrigir validação de campos vazios (bug #2)
- [ ] Definir política de audit logs (bug #4)

### Após Correções:
- [ ] Executar `./run_security_tests.sh` novamente
- [ ] Validar que todos os testes passam
- [ ] Deploy em staging para teste manual
- [ ] Deploy em produção

---

**Gerado automaticamente em:** 2025-11-17 01:52:24  
**Comando para reexecutar:** `cd backend && ./run_security_tests.sh`
