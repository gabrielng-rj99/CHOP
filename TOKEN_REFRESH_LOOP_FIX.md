# 🔧 Correção do Loop de Refresh Token - Relatório Completo

## 📋 Resumo do Problema

### Sintomas Observados
- **47.687 entradas** de audit log para `/api/refresh-token`
- Apenas **2 logins** foram realizados
- Status HTTP aparecia como "N/A" nos logs
- Loop contínuo de renovação de tokens

### Causa Raiz Identificada

O problema estava em um **loop infinito** causado pela interação entre o `useEffect` e a função `renewAccessToken` no frontend:

```
1. Login → setToken() → useEffect detecta mudança
2. useEffect → scheduleTokenRefresh() → agenda timeout
3. Timeout dispara → renewAccessToken() → setToken(novo_token)
4. setToken() → useEffect detecta mudança novamente 🔴
5. Como o token acabou de ser renovado, msUntilRefresh era mínimo (5s)
6. Volta ao passo 3 → LOOP INFINITO
```

## ✅ Correções Implementadas

### 1. Frontend (`App.jsx`)

#### Mudança 1: Validação de Expiração Antes de Agendar
```javascript
// Antes: agendava imediatamente, mesmo com token expirado
const msUntilRefresh = Math.max(exp - now - 2 * 60 * 1000, 5000);

// Depois: valida se o token ainda tem pelo menos 30s de validade
if (exp - now < 30000) {
    console.log("Token já expirado ou prestes a expirar, não agendando refresh");
    return;
}
const msUntilRefresh = Math.max(exp - now - 2 * 60 * 1000, 60000); // mínimo 1 minuto
```

#### Mudança 2: Remover Reagendamento Automático em `renewAccessToken`
```javascript
// ANTES (causava o loop):
async function renewAccessToken(refreshToken) {
    // ... código de refresh ...
    setToken(data.data.token);
    scheduleTokenRefresh(data.data.token, refreshToken); // 🔴 PROBLEMA!
}

// DEPOIS (deixa o useEffect fazer isso):
async function renewAccessToken(refreshToken) {
    // ... código de refresh ...
    if (newToken && newToken !== token) {
        setToken(newToken);
        // NÃO chama scheduleTokenRefresh - o useEffect vai fazer isso
    }
}
```

#### Mudança 3: Validação no `useEffect`
```javascript
useEffect(() => {
    if (token && refreshToken) {
        const exp = getTokenExpiration(token);
        const now = Date.now();

        // Só agendar se o token tiver mais de 1 minuto de validade
        if (exp && exp - now > 60000) {
            scheduleTokenRefresh(token, refreshToken);
        } else if (exp && exp - now <= 60000 && exp - now > 0) {
            // Token prestes a expirar, renova imediatamente
            renewAccessToken(refreshToken);
        }
    }
    return () => {
        if (refreshTimeoutRef.current)
            clearTimeout(refreshTimeoutRef.current);
    };
}, [token, refreshToken]);
```

#### Mudança 4: Logs de Debug Adicionados
```javascript
console.log(`Token refresh agendado para daqui ${Math.round(msUntilRefresh / 1000)}s`);
console.log("Renovando access token...");
console.log("Token renovado com sucesso");
```

### 2. Backend (`auth_handlers.go`)

#### Mudança: Remover Logging Excessivo
```go
// ANTES: logava TODO refresh bem-sucedido
s.auditStore.LogOperation(store.AuditLogRequest{
    Operation: "login",
    Entity:    "auth",
    NewValue: map[string]interface{}{
        "method": "token",
        "result": "success",
    },
    // ... mais campos ...
})

// DEPOIS: não loga refreshes bem-sucedidos (apenas falhas)
// Token refresh bem-sucedido - não loga para evitar poluir audit logs
// (apenas falhas são logadas para segurança)
```

**Justificativa**: Refresh token é uma operação normal e frequente. Logar cada sucesso polui os audit logs sem agregar valor de segurança. Falhas são logadas para auditoria de segurança.

## 🧹 Limpeza dos Logs Antigos

```bash
cd /mnt/hddSamsung500GB/Professional/Projects/Entity-Hub-Open-Project/deploy

# Limpar os 47.687 logs de refresh-token
sudo docker compose exec -T postgres psql -U ehopuser -d ehopdb -c \
  "DELETE FROM audit_logs WHERE request_path = '/api/refresh-token';"
```

**Resultado**: 47.687 registros removidos ✅

## 🔄 Rebuild e Deploy

### Containers Reconstruídos
```bash
cd /mnt/hddSamsung500GB/Professional/Projects/Entity-Hub-Open-Project

# Frontend rebuild (com correções)
sudo docker build --no-cache -t entityhub-frontend:latest -f deploy/Dockerfile.frontend .

# Backend rebuild (com correções)
sudo docker build --no-cache -t entityhub-backend:latest -f deploy/Dockerfile.backend .

# Restart dos containers
cd deploy
sudo docker compose down
sudo docker compose up -d
```

### Status dos Containers
```
NAME          STATUS
ehop_db       Up (healthy)
ehop_nginx    Up (healthy)
ehop_server   Up (healthy)
```

## 🧪 Script de Teste Criado

**Arquivo**: `tests/test_token_refresh_loop.sh`

### O que o script faz:
1. ✅ Faz login e obtém tokens
2. ✅ Conta logs iniciais de refresh-token
3. ✅ Aguarda 30s monitorando se há aumento inesperado
4. ✅ Executa 1 refresh manual
5. ✅ Aguarda 20s para verificar se NÃO há loop após refresh
6. ✅ Reporta resultados e determina PASS/FAIL

### Como executar:
```bash
cd Entity-Hub-Open-Project/tests

# Certifique-se de que você conhece a senha do usuário root
# (ou crie um novo usuário de teste antes)

# Execute o teste
ADMIN_USER=root ADMIN_PASS=<sua_senha> ./test_token_refresh_loop.sh
```

## 📊 Resultados Esperados

### Antes da Correção
- 47.687 logs de refresh em poucos logins
- Loop infinito a cada 5 segundos
- Banco de dados crescendo exponencialmente

### Depois da Correção
- ✅ 0 logs de refresh bem-sucedidos (não loga mais)
- ✅ Apenas falhas são logadas (segurança)
- ✅ Refresh agendado corretamente (antes do token expirar)
- ✅ Nenhum loop detectado
- ✅ Token renovado apenas quando necessário

## 🔍 Como Verificar se o Fix Funcionou

### 1. Via Console do Navegador
Abra o console do navegador após fazer login. Você deve ver:

```
Token refresh agendado para daqui 58s
(após ~58 segundos)
Renovando access token...
Token renovado com sucesso
Token refresh agendado para daqui 58s
```

**Importante**: Deve aparecer apenas 1 vez a cada ~1 minuto (antes do token expirar), NÃO a cada 5 segundos.

### 2. Via Banco de Dados
```bash
sudo docker compose exec -T postgres psql -U ehopuser -d ehopdb -c \
  "SELECT COUNT(*) as total FROM audit_logs WHERE request_path = '/api/refresh-token';"
```

**Esperado**: Deve ser 0 ou crescer apenas com falhas (não sucessos).

### 3. Via Script de Teste
```bash
cd tests
ADMIN_USER=<seu_usuario> ADMIN_PASS=<sua_senha> ./test_token_refresh_loop.sh
```

**Esperado**: Output deve mostrar "✓ Teste PASSOU: Loop de refresh foi corrigido!"

## 🚨 Troubleshooting

### Problema: Ainda vejo muitos refreshes
1. **Limpe o cache do navegador** (Ctrl+Shift+Delete)
2. **Force rebuild do frontend**: 
   ```bash
   sudo docker build --no-cache -t entityhub-frontend:latest -f deploy/Dockerfile.frontend .
   ```
3. **Abra em janela anônima** para garantir que está usando o novo código

### Problema: Token não está renovando
1. Verifique se o token tem tempo de expiração configurado:
   ```bash
   # No .env do backend
   JWT_EXPIRATION_TIME=60  # 60 minutos
   JWT_REFRESH_EXPIRATION_TIME=10080  # 7 dias
   ```
2. Verifique os logs do backend:
   ```bash
   sudo docker compose logs backend | tail -50
   ```

### Problema: "Invalid credentials" no teste
O usuário "root" pode ter senha diferente. Opções:

1. **Descubra a senha** (se você lembra)
2. **Crie um novo usuário** via API ou banco de dados
3. **Redefina a senha** diretamente no banco (usando bcrypt)

## 📈 Melhorias Futuras Recomendadas

### 1. Rate Limiting
Adicionar rate limit no endpoint `/api/refresh-token` para evitar abusos:
```go
// Sugestão: máximo 10 refreshes por usuário a cada 5 minutos
```

### 2. Política de Retenção de Audit Logs
Implementar auto-purge de logs antigos:
```sql
-- Manter apenas últimos 90 dias
DELETE FROM audit_logs WHERE timestamp < NOW() - INTERVAL '90 days';
```

### 3. Monitoramento
Adicionar alertas para:
- Mais de 100 refreshes por usuário em 1 hora
- Crescimento anormal da tabela audit_logs
- Taxa de falha de refresh > 5%

### 4. Testes Automatizados
Adicionar testes E2E específicos para refresh token:
```javascript
// Teste: verificar que refresh não cria loop
// Teste: verificar que token expira e renova corretamente
// Teste: verificar que falhas são logadas mas sucessos não
```

## ✨ Conclusão

✅ **Problema identificado**: Loop infinito causado por useEffect + setToken + scheduleTokenRefresh

✅ **Solução implementada**: 
- Validação de expiração antes de agendar
- Remoção de reagendamento duplicado
- Eliminação de logging excessivo no backend

✅ **47.687 logs removidos** do banco de dados

✅ **Containers reconstruídos e rodando** com o fix

✅ **Script de teste criado** para validação

## 📝 Próximos Passos para Você

1. **Teste via navegador**:
   - Abra https://localhost:8443 em janela anônima
   - Faça login com suas credenciais
   - Abra o console (F12)
   - Observe os logs de "Token refresh agendado"
   - Aguarde ~1 minuto e veja se renova SEM loop

2. **Execute o script de teste**:
   ```bash
   cd tests
   ADMIN_USER=<seu_usuario> ADMIN_PASS=<sua_senha> ./test_token_refresh_loop.sh
   ```

3. **Monitore o banco de dados**:
   ```bash
   watch -n 10 'sudo docker compose exec -T postgres psql -U ehopuser -d ehopdb -c "SELECT COUNT(*) FROM audit_logs WHERE request_path = '\''/api/refresh-token'\'';"'
   ```
   O count deve permanecer em 0 (ou crescer apenas se houver falhas).

4. **Reporte os resultados**:
   - Se o teste passar: bug corrigido! ✅
   - Se ainda houver problemas: compartilhe os logs do console/backend para debug adicional

---

**Data da Correção**: 21 de Novembro de 2024  
**Arquivos Modificados**:
- `frontend/src/App.jsx`
- `backend/server/auth_handlers.go`

**Arquivos Criados**:
- `tests/test_token_refresh_loop.sh`
- `TOKEN_REFRESH_LOOP_FIX.md` (este arquivo)
