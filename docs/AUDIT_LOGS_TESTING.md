# Guia de Testes - Sistema de Auditoria

## Pré-Requisitos

- Backend compilado e rodando em http://localhost:3000
- PostgreSQL com banco de dados inicializado
- Frontend rodando em modo desenvolvimento
- Um usuário com role `root` para testar acesso

---

## 1. Testes de Backend

### 1.1 Verificar Soft-Delete de Usuários

**Teste SQL:**
```sql
-- Antes de deletar
SELECT id, username, deleted_at FROM users WHERE username = 'test_user';

-- Deletar via API
-- DELETE /api/users/test_user (como root)

-- Depois de deletar
SELECT id, username, deleted_at, password_hash, role 
FROM users WHERE username IS NULL 
ORDER BY deleted_at DESC LIMIT 1;

-- Verificar que:
-- ✅ deleted_at está preenchido (NOT NULL)
-- ✅ username é NULL
-- ✅ password_hash é NULL
-- ✅ role é NULL
```

### 1.2 Verificar Soft-Delete Não Quebra FK

**Teste SQL:**
```sql
-- Buscar log que registrou a deleção
SELECT * FROM audit_logs 
WHERE operation = 'delete' 
AND entity = 'user'
ORDER BY timestamp DESC LIMIT 1;

-- Verificar que:
-- ✅ admin_id ainda aponta para um UUID válido (mesmo que o user foi deletado)
-- ✅ Não há erro de FK constraint
```

### 1.3 Testar LogOperation() - CREATE

**Teste via cURL:**
```bash
# Criar um novo usuário
curl -X POST http://localhost:3000/api/users \
  -H "Authorization: Bearer <token_root>" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "test_create_user",
    "display_name": "Test Create User",
    "password": "SecurePassword123!@#",
    "role": "user"
  }'

# Verificar no banco
SELECT * FROM audit_logs 
WHERE entity = 'user' 
AND operation = 'create'
ORDER BY timestamp DESC LIMIT 1;

# Verificar que:
# ✅ operation = 'create'
# ✅ status = 'success'
# ✅ old_value é NULL
# ✅ new_value contém dados do novo user
# ✅ admin_id está preenchido
# ✅ timestamp é recente
# ✅ ip_address está preenchido
# ✅ user_agent está preenchido
```

### 1.4 Testar LogOperation() - UPDATE

**Teste via cURL:**
```bash
# Atualizar um usuário (ex: display_name)
curl -X PUT http://localhost:3000/api/users/test_user \
  -H "Authorization: Bearer <token_root>" \
  -H "Content-Type: application/json" \
  -d '{
    "display_name": "Updated Display Name",
    "password": "NewPassword456!@#"
  }'

# Verificar no banco
SELECT operation, old_value, new_value, status 
FROM audit_logs 
WHERE entity = 'user' 
AND operation = 'update'
ORDER BY timestamp DESC LIMIT 1;

# Verificar que:
# ✅ operation = 'update'
# ✅ old_value contém dados antigos
# ✅ new_value contém dados novos
# ✅ status = 'success'
```

### 1.5 Testar Filtros - GET /api/audit-logs

**Teste 1: Filtrar por entity**
```bash
curl "http://localhost:3000/api/audit-logs?entity=user&limit=10" \
  -H "Authorization: Bearer <token_root>"

# Verificar resposta:
# ✅ data é um array
# ✅ Todos os items têm entity = 'user'
# ✅ total está preenchido
```

**Teste 2: Filtrar por operation**
```bash
curl "http://localhost:3000/api/audit-logs?operation=delete&limit=10" \
  -H "Authorization: Bearer <token_root>"

# Verificar resposta:
# ✅ data é um array
# ✅ Todos os items têm operation = 'delete'
```

**Teste 3: Filtrar por date range**
```bash
curl "http://localhost:3000/api/audit-logs?start_date=2024-01-01T00:00:00Z&end_date=2024-12-31T23:59:59Z" \
  -H "Authorization: Bearer <token_root>"

# Verificar resposta:
# ✅ Todos os timestamps estão no range
```

**Teste 4: Filtrar por status**
```bash
curl "http://localhost:3000/api/audit-logs?status=error&limit=10" \
  -H "Authorization: Bearer <token_root>"

# Verificar resposta:
# ✅ Todos os items têm status = 'error'
# ✅ error_message está preenchido para cada um
```

**Teste 5: Filtrar por IP**
```bash
curl "http://localhost:3000/api/audit-logs?ip_address=192.168.1.100&limit=10" \
  -H "Authorization: Bearer <token_root>"

# Verificar resposta:
# ✅ Todos os items têm ip_address = '192.168.1.100'
```

### 1.6 Testar GET /api/audit-logs/{id}

```bash
# Buscar um log específico
curl "http://localhost:3000/api/audit-logs/550e8400-e29b-41d4-a716-446655440000" \
  -H "Authorization: Bearer <token_root>"

# Verificar resposta:
# ✅ Retorna um objeto (não array)
# ✅ id está preenchido
# ✅ Todos os 16 campos estão presentes
```

### 1.7 Testar Autenticação e Autorização

**Teste 1: Sem token**
```bash
curl "http://localhost:3000/api/audit-logs"

# Esperado: 401 Unauthorized
```

**Teste 2: Token inválido**
```bash
curl "http://localhost:3000/api/audit-logs" \
  -H "Authorization: Bearer invalid_token"

# Esperado: 401 Unauthorized
```

**Teste 3: Token válido mas não root**
```bash
curl "http://localhost:3000/api/audit-logs" \
  -H "Authorization: Bearer <token_user_normal>"

# Esperado: 403 Forbidden
```

**Teste 4: Token válido e root**
```bash
curl "http://localhost:3000/api/audit-logs" \
  -H "Authorization: Bearer <token_root>"

# Esperado: 200 OK com dados
```

### 1.8 Testar IP Extraction

**Setup:**
1. Faça requisição com header `X-Forwarded-For: 10.0.0.1`
2. Ou com header `X-Real-IP: 10.0.0.2`
3. Ou com RemoteAddr normal

**Verificar no banco:**
```sql
SELECT ip_address FROM audit_logs 
ORDER BY timestamp DESC LIMIT 3;

-- Deve conter os IPs que você enviou
```

---

## 2. Testes de Frontend

### 2.1 Menu e Acesso

**Teste 1: User Normal não vê menu**
```
1. Login com user comum (role = 'user')
2. Verificar que menu NÃO tem "Logs de Auditoria"
```

**Teste 2: Admin vê menu**
```
1. Login com admin (role = 'admin')
2. Verificar que menu NÃO tem "Logs de Auditoria"
```

**Teste 3: Root vê menu**
```
1. Login com root
2. Verificar que menu TEM "Logs de Auditoria"
3. Clicar no menu
4. Verificar que página carrega sem erros
```

### 2.2 Renderização da Página

**Teste 1: Componentes aparecem**
```
1. Acessar /audit-logs como root
2. Verificar que aparecem:
   - ✅ Título "Logs de Auditoria"
   - ✅ Botão "Atualizar"
   - ✅ Botão "Exportar JSON"
   - ✅ Seção "Filtros Avançados"
   - ✅ Tabela com logs
   - ✅ Paginação (se houver dados)
```

**Teste 2: Tabela renderiza**
```
1. Se há dados no banco
2. Verificar colunas:
   - ✅ Timestamp
   - ✅ Operação (com cores)
   - ✅ Entidade
   - ✅ Admin
   - ✅ Status (com cores)
   - ✅ IP Address
   - ✅ Botão Detalhes
```

**Teste 3: Cores corretas**
```
Operações:
- ✅ create = verde
- ✅ update = laranja
- ✅ delete = vermelho
- ✅ read = azul

Status:
- ✅ success = verde
- ✅ error = vermelho
```

### 2.3 Testes de Filtros

**Teste 1: Filtro por entity**
```
1. Selecionar "user" em Entidade
2. Clicar "Aplicar Filtros"
3. Verificar que todos os logs mostram entity = 'user'
```

**Teste 2: Filtro por operation**
```
1. Selecionar "delete" em Operação
2. Clicar "Aplicar Filtros"
3. Verificar que todos mostram operation = 'delete'
```

**Teste 3: Múltiplos filtros**
```
1. Entidade: user
2. Operação: delete
3. Status: success
4. Clicar "Aplicar Filtros"
5. Verificar que TODOS combinam os 3 critérios
```

**Teste 4: Limpar filtros**
```
1. Aplicar alguns filtros
2. Clicar "Limpar Filtros"
3. Verificar que campos voltam ao padrão
4. Clicar "Aplicar Filtros"
5. Verificar que mostra todos os logs novamente
```

**Teste 5: Date range**
```
1. Data Inicial: 01/01/2024
2. Data Final: 31/01/2024
3. Clicar "Aplicar Filtros"
4. Verificar que todos os timestamps estão no range
```

### 2.4 Testes de Paginação

**Teste 1: Navegação**
```
1. Se há mais de 50 logs (padrão)
2. Clicar "Próxima →"
3. Verificar que página avança e mostra novos logs
4. Clicar "← Anterior"
5. Verificar que volta aos logs anteriores
```

**Teste 2: Seletor de página**
```
1. Selecionar "100 por página"
2. Clicar "Aplicar Filtros" (se necessário)
3. Verificar que mostra até 100 logs
```

**Teste 3: Ir para página**
```
1. Se há múltiplas páginas
2. Selecionar página específica no dropdown
3. Verificar que pula para aquela página
```

### 2.5 Testes de Expandir Detalhes

**Teste 1: Expandir uma linha**
```
1. Clicar em "Detalhes" de um log
2. Verificar que a linha se expande
3. Mostra:
   - ✅ Informações da Requisição (método, endpoint, etc)
   - ✅ Informações do Cliente (IP, User-Agent)
   - ✅ Valores Alterados (old_value e new_value em JSON)
   - ✅ Mensagem de erro (se houver)
```

**Teste 2: Colapsar uma linha**
```
1. Clicar em "Detalhes" novamente
2. Verificar que a linha se colapsa
```

**Teste 3: JSON formatado**
```
1. Expandir um log com old_value ou new_value
2. Verificar que JSON está indentado e legível
3. Não é uma string crua
```

### 2.6 Teste de Exportação

**Teste 1: Exportar sem filtros**
```
1. Clicar "Exportar JSON"
2. Verificar que baixa arquivo "audit_logs_YYYY-MM-DD.json"
3. Abrir arquivo em editor de texto
4. Verificar que é válido JSON array
5. Verificar que tem logs
```

**Teste 2: Exportar com filtros**
```
1. Aplicar filtro (ex: entity = user)
2. Clicar "Exportar JSON"
3. Abrir arquivo
4. Verificar que contém apenas logs de user
```

### 2.7 Teste de Atualizar

**Teste 1: Botão Atualizar**
```
1. Clicar "Atualizar"
2. Verificar que table se recarrega
3. Se houver novos logs, aparecem
```

### 2.8 Teste de Mensagens de Erro

**Teste 1: Erro ao carregar**
```
1. Parar o backend
2. Tentar carregar página de auditoria
3. Verificar mensagem de erro clara
```

**Teste 2: Erro ao exportar**
```
1. Parar o backend
2. Tentar exportar JSON
3. Verificar mensagem de erro clara
```

---

## 3. Testes de Integração

### 3.1 Criar Usuário e Verificar Log

```
1. Fazer login como root
2. Ir para Usuários
3. Criar novo usuário "test_integration"
4. Ir para Logs de Auditoria
5. Filtrar: entity = user, operation = create
6. Verificar que log do novo user aparece
7. Expandir log
8. Verificar que new_value contém os dados corretos
9. Verificar que admin_username está correto
```

### 3.2 Deletar Usuário e Verificar Log

```
1. Ir para Usuários
2. Deletar o usuário "test_integration"
3. Ir para Logs de Auditoria
4. Filtrar: entity = user, operation = delete
5. Verificar que log de deleção aparece
6. Expandir log
7. Verificar que:
   - old_value contém dados do user deletado
   - new_value é null
8. No banco, verificar que:
   - users.deleted_at está preenchido
   - users.username é NULL
```

### 3.3 Rastrear Ações de um Admin

```
1. Ir para Logs de Auditoria
2. No filtro "ID do Admin", selecionar um admin
3. Clicar "Aplicar Filtros"
4. Verificar que todos os logs são daquele admin
5. Ver histórico completo de ações
```

### 3.4 Análise Temporal

```
1. Ir para Logs de Auditoria
2. Data Inicial: 3 dias atrás
3. Data Final: hoje
4. Clicar "Aplicar Filtros"
5. Verificar que todos os timestamps estão no range
6. Exportar para análise
```

---

## 4. Testes de Performance

### 4.1 Carregar 1000+ Logs

```sql
-- Injetar logs fake (se necessário para teste)
INSERT INTO audit_logs 
(id, timestamp, operation, entity, entity_id, admin_id, status)
VALUES (gen_random_uuid(), NOW(), 'read', 'user', gen_random_uuid(), 
        (SELECT id FROM users LIMIT 1), 'success')
-- Repetir 1000 vezes
```

```
1. Ir para Logs de Auditoria
2. Verificar que página carrega em <2 segundos
3. Mudar para "200 por página"
4. Clicar em última página
5. Verificar que não demora
6. Filtrar por date range
7. Verificar que query é rápido (<1 segundo)
```

### 4.2 Exportar Muitos Logs

```
1. Sem filtros (máximo de logs)
2. Clicar "Exportar JSON"
3. Arquivo deve baixar em <5 segundos
4. Arquivo deve ser válido JSON
```

---

## 5. Testes de Segurança

### 5.1 Acesso Não Autorizado

```
1. Login como user normal
2. Tentar acessar /audit-logs diretamente
3. Esperado: Mensagem de acesso negado
4. NÃO deve poder acessar dados de auditoria
```

### 5.2 Dados Sensíveis

```
1. Full admin vê audit logs
2. Password hash NUNCA deve aparecer em new_value
3. Verificar que apenas username é registrado
```

### 5.3 IP Tracking

```
1. Fazer requisição com proxy (X-Forwarded-For)
2. Verificar que IP correto está registrado
3. Não deve registrar IP do proxy
```

---

## 6. Checklist de Testes

### Backend
- [ ] Soft-delete funciona (deleted_at preenchido)
- [ ] FK não quebra após soft-delete
- [ ] LogOperation registra CREATE
- [ ] LogOperation registra UPDATE
- [ ] LogOperation registra DELETE
- [ ] Filtro por entity funciona
- [ ] Filtro por operation funciona
- [ ] Filtro por date range funciona
- [ ] Filtro por status funciona
- [ ] Filtro por IP funciona
- [ ] Múltiplos filtros combinam corretamente
- [ ] GET /api/audit-logs/{id} funciona
- [ ] Autenticação (401 sem token)
- [ ] Autorização (403 se não root)
- [ ] IP é extraído corretamente
- [ ] User-Agent é capturado
- [ ] Timestamps são precisos
- [ ] JSON em old_value/new_value é válido

### Frontend
- [ ] Menu aparece apenas para root
- [ ] Página de auditoria carrega
- [ ] Tabela renderiza com dados
- [ ] Cores estão corretas
- [ ] Filtros funcionam individualmente
- [ ] Múltiplos filtros combinam
- [ ] Botão limpar filtros funciona
- [ ] Paginação funciona
- [ ] Seletor de página funciona
- [ ] Expandir detalhes funciona
- [ ] JSON está formatado corretamente
- [ ] Exportar JSON funciona
- [ ] Arquivo JSON é válido
- [ ] Mensagens de erro aparecem
- [ ] Loading state mostra corretamente

### Integração
- [ ] Criar user registra em audit_logs
- [ ] Deletar user registra em audit_logs
- [ ] Soft-deleted user não aparece em list
- [ ] Soft-deleted user não pode fazer login
- [ ] Filtro por admin mostra ações dele
- [ ] Exportação inclui filtros aplicados
- [ ] Histórico de entidade é consultável

### Performance
- [ ] 1000+ logs carregam rápido
- [ ] Filtros com date range são rápidos
- [ ] Exportação é rápida
- [ ] Paginação não fica lenta

### Segurança
- [ ] Não-authorized users não acessam
- [ ] Password hash não aparece
- [ ] IP é capturado corretamente

---

## 7. Exemplo de Fluxo Completo de Teste

```
1. Backend rodando
2. Frontend rodando
3. Login como root
4. Ir para Usuários
5. Criar novo usuário "test_audit"
6. Ir para Logs de Auditoria
7. Tabela carrega com dados
8. Filtrar: entity=user, operation=create
9. Log de criação aparece
10. Expandir log
11. Ver new_value com dados do user
12. Clicar "Exportar JSON"
13. Arquivo baixa e é válido
14. Voltar para Usuários
15. Deletar "test_audit"
16. Ir para Logs de Auditoria
17. Filtrar: entity=user, operation=delete
18. Log de deleção aparece com old_value
19. No banco:
    - SELECT * FROM users WHERE deleted_at IS NOT NULL;
    - Ver que deleted_at está preenchido
    - Ver que username é NULL
    - Ver que audit_logs não quebrou
20. Tudo funciona ✅
```

---

## 8. Troubleshooting

### Problema: Logs não aparecem
**Solução:**
1. Verificar se há dados no banco: `SELECT COUNT(*) FROM audit_logs;`
2. Verificar se LogOperation está sendo chamado nos handlers
3. Verificar token (root?)
4. Verificar console do navegador (erros?)

### Problema: Query é lenta
**Solução:**
1. Verificar se índices foram criados: `\d audit_logs` (no psql)
2. Executar ANALYZE: `ANALYZE audit_logs;`
3. Usar LIMIT para reduzir dados

### Problema: Soft-delete não funciona
**Solução:**
1. Verificar se coluna deleted_at existe: `\d users` (no psql)
2. Verificar se UPDATE está sendo executado
3. Verificar logs do backend

### Problema: IP não é capturado
**Solução:**
1. Verificar se X-Forwarded-For está sendo passado
2. Verificar extractClientIP() function
3. Testar com curl direto

---

## Conclusão

Executar todos esses testes garante que o sistema de auditoria está funcionando corretamente em:
- Funcionalidade
- Performance
- Segurança
- Integridade de dados
- Experiência do usuário