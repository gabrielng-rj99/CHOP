# Testes de Segurança - Contract Manager

Este diretório contém uma suíte completa de testes de segurança para a API do Contract Manager.

## 📋 Índice

- [Visão Geral](#visão-geral)
- [Configuração do Ambiente](#configuração-do-ambiente)
- [Executando os Testes](#executando-os-testes)
- [Testes Implementados](#testes-implementados)
- [Vulnerabilidades Testadas](#vulnerabilidades-testadas)
- [Estrutura dos Arquivos](#estrutura-dos-arquivos)
- [Troubleshooting](#troubleshooting)

## 🎯 Visão Geral

Esta suíte de testes valida a segurança da aplicação contra as principais vulnerabilidades web, incluindo:

- ✅ Manipulação de tokens JWT (incluindo CVE-2015-9235)
- ✅ Escalação de privilégios
- ✅ SQL Injection em todas as queries
- ✅ Vazamento de dados sensíveis
- ✅ XSS (Cross-Site Scripting)
- ✅ Brute force protection
- ✅ Password security
- ✅ E muito mais...

## 🔧 Configuração do Ambiente

### Pré-requisitos

- **Go** 1.21 ou superior
- **Docker** e **Docker Compose**
- **Make** (opcional, mas recomendado)

### Portas Utilizadas

| Serviço    | Porta |
|------------|-------|
| PostgreSQL | 65432 |
| Backend    | 63000 |
| Frontend   | 65080 |

**Importante:** As portas são diferentes da aplicação principal para permitir testes sem conflitos.

### Verificar Dependências

```bash
make setup
```

Ou manualmente:

```bash
go version
docker --version
docker info
```

## 🚀 Executando os Testes

### Método Rápido (Recomendado)

```bash
# Executar todos os testes
make test

# Testes com output verbose
make test-v

# Testes com relatório de cobertura
make coverage

# Testes verbose + cobertura
make test-cov-v
```

### Testes Específicos

```bash
# Manipulação de tokens
make test-token

# Escalação de privilégios
make test-priv

# SQL Injection
make test-sql

# Vazamento de dados
make test-leak

# Fluxos de autenticação
make test-auth

# Segurança de senhas
make test-password

# Prevenção de XSS
make test-xss
```

### Modo Debug

```bash
# Manter ambiente rodando após testes
make keep-alive

# Em outro terminal, você pode:
curl http://localhost:63000/api/health
make shell-db  # Conectar ao banco
```

### Método Manual

```bash
# Executar o script diretamente
./run_security_tests.sh

# Com opções
./run_security_tests.sh -v           # Verbose
./run_security_tests.sh -c           # Coverage
./run_security_tests.sh -v -c        # Ambos
./run_security_tests.sh --keep-alive # Não limpar após testes
```

## 📝 Testes Implementados

### 1. Manipulação de Tokens JWT (`security_token_manipulation_test.go`)

#### Testes de JWT Vazio (CVE-2015-9235)
- ✅ JWT completamente vazio deve ser rejeitado
- ✅ JWT com assinatura vazia (alg=none) deve ser rejeitado
- ✅ JWT com assinatura alterada deve ser rejeitado

#### Manipulação Geral de Tokens
- ✅ Manipulação de role no payload do token
- ✅ Token de usuário deletado deve ser inválido
- ✅ Token com user_id inexistente
- ✅ Token expirado deve ser rejeitado
- ✅ Token com exp no futuro distante

#### Refresh Tokens
- ✅ Refresh token deve ter lifetime limitado
- ✅ Refresh token não deve dar acesso direto a recursos
- ✅ Access token em endpoint de refresh deve falhar

#### Invalidação de Auth Secret
- ✅ Mudar senha deve invalidar auth_secret
- ✅ Tokens antigos inválidos após mudança de senha

#### Validação de Formato
- ✅ Token vazio, mal formado, com SQL injection, etc.

#### Algoritmo JWT
- ✅ Algoritmo None deve ser rejeitado
- ✅ Mudança de HS256 para RS256 deve falhar

#### Rate Limiting
- ✅ Múltiplas tentativas de refresh limitadas
- ✅ Flood de login detectado

#### Revogação de Tokens
- ✅ Logout invalida tokens
- ✅ Bloqueio de conta invalida tokens

#### Validação de Claims
- ✅ Claims obrigatórios presentes
- ✅ Claims extras/suspeitos ignorados
- ✅ Tipo de dados dos claims validado

### 2. Escalação de Privilégios (`security_privilege_escalation_test.go`)

#### Escalação de Role
- ✅ Usuário não pode alterar próprio role
- ✅ Admin não pode escalar para root
- ✅ Usuário não pode alterar role de outro

#### Requests Sem Senha
- ✅ Criar usuário sem senha deve falhar
- ✅ Update de password para NULL/vazio deve falhar
- ✅ Login sem senha deve falhar
- ✅ Alteração de senha sem senha antiga deve falhar

#### Manipulação de Role em Requests
- ✅ Criar usuário com role=root via request body
- ✅ Update com role manipulado no body
- ✅ Mass assignment de campos privilegiados

#### Permissões Admin vs Root
- ✅ Admin não pode alterar senha de root
- ✅ Admin não pode deletar root
- ✅ Admin não pode alterar role de outro admin
- ✅ Admin não pode alterar display_name de outro admin
- ✅ Root pode alterar qualquer coisa

#### Permissões de Mudança de Senha
- ✅ Usuário pode alterar própria senha
- ✅ Usuário não pode alterar senha de outro
- ✅ Admin pode alterar própria senha
- ✅ Admin NÃO pode alterar senha de outro admin
- ✅ Admin NÃO pode alterar senha de usuário comum
- ✅ Root pode alterar senha de qualquer um

#### Bloqueio de Conta
- ✅ Usuário bloqueado não pode fazer login
- ✅ Admin pode desbloquear usuário comum
- ✅ Admin não pode desbloquear outro admin
- ✅ Usuário não pode auto-desbloquear

#### Acesso a Dados
- ✅ Usuário não pode ver lista de outros usuários
- ✅ Usuário pode ver próprios dados
- ✅ Dados sensíveis filtrados nas respostas
- ✅ Admin pode ver lista de usuários
- ✅ Root pode ver lista completa

#### Audit Logs
- ✅ Usuário comum não pode acessar logs
- ✅ Admin pode ver audit logs
- ✅ Logs não contêm dados sensíveis

### 3. SQL Injection (`security_sql_injection_test.go`)

#### Login
- ✅ SQL injection no username
- ✅ SQL injection no password

#### Queries de Usuários
- ✅ Buscar usuário por ID com injection
- ✅ Buscar usuário por username com injection
- ✅ Update de display_name com injection
- ✅ Filtro com LIKE e injection

#### Queries de Clientes
- ✅ Buscar cliente por nome com injection
- ✅ Buscar cliente por CPF/CNPJ com injection
- ✅ Buscar cliente por email com injection
- ✅ Update de cliente com injection em múltiplos campos
- ✅ Filtro de status com injection

#### Queries de Categorias
- ✅ Buscar categoria por nome com injection
- ✅ Buscar linha por nome com injection
- ✅ Join categories-lines com injection

#### Queries de Contratos
- ✅ Buscar contrato por product_key com injection
- ✅ Buscar contratos por client_id com injection
- ✅ Query complexa com múltiplos JOINs e injection

#### Audit Logs
- ✅ Buscar logs por operation com injection
- ✅ Buscar logs por entity com injection
- ✅ Buscar logs por admin_username com injection
- ✅ Filtro de data com injection

#### Casos Especiais
- ✅ Query com string vazia
- ✅ Query com NULL explícito
- ✅ Query retornando lista vazia (não erro)
- ✅ Múltiplos parâmetros, alguns vazios

#### Caracteres Especiais
- ✅ Caracteres especiais: ', ", ;, --, /*, */, \, \n, \r, \t, \x00, etc.
- ✅ Unicode e caracteres multibyte
- ✅ Emojis e caracteres especiais

#### Operações em Lote
- ✅ Batch insert com injection
- ✅ IN clause com injection

#### Second-Order Attacks
- ✅ Payload armazenado usado em query posterior

### 4. Vazamento de Dados (`security_data_leak_test.go`)

- ✅ Password hash não deve vazar em respostas
- ✅ Auth secret não deve vazar em respostas
- ✅ Stack traces não devem vazar informações
- ✅ Erros genéricos para usuários (sem detalhes internos)
- ✅ Senhas são hasheadas no banco

### 5. Fluxos de Autenticação (`security_auth_flows_test.go`)

- ✅ Login com credenciais válidas
- ✅ Login com credenciais inválidas
- ✅ Brute force protection (tentativas múltiplas)
- ✅ Account locking após falhas
- ✅ Token refresh funciona
- ✅ Logout invalida tokens

### 6. Segurança de Senhas (`security_password_test.go`)

- ✅ Senhas são hasheadas com bcrypt
- ✅ Auth_secret é regenerado na mudança de senha
- ✅ Tokens antigos invalidados após mudança
- ✅ Senhas fracas rejeitadas (se implementado)
- ✅ Histórico de senhas (se implementado)

### 7. Prevenção de XSS (`security_xss_test.go`)

- ✅ Payloads XSS são sanitizados/rejeitados
- ✅ Scripts não são executados
- ✅ HTML é escapado corretamente
- ✅ Headers de segurança (Content-Type, X-XSS-Protection, etc.)

## 🛡️ Vulnerabilidades Testadas

### OWASP Top 10

1. **A01:2021 – Broken Access Control**
   - Escalação de privilégios
   - Acesso horizontal (usuário acessando dados de outro)
   - Acesso vertical (usuário comum acessando funcionalidade de admin)

2. **A02:2021 – Cryptographic Failures**
   - Senhas hasheadas adequadamente (bcrypt)
   - Tokens seguros (JWT com secret dinâmico)
   - Dados sensíveis não vazam

3. **A03:2021 – Injection**
   - SQL Injection em todas as queries
   - Prepared statements sempre usados
   - Validação de input

4. **A05:2021 – Security Misconfiguration**
   - Stack traces não vazam
   - Erros genéricos para usuários
   - Configurações seguras

5. **A07:2021 – Identification and Authentication Failures**
   - Brute force protection
   - Account locking
   - Token management adequado
   - Session management seguro

### Vulnerabilidades Específicas

- **CVE-2015-9235**: JWT vazio (alg=none)
- **Mass Assignment**: Campos não autorizados em requests
- **Second-Order SQL Injection**: Dados armazenados usados em queries
- **Prototype Pollution**: Claims maliciosos em JWT
- **JWT Algorithm Confusion**: HS256 vs RS256
- **Password Enumeration**: Respostas genéricas
- **Timing Attacks**: bcrypt protege contra
- **CSRF**: (se aplicável, testar tokens)
- **CORS**: (se aplicável, testar origens)

## 📁 Estrutura dos Arquivos

```
backend/tests/
├── docker-compose.test.yml          # Stack Docker para testes
├── Makefile                         # Comandos simplificados
├── run_security_tests.sh            # Script principal de execução
├── README.md                        # Este arquivo
├── QUICKSTART.md                    # Guia rápido
├── IMPLEMENTATION_SUMMARY.md        # Detalhes técnicos
│
├── security__main.go                # Helpers e setup de testes
├── security_token_manipulation_test.go
├── security_privilege_escalation_test.go
├── security_sql_injection_test.go
├── security_data_leak_test.go
├── security_auth_flows_test.go
├── security_password_test.go
└── security_xss_test.go
```

## 🐛 Troubleshooting

### Porta 65432 já em uso

```bash
# Verificar o que está usando a porta
sudo lsof -i :65432

# Parar o processo ou mudar a porta em docker-compose.test.yml
```

### Docker não conecta

```bash
# Verificar se Docker está rodando
docker info

# Reiniciar Docker
sudo systemctl restart docker
```

### Testes falhando

```bash
# Verificar status do ambiente
make status

# Ver logs do banco
make logs-db

# Ver logs do servidor
make logs

# Conectar ao banco para debug
make shell-db
```

### Limpar tudo e recomeçar

```bash
# Limpar containers, volumes e arquivos
make clean-all

# Executar novamente
make test
```

### Banco não está populado

```bash
# Verificar se schema foi aplicado
make shell-db
\dt  # Listar tabelas

# Se necessário, reaplicar schema
docker exec -i contracts-test-db psql -U test_user -d contracts_test < ../database/schema.sql
```

## 📊 Cobertura de Código

```bash
# Gerar relatório de cobertura
make coverage

# Abrir relatório no navegador
make open-coverage
```

## 🔍 Comandos Úteis

```bash
# Ver todos os comandos disponíveis
make help

# Status da stack
make status

# Informações da configuração
make info

# Exemplos de uso
make examples

# Conectar ao banco de testes
make shell-db

# Ver logs em tempo real
make logs
```

## 📚 Documentação Adicional

- [QUICKSTART.md](./QUICKSTART.md) - Guia rápido de 5 minutos
- [IMPLEMENTATION_SUMMARY.md](./IMPLEMENTATION_SUMMARY.md) - Detalhes técnicos e arquitetura

## ⚠️ Notas Importantes

1. **Não usar em produção**: Este ambiente é apenas para testes
2. **Portas diferentes**: 65432 (DB), 63000 (API) para não conflitar com produção
3. **Credenciais de teste**: Nunca usar as mesmas de produção
4. **Dados temporários**: Tudo é limpo após execução (exceto com `--keep-alive`)
5. **Schema aplicado**: O `schema.sql` é aplicado automaticamente no init do container

## 🎓 Melhores Práticas

### Ao Adicionar Novos Testes

1. Criar arquivo `security_NOME_test.go`
2. Usar `setupTestEnvironment(t)` para configuração
3. Sempre usar `defer config.CleanupFunc()` para limpar
4. Testar tanto casos válidos quanto inválidos
5. Validar que dados sensíveis não vazam
6. Adicionar documentação inline

### Ao Modificar a API

1. Executar `make test` antes de commit
2. Atualizar testes se necessário
3. Garantir que cobertura não diminua
4. Documentar novas vulnerabilidades testadas

## 🚨 Checklist de Segurança

Antes de fazer deploy em produção, garantir que:

- [ ] Todos os testes de segurança passam
- [ ] Cobertura de código > 80%
- [ ] Prepared statements usados em todas queries
- [ ] Password hash nunca vaza em respostas
- [ ] Auth secret nunca vaza
- [ ] Stack traces não são expostos
- [ ] Brute force protection ativo
- [ ] Rate limiting implementado
- [ ] HTTPS obrigatório em produção
- [ ] CORS configurado adequadamente
- [ ] Headers de segurança presentes
- [ ] Logs não contêm dados sensíveis
- [ ] Senhas têm requisitos mínimos
- [ ] Tokens têm expiração apropriada
- [ ] Audit logs registram todas operações sensíveis

## 📞 Suporte

Se encontrar problemas ou vulnerabilidades não cobertas:

1. Adicione um teste reproduzindo o problema
2. Corrija a vulnerabilidade
3. Verifique que o teste passa
4. Documente a correção

---

**Última atualização**: 2024
**Versão**: 2.0
**Mantenedor**: Equipe de Desenvolvimento