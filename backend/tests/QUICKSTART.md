# 🚀 Quick Start - Testes de Segurança

Guia rápido para executar os testes de segurança em **menos de 2 minutos**.

## ⚡ Execução Ultra-Rápida

```bash
cd backend/tests
make test
```

**Pronto!** Os testes serão executados automaticamente.

---

## 📋 Pré-requisitos Mínimos

- ✅ Go 1.21+
- ✅ PostgreSQL rodando
- ✅ Banco `contracts_test` criado (o script cria automaticamente se não existir)

## 🎯 Comandos Principais

```bash
# Executar todos os testes
make test

# Com output detalhado
make test-v

# Com relatório de cobertura
make coverage

# Testar SQL injection específico
make test-sql

# Testar escalação de privilégios
make test-priv

# Limpar tudo
make clean
```

## 🔧 Setup Inicial (Primeira Vez)

### 1. Verificar se PostgreSQL está rodando

```bash
# Linux
sudo systemctl status postgresql

# macOS
brew services list | grep postgresql

# Iniciar se não estiver rodando
sudo systemctl start postgresql  # Linux
brew services start postgresql   # macOS
```

### 2. Criar banco de teste (se não existir)

```bash
# O script faz isso automaticamente, mas se quiser fazer manualmente:
createdb contracts_test

# Executar migrations
psql contracts_test < ../migrations/001_initial_schema.sql
```

### 3. Configurar variável de ambiente (opcional)

```bash
# Apenas se usar credenciais diferentes
export TEST_DATABASE_URL="postgres://seu_usuario:sua_senha@localhost:5432/contracts_test?sslmode=disable"
```

### 4. Executar testes

```bash
cd backend/tests
make test
```

## ✅ O Que é Testado?

### 🔐 Segurança Crítica
- ✓ Manipulação de tokens JWT
- ✓ Escalação de privilégios (admin → root)
- ✓ SQL injection (9+ payloads maliciosos)
- ✓ Vazamento de dados sensíveis
- ✓ Brute force protection
- ✓ XSS attacks (6+ payloads)

### 🎯 Total
- **7 suites de teste**
- **25+ cenários específicos**
- **50+ payloads de ataque**
- **~0.2s** de execução

## 📊 Interpretando Resultados

### ✅ Sucesso
```
PASS
ok      Contracts-Manager/backend/tests    0.234s

  ✓ ALL SECURITY TESTS PASSED
```

### ❌ Falha
```
FAIL: TestPrivilegeEscalation/Admin_não_pode_alterar_senha_de_root
    security_test.go:310: FALHA CRÍTICA: Admin conseguiu alterar senha de root!

FAIL
exit status 1

  ✗ SOME SECURITY TESTS FAILED
```

## 🐛 Troubleshooting Rápido

### Erro: "connection refused"
```bash
# PostgreSQL não está rodando
sudo systemctl start postgresql  # Linux
brew services start postgresql   # macOS
```

### Erro: "database does not exist"
```bash
# Criar banco
createdb contracts_test

# Executar migrations
psql contracts_test < ../migrations/001_initial_schema.sql
```

### Erro: "no such file or directory"
```bash
# Você não está na pasta correta
cd backend/tests
make test
```

## 📖 Quer Mais Detalhes?

- **README.md** - Documentação completa
- **IMPLEMENTATION_SUMMARY.md** - Detalhes técnicos
- **Makefile** - Todos os comandos disponíveis
- **run_security_tests.sh** - Script principal

## 🎓 Exemplos Práticos

### Testar apenas SQL injection
```bash
make test-sql
```

### Gerar relatório HTML de cobertura
```bash
make coverage
make open-coverage  # Abre no navegador
```

### Executar teste específico
```bash
go test -v -run TestTokenManipulation
```

### Modo debug (mantém ambiente rodando)
```bash
make keep-alive
# Em outro terminal:
psql contracts_test
# Ctrl+C para parar
```

## 🚨 IMPORTANTE - Antes de Deploy

```bash
# SEMPRE executar antes de fazer push/deploy:
make test

# Se houver falhas, NÃO faça deploy até corrigir!
```

## 💡 Dicas Úteis

1. **Teste localmente primeiro** - Sempre rode `make test` antes de commit
2. **Use verbose para debug** - `make test-v` mostra mais detalhes
3. **Verifique cobertura** - `make coverage` garante que tudo está coberto
4. **Mantenha logs** - `make logs` para ver logs do servidor de teste
5. **Limpe regularmente** - `make clean` remove arquivos temporários

## 📞 Ajuda Rápida

```bash
# Ver todos os comandos disponíveis
make help

# Ver status da stack de testes
make status

# Ver versões das ferramentas
make version

# Ver informações da configuração
make info
```

---

**Tempo estimado:** 30 segundos para executar todos os testes 🚀

**Última atualização:** 2025-01-16