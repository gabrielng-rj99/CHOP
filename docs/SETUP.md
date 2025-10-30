# Setup — Licenses Manager

Guia completo para instalar, configurar e começar a usar o Licenses Manager em ambiente de desenvolvimento ou produção.

## 📋 Pré-requisitos

- **Go** 1.18 ou superior
- **PostgreSQL** 12 ou superior
- **Git**
- **Make** (opcional, para automação)

Verifique se estão instalados:
```bash
go version
psql --version
git --version
```

## 🚀 Instalação Rápida

### 1. Clone o Repositório

```bash
git clone https://github.com/seu-usuario/Licenses-Manager.git
cd Licenses-Manager
```

### 2. Configure o Banco de Dados

```bash
# Crie o banco
createdb licenses_manager

# Aplique o schema
psql -d licenses_manager -f backend/database/init.sql
```

Verifique:
```bash
psql -d licenses_manager -c "\dt"
# Deve listar: categories, companies, entities, licenses, lines, users
```

### 3. Configure Variáveis de Ambiente

Na raiz do projeto, crie `.env`:

```bash
cat > .env << EOF
DB_HOST=localhost
DB_PORT=5432
DB_USER=seu_usuario_pg
DB_PASSWORD=sua_senha_pg
DB_NAME=licenses_manager
EOF
```

**Não commite o `.env` no git!** Adicione à `.gitignore` se não estiver.

### 4. Instale Dependências

```bash
cd backend
go mod tidy
```

### 5. Execute

```bash
go run cmd/cli/main.go
```

Você verá o menu interativo da CLI.

## 🔧 Configuração Detalhada

### Variáveis de Ambiente

| Variável | Exemplo | Descrição |
|----------|---------|-----------|
| `DB_HOST` | localhost | Host do PostgreSQL |
| `DB_PORT` | 5432 | Porta do PostgreSQL |
| `DB_USER` | postgres | Usuário do BD |
| `DB_PASSWORD` | senha123 | Senha do BD |
| `DB_NAME` | licenses_manager | Nome do banco |

### Criar Usuário Dedicado (Recomendado)

Ao invés de usar `postgres`, crie um usuário específico:

```bash
psql -U postgres << EOF
CREATE USER licenses_user WITH PASSWORD 'senha_segura';
CREATE DATABASE licenses_manager OWNER licenses_user;
\c licenses_manager
GRANT ALL ON SCHEMA public TO licenses_user;
EOF
```

Depois execute o init:
```bash
psql -U licenses_user -d licenses_manager -f backend/database/init.sql
```

### Estrutura do Banco

O script `init.sql` cria as seguintes tabelas:

```sql
users              -- Usuários do sistema
companies          -- Empresas clientes
entities           -- Unidades/filiais
categories         -- Classificação de licenças
lines              -- Linhas de produtos
licenses           -- Licenças de software
```

Com relacionamentos via chaves estrangeiras e constraints de unicidade.

## 🧪 Executar Testes

Antes de testar, certifique-se de que o banco está rodando:

```bash
cd backend

# Testes unitários
go test ./tests/store -v

# Com cobertura
go test ./tests/store -cover

# Benchmark
go test ./tests/store -bench=.
```

## 🏭 Build para Produção

Compile um binário executável:

```bash
cd backend
go build -o licenses-manager cmd/cli/main.go
./licenses-manager
```

## 🐳 Docker (Opcional)

Se preferir usar Docker para o PostgreSQL:

```bash
docker run -d \
  --name licenses-db \
  -e POSTGRES_USER=licenses_user \
  -e POSTGRES_PASSWORD=senha_segura \
  -e POSTGRES_DB=licenses_manager \
  -p 5432:5432 \
  postgres:15

# Aplique o schema
psql -h localhost -U licenses_user -d licenses_manager -f backend/database/init.sql
```

Configure `.env`:
```
DB_HOST=localhost
DB_USER=licenses_user
DB_PASSWORD=senha_segura
```

## 🔍 Troubleshooting

### Erro: "connection refused"

**Causa:** PostgreSQL não está rodando

**Solução:**
```bash
# Verifique se está rodando
psql -h localhost -U postgres -d postgres -c "SELECT 1;"

# Se não estiver, inicie (macOS/Homebrew)
brew services start postgresql

# Linux (systemd)
sudo systemctl start postgresql

# Windows
net start PostgreSQL-x64-15
```

### Erro: "FATAL: database does not exist"

**Causa:** Banco não foi criado

**Solução:**
```bash
createdb licenses_manager
psql -d licenses_manager -f backend/database/init.sql
```

### Erro: "permission denied for schema public"

**Causa:** Usuário não tem permissões

**Solução:**
```bash
psql -U postgres -d licenses_manager << EOF
GRANT ALL ON SCHEMA public TO seu_usuario;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO seu_usuario;
EOF
```

### Erro: "undefined reference" ou "module not found"

**Causa:** Dependências Go não foram instaladas

**Solução:**
```bash
cd backend
go mod tidy
go mod download
```

### Erro: "cannot find cmd/cli/main.go"

**Causa:** Você não está no diretório correto

**Solução:**
```bash
cd Licenses-Manager/backend
go run cmd/cli/main.go
```

### Erro: ".env file not found" ou variáveis não carregam

**Causa:** Arquivo `.env` não está no lugar certo

**Solução:**
```bash
# Verifique o caminho
ls -la Licenses-Manager/.env

# Se não existir, crie
cat > Licenses-Manager/.env << EOF
DB_HOST=localhost
DB_PORT=5432
DB_USER=postgres
DB_PASSWORD=sua_senha
DB_NAME=licenses_manager
EOF
```

### Banco criado mas sem tabelas

**Causa:** Script SQL não foi executado completamente

**Solução:**
```bash
# Verifique as tabelas
psql -d licenses_manager -c "\dt"

# Se vazio, execute novamente
psql -d licenses_manager -f backend/database/init.sql

# Ou verifique se init.sql existe
ls -la backend/database/init.sql
```

## 📝 Próximas Passos

1. **Leia** [USAGE.md](USAGE.md) para aprender os comandos
2. **Explore** [ARCHITECTURE.md](ARCHITECTURE.md) para entender a estrutura
3. **Execute** alguns exemplos práticos
4. **Contribua** com melhorias!

## ✅ Verificação Final

Após seguir todos os passos, teste se tudo funciona:

```bash
cd backend
go run cmd/cli/main.go
# Você deve ver o menu principal da CLI
```

Se vir o menu, parabéns! 🎉 O setup está completo.

---

**Dúvidas?** Consulte [README.md](../README.md) ou abra uma issue no repositório.