# Setup — Contracts Manager

Guia completo para instalar, configurar e começar a usar o Contracts Manager em ambiente de desenvolvimento ou produção.

## 📋 Pré-requisitos

- **Go** 1.21 ou superior
- **Git**
- **PostgreSQL** 12+ (banco padrão)

Verifique:
```bash
go version
git --version
```

## 🚀 Instalação Rápida

### 1. Clone o Repositório

```bash
git clone https://github.com/seu-usuario/Contracts-Manager.git
cd Contracts-Manager
```

### 2. Instale Dependências

```bash
cd backend
go mod tidy
```

### 3. Configure Variáveis de Ambiente (Opcional)

Para PostgreSQL (desenvolvimento), crie `.env` na raiz do projeto:

```bash
cat > ../.env << EOF
DB_HOST=localhost
DB_PORT=5432
DB_USER=seu_usuario_pg
DB_PASSWORD=sua_senha_pg
DB_NAME=contracts_manager
EOF
```

**Nota:** O banco padrão agora é PostgreSQL. Configure o arquivo `.env` com as variáveis de conexão do PostgreSQL.


### 4. Execute

```bash
go run cmd/cli/main.go
```

Você verá o menu interativo da CLI.

## 🗄️ Banco de Dados

### PostgreSQL (Padrão)


O banco PostgreSQL deve estar disponível e configurado antes da primeira execução. As tabelas serão criadas automaticamente se necessário.


**Vantagens:**
- ✅ Sem configuração
- ✅ Sem servidor externo
- ✅ Perfeito para desenvolvimento
- ✅ Portável

### PostgreSQL (Produção)

Se preferir usar PostgreSQL:

#### 1. Criar Banco de Dados

```bash
createdb contracts_manager
```

#### 2. Aplicar Schema

```bash
psql -d contracts_manager -f backend/database/schema.sql
```

#### 3. Verificar Tabelas

```bash
psql -d contracts_manager -c "\dt"
```

Deve listar: `categories`, `clients`, `contracts`, `dependents`, `lines`, `users`.

#### 4. Configurar .env

```bash
cat > .env << EOF
DB_HOST=localhost
DB_PORT=5432
DB_USER=seu_usuario
DB_PASSWORD=sua_senha
DB_NAME=contracts_manager
EOF
```

## 🔧 Configuração Detalhada

### Criar Usuário Dedicado (PostgreSQL)

```bash
psql -U postgres << EOF
CREATE USER contracts_user WITH PASSWORD 'senha_segura';
CREATE DATABASE contracts_manager OWNER contracts_user;
\c contracts_manager
GRANT ALL ON SCHEMA public TO contracts_user;
EOF
```

### Variáveis de Ambiente

| Variável | Exemplo | Descrição |
|----------|---------|-----------|
| `DB_HOST` | localhost | Host do PostgreSQL |
| `DB_PORT` | 5432 | Porta do PostgreSQL |
| `DB_USER` | contracts_user | Usuário do BD |
| `DB_PASSWORD` | senha123 | Senha do BD |
| `DB_NAME` | contracts_manager | Nome do banco |

## 🧪 Executar Testes

```bash
cd backend

# Todos os testes
go test ./store -v

# Com cobertura
go test ./store -cover

# Teste específico
go test -run TestContractCreate ./store
```

**Status esperado:** ✅ 114 testes passando

## 🏭 Build para Produção

Compile um binário executável:

```bash
cd backend
go build -o contracts-manager cmd/cli/main.go
./contracts-manager
```

## 🐳 Docker (Opcional)

### Com PostgreSQL no Docker

```bash
docker run -d \
  --name contracts-db \
  -e POSTGRES_USER=contracts_user \
  -e POSTGRES_PASSWORD=senha_segura \
  -e POSTGRES_DB=contracts_manager \
  -p 5432:5432 \
  postgres:15

# Aguarde 5 segundos e aplique o schema
sleep 5
psql -h localhost -U contracts_user -d contracts_manager -f backend/database/schema.sql
```

Configure `.env`:
```
DB_HOST=localhost
DB_USER=contracts_user
DB_PASSWORD=senha_segura
DB_NAME=contracts_manager
```

### Docker Compose (Completo)

Crie `docker-compose.yml`:

```yaml
version: '3.8'

services:
  db:
    image: postgres:15
    environment:
      POSTGRES_USER: contracts_user
      POSTGRES_PASSWORD: senha_segura
      POSTGRES_DB: contracts_manager
    ports:
      - "5432:5432"
    volumes:
      - pg_data:/var/lib/postgresql/data
      - ./backend/database/schema.sql:/docker-entrypoint-initdb.d/schema.sql

volumes:
  pg_data:
```

Execute:
```bash
docker-compose up -d
```

## 🔍 Troubleshooting

### Erro: "cannot open database"

**Causa:** Banco de dados não pode ser criado/acessado

**Solução:**
```bash
# Verifique permissões do usuário do PostgreSQL e se o banco existe
# Para recriar o banco, utilize comandos do PostgreSQL:

dropdb contracts_manager
createdb contracts_manager
go run cmd/cli/main.go
```

### Erro: "connection refused" (PostgreSQL)

**Causa:** PostgreSQL não está rodando

**Solução:**
```bash
# Verifique status
psql -h localhost -U postgres -d postgres -c "SELECT 1;"

# Se não estiver rodando:
# macOS (Homebrew)
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
createdb contracts_manager
psql -d contracts_manager -f backend/database/schema.sql
```

### Erro: "permission denied for schema public"

**Causa:** Usuário não tem permissões

**Solução:**
```bash
psql -U postgres -d contracts_manager << EOF
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
cd Contracts-Manager/backend
go run cmd/cli/main.go
```

### Erro: ".env file not found" ou variáveis não carregam

**Causa:** Arquivo `.env` está no local errado

**Solução:**
```bash
# Deve estar na raiz do projeto
ls -la Contracts-Manager/.env

# Se não existir, crie
cat > Contracts-Manager/.env << EOF
DB_HOST=localhost
DB_PORT=5432
DB_USER=seu_usuario
DB_PASSWORD=sua_senha
DB_NAME=contracts_manager
EOF
```

### Erro: "too many connections"

**Causa:** Muitas conexões abertas com PostgreSQL

**Solução:**
```bash
# Limpe conexões antigas
psql -U postgres -d postgres << EOF
SELECT pg_terminate_backend(pg_stat_activity.pid)
FROM pg_stat_activity
WHERE pg_stat_activity.datname = 'contracts_manager'
  AND pid <> pg_backend_pid();
EOF
```

### Erro: "go version not supported"

**Causa:** Versão do Go é muito antiga

**Solução:**
```bash
# Verifique versão
go version

# Se for < 1.21, atualize
# https://go.dev/dl/
```

## 📝 Próximas Passos

1. **Leia** [USAGE.md](USAGE.md) para aprender os comandos
2. **Explore** [ARCHITECTURE.md](ARCHITECTURE.md) para entender a estrutura
3. **Teste** comandos básicos no menu CLI
4. **Consulte** [CONTRIBUTING.md](CONTRIBUTING.md) se for contribuir

## ✅ Verificação Final

Após seguir todos os passos, teste se tudo funciona:

```bash
cd backend
go run cmd/cli/main.go
```

Você deve ver o menu principal com opções como:
```
=== Contracts Manager ===
1. Clients
2. Dependents
3. Categories
4. Lines
5. Contracts
6. Users
0. Exit
```

Se vir o menu, parabéns! 🎉 O setup está completo.

---

**Problemas?** Consulte [Troubleshooting](#-troubleshooting) acima ou abra uma [issue](https://github.com/seu-usuario/Contracts-Manager/issues).
