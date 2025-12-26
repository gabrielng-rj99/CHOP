# Entity Hub - Deploy

Deployment configurations for Entity Hub.

## 🎯 Modos de Deploy

Este projeto oferece **3 modos** de deploy:

### 1. 🐳 Docker (Recomendado para Produção)
Tudo em containers isolados. Mais fácil, seguro e portável.

### 2. 🖥️ Monolith (Produção Local)
Backend + Frontend (build estático via Nginx) no host. Simula ambiente de produção.

### 3. 🔧 Development (Para Desenvolvedores)
Backend + Vite dev server com hot reload. Perfeito para desenvolver.

---

## 📁 Estrutura

```
deploy/
├── docker/                   # Deploy via Docker Compose
│   ├── docker-compose.yml
│   ├── .env.example
│   ├── Dockerfile.backend
│   ├── Dockerfile.frontend
│   └── nginx.conf
│
├── monolith/                 # Deploy local (produção-like)
│   ├── start-monolith.sh
│   ├── stop-monolith.sh
│   ├── install-monolith.sh
│   ├── monolith.ini
│   └── versions.ini
│
├── dev/                      # Ambiente de desenvolvimento
│   ├── start-dev.sh
│   ├── stop-dev.sh
│   └── dev.ini
│
├── certs/                    # Certificados SSL
│   └── ssl/
│
├── generate-ssl.sh           # Script para gerar certificados
├── certs-config.ini          # Configuração para certificados
└── README.md                 # Este arquivo
```

---

## 🚀 Quick Start

### Docker (Recomendado)

```bash
cd deploy/docker

# 1. Configure as variáveis
cp .env.example .env
nano .env  # Edite DB_PASSWORD e JWT_SECRET

# 2. Suba os containers
docker-compose up -d

# 3. Acesse
# https://localhost (ou sua porta configurada)
```

### Monolith (Produção Local)

```bash
cd deploy/monolith

# 1. Instale dependências (apenas primeira vez)
./install-monolith.sh

# 2. Configure
nano monolith.ini  # Deixe DB_PASSWORD e JWT_SECRET vazios para auto-gerar

# 3. Inicie
./start-monolith.sh

# 4. Acesse
# https://localhost
# http://localhost:80
```

### Development (Hot Reload)

```bash
cd deploy/dev

# 1. Configure
nano dev.ini  # Deixe DB_PASSWORD e JWT_SECRET vazios para auto-gerar

# 2. Inicie
./start-dev.sh

# 3. Acesse
# http://localhost:5173  (Vite dev server)
```

---

## 🔍 Comparação dos Modos

| Característica        | Docker          | Monolith         | Development      |
|-----------------------|-----------------|------------------|------------------|
| **Isolamento**        | ✅ Containers   | ❌ Host          | ❌ Host          |
| **Facilidade**        | ⭐⭐⭐⭐⭐       | ⭐⭐⭐⭐          | ⭐⭐⭐           |
| **Produção**          | ✅ Sim          | ✅ Sim           | ❌ Não           |
| **Hot Reload**        | ❌ Não          | ❌ Não           | ✅ Sim           |
| **Performance**       | Alta            | Alta             | Média            |
| **Frontend**          | Nginx (build)   | Nginx (build)    | Vite dev server  |
| **SSL**               | ✅ Auto         | ✅ Auto          | ❌ Opcional      |
| **Portabilidade**     | ✅ Máxima       | ⚠️ Requer deps  | ⚠️ Requer deps  |

---

## 🐳 Docker

### Comandos

```bash
cd deploy/docker

# Iniciar
docker-compose up -d

# Ver logs
docker-compose logs -f

# Reiniciar
docker-compose restart

# Parar
docker-compose down

# Limpar tudo (remove volumes/dados)
docker-compose down -v
```

### Arquivo .env

```bash
# Exemplo mínimo
DB_PASSWORD=your_secure_password_here
JWT_SECRET=your_jwt_secret_min_64_chars
SSL_DOMAIN=localhost
```

Gere senhas seguras:
```bash
# DB Password (64 chars)
openssl rand -base64 48 | tr -d "=+/" | cut -c1-64

# JWT Secret (64 chars)
openssl rand -base64 48 | tr -d "=+/" | cut -c1-64
```

---

## 🖥️ Monolith

### Requisitos

- Go 1.21+
- Node.js 20+
- PostgreSQL 14+
- Nginx
- OpenSSL

### Instalação

```bash
cd deploy/monolith
./install-monolith.sh
```

Este script instala automaticamente todas as dependências (Go, Node, PostgreSQL, Nginx).

### Configuração

Edite `monolith.ini`:

```ini
# Database
DB_USER=ehopuser
DB_NAME=ehopdb
DB_PASSWORD=          # Deixe vazio para auto-gerar

# Backend
JWT_SECRET=           # Deixe vazio para auto-gerar

# Portas
API_PORT=3000
FRONTEND_PORT=80
FRONTEND_HTTPS_PORT=443
```

### Uso

```bash
# Iniciar
./start-monolith.sh

# Parar
./stop-monolith.sh

# Destruir tudo (remove banco, etc)
./destroy-monolith.sh
```

### O que acontece no start:

1. ✅ Carrega `monolith.ini`
2. ✅ Gera senhas se vazias (salva no .ini)
3. ✅ Verifica PostgreSQL
4. ✅ Cria banco e usuário
5. ✅ Compila backend (Go)
6. ✅ Compila frontend (Vite build → dist/)
7. ✅ Gera certificados SSL
8. ✅ Configura e inicia Nginx
9. ✅ Inicia backend API

### Logs

- Backend: `logs/backend/server.log`
- Nginx: `/tmp/ehop_access.log`, `/tmp/ehop_error.log`

---

## 🔧 Development

### Requisitos

Mesmos do Monolith (Go, Node, PostgreSQL).

### Configuração

Edite `dev.ini`:

```ini
# Database (usa banco separado: ehopdb_dev)
DB_USER=ehopuser
DB_NAME=ehopdb_dev
DB_PASSWORD=          # Deixe vazio para auto-gerar

# Backend
JWT_SECRET=           # Deixe vazio para auto-gerar

# Portas
API_PORT=3000
VITE_PORT=5173
```

### Uso

```bash
cd deploy/dev

# Iniciar
./start-dev.sh

# Parar
./stop-dev.sh
```

### O que acontece no start:

1. ✅ Carrega `dev.ini`
2. ✅ Gera senhas se vazias (salva no .ini)
3. ✅ Verifica PostgreSQL
4. ✅ Cria banco e usuário (separado: `ehopdb_dev`)
5. ✅ Compila backend (Go)
6. ✅ Inicia backend API
7. ✅ Inicia Vite dev server (hot reload)

### Vantagens

- ⚡ **Hot Reload**: Edite código e veja mudanças instantaneamente
- 🐛 **Debug**: React DevTools, logs detalhados
- 🗄️ **Banco separado**: Não afeta dados de produção
- 🔄 **Rápido**: Sem rebuild de imagens Docker

### Logs

- Backend: `logs/backend_dev/server.log`
- Vite: `logs/vite-dev.log`

---

## 🔐 SSL e Certificados

Todos os modos geram certificados SSL automaticamente usando `generate-ssl.sh`.

### Personalizar Certificados

Edite `certs-config.ini`:

```ini
[certificate]
country=BR
state=Sao Paulo
locality=Sao Paulo
organization=Entity Hub
organizational_unit=IT
common_name=ehop.home.arpa
email=admin@ehop.home.arpa
days_valid=365
key_size=2048
```

### Gerar Manualmente

```bash
./generate-ssl.sh ./certs/ssl
```

### Domínio Customizado

Se usar domínio customizado (ex: `ehop.home.arpa`):

1. Configure no arquivo .ini:
   ```ini
   SSL_DOMAIN=ehop.home.arpa
   CORS_ALLOWED_ORIGINS=https://ehop.home.arpa
   VITE_API_URL=/api
   ```

2. Adicione ao `/etc/hosts`:
   ```bash
   127.0.0.1 ehop.home.arpa
   ```

3. Importe o certificado no navegador ou use mkcert:
   ```bash
   mkcert -install
   mkcert ehop.home.arpa localhost 127.0.0.1
   ```

---

## 🔧 Troubleshooting

### PostgreSQL não está rodando

```bash
# Linux
sudo systemctl start postgresql
sudo systemctl status postgresql

# macOS
brew services start postgresql
```

### Porta em uso

```bash
# Ver o que está usando a porta
sudo lsof -i :80
sudo lsof -i :443
sudo lsof -i :3000

# Matar processo
sudo kill -9 <PID>
```

### Erro de permissão no Nginx

```bash
# Nginx precisa de sudo para portas 80/443
# Se erro, limpe processos:
sudo pkill -9 nginx
```

### Frontend não carrega

1. Verifique se o build foi criado: `ls frontend/dist/`
2. Veja logs do Nginx: `tail -f /tmp/ehop_error.log`
3. Verifique permissões: `ls -la frontend/dist/`

### Backend não conecta ao banco

1. Verifique se PostgreSQL está rodando
2. Teste conexão:
   ```bash
   psql -h localhost -p 5432 -U ehopuser -d ehopdb
   ```
3. Verifique variáveis exportadas:
   ```bash
   echo $DB_PASSWORD
   echo $DB_NAME
   ```

### Erro CORS

Se ver erro de CORS no console do navegador:

1. Verifique `CORS_ALLOWED_ORIGINS` no .ini
2. Use `/api` em `VITE_API_URL` (não `http://localhost:3000/api`)
3. Se usar domínio customizado, configure corretamente

---

## 📊 Portas Padrão

| Serviço           | Docker | Monolith | Development |
|-------------------|--------|----------|-------------|
| Frontend          | 443    | 443      | 5173        |
| Frontend (HTTP)   | -      | 80       | -           |
| Backend API       | 3000   | 3000     | 3000        |
| PostgreSQL        | 5432   | 5432     | 5432        |

---

## 🗄️ Banco de Dados

### Inicialização

Quando o banco está vazio, o sistema entra em modo de setup:

1. Acesse `/api/initialize/status` para verificar
2. Use `/api/initialize/admin` para criar o primeiro usuário admin
3. Documentação completa em: `http://localhost:3000/docs`

### Backup (Monolith/Dev)

```bash
# Backup
pg_dump -h localhost -U ehopuser ehopdb > backup.sql

# Restore
psql -h localhost -U ehopuser ehopdb < backup.sql
```

### Backup (Docker)

```bash
# Backup
docker exec ehop_db pg_dump -U ehopuser ehopdb > backup.sql

# Restore
docker exec -i ehop_db psql -U ehopuser ehopdb < backup.sql
```

---

## 🔒 Segurança

### Checklist

- ✅ Use senhas de 64 caracteres (use os comandos de geração)
- ✅ Nunca commite arquivos `.env` ou `.ini` com senhas
- ✅ Mude senhas default antes de produção
- ✅ Use HTTPS sempre (certificados SSL)
- ✅ Configure CORS corretamente (não use `*`)
- ✅ Mantenha dependências atualizadas
- ✅ Faça backups regulares

### Gerar Senhas Seguras

```bash
# Senha de 64 caracteres
openssl rand -base64 48 | tr -d "=+/" | cut -c1-64

# Ou deixe vazio no .ini para auto-gerar
```

---

## 📚 Mais Informações

- **Backend**: `../backend/README.md`
- **Frontend**: `../frontend/README.md`
- **Schema SQL**: `../backend/database/schema.sql`
- **API Docs**: `http://localhost:3000/docs` (quando rodando)

---

## 🤝 Contribuindo

Ao adicionar features de deploy:

1. Mantenha os 3 modos sincronizados
2. Documente mudanças neste README
3. Teste em todos os modos
4. Atualize `versions.ini` se mudar dependências

---

**Dúvidas?** Abra uma issue ou veja os logs primeiro! 🚀