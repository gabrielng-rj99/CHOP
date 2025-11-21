# Contract Manager - Deploy

Deployment simples e direto para o Contract Manager.

## 🚀 Quick Start

### Docker (Recomendado)

```bash
# 1. Copie o .env.example
cp .env.example .env

# 2. Edite o .env e preencha suas senhas
nano .env

# 3. Suba tudo
docker-compose up -d
```

Acesse: http://localhost:8080

### Monolito (Desenvolvimento)

```bash
# 1. Tenha o PostgreSQL rodando localmente
sudo systemctl start postgresql  # Linux
brew services start postgresql   # macOS

# 2. Copie o .env.example
cp .env.example .env

# 3. Edite o .env e preencha suas senhas
nano .env

# 4. Execute o script
./start-monolith.sh
```

Acesse: http://localhost:5173

## 📁 Estrutura

```
deploy/
├── docker-compose.yml      # Compose padrão
├── .env.example           # Template de variáveis
├── .env                   # Suas variáveis (não commitar!)
├── Dockerfile.backend     # Build do backend
├── Dockerfile.frontend    # Build do frontend
├── nginx.conf            # Config do Nginx
├── start-monolith.sh     # Script modo monolito
├── docs/
│   └── SSL_SETUP.md       # Guia SSL e domínios customizados
└── README.md             # Este arquivo
```

## 🔧 Configuração

### Arquivo .env

Copie `.env.example` para `.env` e preencha:

```bash
# Database - use senhas fortes!
DB_PASSWORD=sua_senha_aqui
DB_USER=appuser
DB_NAME=contract_manager

# JWT - mínimo 32 caracteres
JWT_SECRET=sua_chave_jwt_secreta_min_32_chars

# Root User - criado automaticamente
ROOT_USER_EMAIL=admin@localhost
ROOT_USER_PASSWORD=senha_admin_aqui

# Portas
API_PORT=3000
FRONTEND_PORT=8080

# SSL e API URL (importante!)
SSL_DOMAIN=localhost
VITE_API_URL=/api
```

**Importante:** 
- Nunca commite o `.env`!
- Se usar domínio SSL customizado (ex: `https://ehop.home.arpa`), **leia [docs/SSL_SETUP.md](docs/SSL_SETUP.md)**

### 🔐 Usando Domínio SSL Customizado

Se você vai acessar o sistema via HTTPS com domínio customizado (não localhost), você **DEVE** configurar:

```bash
# Seu domínio
SSL_DOMAIN=ehop.home.arpa

# IMPORTANTE: Use /api para que o Nginx faça proxy
VITE_API_URL=/api
```

**📖 Leia o guia completo:** [docs/SSL_SETUP.md](docs/SSL_SETUP.md)

Sem essa configuração, você verá erros de CORS ao tentar fazer login.

### Gerar senhas seguras

```bash
# Password aleatória
openssl rand -base64 32

# JWT Secret
openssl rand -base64 48
```

## 🐳 Comandos Docker

```bash
# Iniciar
docker-compose up -d

# Ver logs
docker-compose logs -f

# Parar
docker-compose down

# Reiniciar
docker-compose restart

# Limpar tudo (remove volumes)
docker-compose down -v
```

Ou use o Makefile:
```bash
make up
make logs
make down
make clean
```

## 🛠️ Ferramentas

Scripts simples em `../backend/tools/`:

```bash
cd ../backend/tools

# Rodar testes
./test.sh

# Verificar saúde
./health.sh

# Backup do banco
./backup.sh
```

## 📝 Criar o Usuário Root

O usuário root deve ser criado manualmente na primeira execução. Use as credenciais definidas em `ROOT_USER_EMAIL` e `ROOT_USER_PASSWORD` do arquivo `.env`.

### Via API (curl)

```bash
curl -X POST http://localhost:3000/api/users \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@localhost",
    "password": "sua_senha_do_env",
    "name": "Administrator",
    "role": "admin"
  }'
```

### Via Interface

Acesse a página de registro e crie o primeiro usuário com as credenciais do `.env`.

## 🔍 Troubleshooting

### Porta em uso

```bash
# Ver o que está usando a porta
lsof -i :3000

# Matar processo
kill -9 <PID>
```

### PostgreSQL não está rodando (Monolito)

```bash
# Linux
sudo systemctl start postgresql
sudo systemctl status postgresql

# macOS
brew services start postgresql
brew services list
```

### Erro de conexão com o banco

1. Verifique se o PostgreSQL está rodando
2. Verifique as credenciais no `.env`
3. No modo Docker, o `DB_HOST` deve ser `postgres`
4. No modo Monolito, o `DB_HOST` deve ser `localhost`

### Docker não inicia

```bash
# Ver logs
docker-compose logs

# Recriar tudo
docker-compose down -v
docker-compose up -d
```

## 🔒 Segurança

- ✅ Use senhas fortes (use `openssl rand -base64 32`)
- ✅ Nunca commite o `.env`
- ✅ Mude as senhas default
- ✅ Use HTTPS em produção (reverse proxy)
- ✅ Restrinja CORS para seu domínio

## 📊 Portas

| Serviço    | Docker | Monolito |
|------------|--------|----------|
| Frontend   | 8080   | 5173     |
| Backend    | 3000   | 3000     |
| PostgreSQL | 5432   | 5432     |

## 🚀 Produção

Para produção, adicione:

1. **Reverse Proxy** (Nginx/Caddy)
2. **SSL/TLS** (Let's Encrypt)
3. **Firewall** (UFW/iptables)
4. **Backups automáticos** (cron + `backend/tools/backup.sh`)
5. **Monitoring** (logs, health checks)

Exemplo de cron para backup diário:
```bash
0 2 * * * cd /path/to/Contract-Manager/backend/tools && ./backup.sh
```

## 📚 Mais Informações

- Backend: `../backend/`
- Frontend: `../frontend/`
- Schema SQL: `../backend/database/schema.sql`

---

**Dúvidas?** Veja os logs primeiro: `docker-compose logs` ou `./start-monolith.sh`
