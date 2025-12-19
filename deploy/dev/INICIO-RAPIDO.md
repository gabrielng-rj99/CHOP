# 🚀 Início Rápido - Desenvolvimento

## ✅ Pré-requisitos

- Go 1.21+
- Node.js 18+ e npm
- PostgreSQL 14+
- Git

## 📦 Primeira Execução

### 1. Clone o repositório (se ainda não fez)

```bash
git clone <repository-url>
cd Entity-Hub-Open-Project
```

### 2. Configure o PostgreSQL

```bash
# Inicie o PostgreSQL
sudo systemctl start postgresql  # Linux
# ou
brew services start postgresql   # macOS

# Verifique se está rodando
pg_isready
```

### 3. Instale dependências do Frontend

```bash
cd frontend
npm install
cd ..
```

### 4. Inicie o ambiente de desenvolvimento

```bash
./deploy/dev/start-dev.sh
```

**⚠️ IMPORTANTE: NÃO use `sudo`!**

Na primeira execução, o script irá:
- ✅ Gerar senhas seguras (DB_PASSWORD e JWT_SECRET)
- ✅ Criar usuário do banco de dados
- ✅ Criar banco de dados de desenvolvimento
- ✅ Compilar o backend
- ✅ Iniciar backend na porta 3000
- ✅ Iniciar Vite dev server na porta 5173

## 🌐 Acessando o Sistema

Abra o navegador em:

```
http://localhost:5173
```

**URLs importantes:**
- Frontend: `http://localhost:5173`
- Backend API: `http://localhost:3000`
- Health Check: `http://localhost:3000/health`

## 🔐 Login Inicial

Após aplicar os seeds (veja seção abaixo), use:

```
Usuário: root
Senha: root123
```

## 🗄️ Aplicar Seeds (Dados Iniciais)

Se o banco estiver vazio, aplique os seeds:

```bash
# Conecte ao banco
psql -h localhost -p 5432 -U ehopuser -d ehopdb_dev

# Aplique os seeds na ordem:
\i backend/seeds/01_roles_permissions.sql
\i backend/seeds/02_system_settings.sql
\i backend/seeds/03_root_user.sql
\i backend/seeds/04_enhanced_permissions.sql

# Saia
\q
```

Senha do banco: veja em `deploy/dev/dev.ini` após primeira execução

## 🛑 Parar os Serviços

```bash
./deploy/dev/stop-dev.sh
```

## 📊 Verificar se Está Funcionando

```bash
# Backend
curl http://localhost:3000/health
# Deve retornar: {"status":"healthy"}

# Frontend
curl http://localhost:5173
# Deve retornar HTML

# API via Proxy
curl http://localhost:5173/api/health
# Deve retornar: {"status":"healthy"}
```

## 📝 Logs

Se algo der errado, verifique os logs:

```bash
# Backend
tail -f logs/backend_dev/server.log

# Vite
tail -f logs/vite-dev.log
```

## 🔧 Estrutura de Portas

| Serviço | Porta | URL |
|---------|-------|-----|
| Frontend (Vite) | 5173 | http://localhost:5173 |
| Backend API | 3000 | http://localhost:3000 |
| PostgreSQL | 5432 | localhost:5432 |

## 📁 Arquivos Importantes

```
Entity-Hub-Open-Project/
├── deploy/dev/
│   ├── start-dev.sh         # Script de início
│   ├── stop-dev.sh          # Script de parada
│   ├── dev.ini              # Configuração (gerado na 1ª execução)
│   ├── CONEXAO-FIX.md       # Detalhes da correção de conexão
│   └── INICIO-RAPIDO.md     # Este arquivo
├── backend/
│   ├── cmd/server/main.go   # Entrada do backend
│   └── seeds/               # Scripts SQL iniciais
├── frontend/
│   ├── src/                 # Código React
│   └── vite.config.js       # Configuração do Vite (proxy)
└── logs/
    ├── backend_dev/         # Logs do backend
    └── vite-dev.log         # Logs do Vite
```

## 🐛 Problemas Comuns

### "PostgreSQL is not running"

```bash
sudo systemctl start postgresql
# ou
brew services start postgresql
```

### "Failed to create database user"

Certifique-se que você pode executar:

```bash
sudo -u postgres psql
```

### "Cannot connect to backend"

1. Verifique se backend está rodando:
   ```bash
   curl http://localhost:3000/health
   ```

2. Verifique logs:
   ```bash
   tail -f logs/backend_dev/server.log
   ```

3. Reinicie tudo:
   ```bash
   ./deploy/dev/stop-dev.sh
   ./deploy/dev/start-dev.sh
   ```

### "Port already in use"

Algum serviço já está usando a porta. Pare os processos:

```bash
# Encontre o processo
sudo lsof -i :5173  # Frontend
sudo lsof -i :3000  # Backend

# Mate o processo
kill -9 <PID>

# Ou use o stop script
./deploy/dev/stop-dev.sh
```

## 🔄 Workflow de Desenvolvimento

1. **Inicie os serviços** (uma vez):
   ```bash
   ./deploy/dev/start-dev.sh
   ```

2. **Desenvolva**:
   - Edite arquivos em `frontend/src/` → Hot reload automático
   - Edite arquivos em `backend/` → Reinicie backend manualmente

3. **Para reiniciar só o backend**:
   ```bash
   # Mate o processo
   pkill ehop-backend-dev
   
   # Recompile e rode
   cd backend
   go build -o ehop-backend-dev ./cmd/server/main.go
   ./ehop-backend-dev
   ```

4. **Commit suas mudanças**:
   ```bash
   git add .
   git commit -m "feat: sua feature"
   git push
   ```

## 🎯 Próximos Passos

- [ ] Explorar a interface em http://localhost:5173
- [ ] Criar seu primeiro usuário/entidade
- [ ] Ler documentação em `/docs`
- [ ] Configurar roles e permissões
- [ ] Personalizar branding

## 📚 Documentação Adicional

- [CONEXAO-FIX.md](./CONEXAO-FIX.md) - Detalhes técnicos do fix de conexão
- [../../README.md](../../README.md) - README principal do projeto
- [../../backend/README.md](../../backend/README.md) - Documentação do backend
- [../../frontend/README.md](../../frontend/README.md) - Documentação do frontend

## 💬 Precisa de Ajuda?

- Verifique os logs: `tail -f logs/backend_dev/server.log`
- Leia [CONEXAO-FIX.md](./CONEXAO-FIX.md)
- Abra uma issue no GitHub

---

**Happy Coding! 🚀**