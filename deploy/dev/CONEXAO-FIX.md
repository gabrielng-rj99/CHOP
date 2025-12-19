# Fix de Conexão Backend/Frontend - Resolvido ✅

## 🐛 Problema Identificado

Quando executava `sudo ./start-dev.sh`, o site não conseguia conectar ao backend.

### Causas Raiz:

1. **Porta do Vite hardcoded**: O `vite.config.js` tinha porta `8080` fixa, mas o script tentava usar porta `5173`
2. **Variáveis de ambiente não propagadas**: Executar com `sudo` fazia as variáveis de ambiente não serem repassadas corretamente ao Vite
3. **Proxy mal configurado**: O proxy do Vite não estava lendo a porta correta do backend
4. **PID files em `/tmp`**: Usando `sudo` criava arquivos como root, causando problemas de permissão

## ✅ Correções Aplicadas

### 1. **vite.config.js** - Porta e Proxy Dinâmicos

Antes:
```javascript
server: {
    port: 8080,  // ❌ Hardcoded
    proxy: {
        "/api": {
            target: "http://localhost:3000",  // ❌ Hardcoded
            changeOrigin: true,
        },
    },
}
```

Depois:
```javascript
const VITE_PORT = parseInt(process.env.VITE_PORT || "5173", 10);
const API_PORT = parseInt(process.env.API_PORT || "3000", 10);

server: {
    port: VITE_PORT,              // ✅ Dinâmico
    host: "0.0.0.0",              // ✅ Permite conexões externas
    proxy: {
        "/api": {
            target: `http://localhost:${API_PORT}`,  // ✅ Dinâmico
            changeOrigin: true,
            secure: false,
            ws: true,  // ✅ WebSocket support
        },
    },
}
```

### 2. **start-dev.sh** - Sem Sudo e PID Files Corrigidos

**Mudanças principais:**

- ✅ Script **NÃO requer sudo** para rodar (só para setup do PostgreSQL)
- ✅ PID files salvos em `$PROJECT_ROOT/logs/` (não em `/tmp`)
- ✅ Variáveis de ambiente `VITE_PORT` e `API_PORT` exportadas corretamente
- ✅ Detecta e para processos antigos antes de iniciar
- ✅ Logs mais claros sobre como o proxy funciona

**PID files movidos:**
- Backend: `logs/backend_dev/backend.pid` (antes: `/tmp/ehop-backend-dev.pid`)
- Vite: `logs/vite-dev.pid` (antes: `/tmp/ehop-vite-dev.pid`)

### 3. **stop-dev.sh** - Atualizado

- ✅ Usa os novos caminhos de PID files
- ✅ Fallback para matar por nome de processo se PID não existir

## 🚀 Como Usar Agora

### Iniciar (SEM sudo):

```bash
./deploy/dev/start-dev.sh
```

### Parar:

```bash
./deploy/dev/stop-dev.sh
```

## 📊 Fluxo de Conexão

```
Browser (localhost:5173)
    ↓
Vite Dev Server (porta 5173)
    ↓ [Proxy /api/*]
Backend API (porta 3000)
    ↓
PostgreSQL (porta 5432)
```

### Como funciona o Proxy:

1. Frontend faz requisição para `/api/users`
2. Vite intercepta (proxy configurado em `vite.config.js`)
3. Vite encaminha para `http://localhost:3000/api/users`
4. Backend responde
5. Vite retorna resposta ao frontend

**✅ CORS não é problema** porque o browser vê tudo vindo de `localhost:5173`

## 🔍 Verificação

Após iniciar, verifique:

```bash
# Backend está rodando?
curl http://localhost:3000/health

# Vite está rodando?
curl http://localhost:5173

# Frontend consegue acessar API via proxy?
curl http://localhost:5173/api/health
```

## 📝 Logs

Se ainda tiver problemas, verifique os logs:

```bash
# Backend
tail -f logs/backend_dev/server.log

# Vite
tail -f logs/vite-dev.log
```

## ⚠️ Importante

1. **NÃO use sudo** para rodar `start-dev.sh` (só se pedir permissão para PostgreSQL)
2. **Acesse via**: `http://localhost:5173` (não porta 3000 ou 8080)
3. **Requisições da API**: Use `/api/*` no frontend (proxy faz o resto)

## 🎯 Caso Ainda Não Funcione

1. Pare todos os processos: `./deploy/dev/stop-dev.sh`
2. Mate processos órfãos: `pkill -f ehop-backend-dev && pkill -f vite`
3. Limpe logs: `rm -rf logs/*`
4. Inicie novamente: `./deploy/dev/start-dev.sh`
5. Verifique os 3 curls acima

## 📚 Referências

- Vite Proxy Config: https://vitejs.dev/config/server-options.html#server-proxy
- Issue resolvida em: 2025-01-XX