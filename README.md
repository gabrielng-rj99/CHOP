# Contract Manager

Sistema centralizado para gerenciar contratos e licenças de software.

## 🚀 Começar Agora

```bash
cd deploy
make build
./bin/deploy-manager
```

Escolha:
- **1** = Monolith (desenvolvimento local)
- **10** = Docker (containerizado)

Depois acesse:
- Monolith: http://localhost:5173
- Docker: http://localhost:8081

## 📖 Documentação

Toda a documentação de deployment está em **`deploy/`**:

| Documento | Tempo | Para Quem |
|-----------|-------|-----------|
| `deploy/docs/QUICK_START.md` | 2 min | Começar rápido |
| `deploy/README.md` | 15 min | Guia completo |
| `deploy/docs/TROUBLESHOOTING.md` | 10 min | Resolver problemas |

## 🏗️ Estrutura

```
Contract-Manager/
├── deploy/           ← Tudo de deployment aqui
├── backend/          → Go API
├── frontend/         → React UI
└── docs/             → Documentação de features
```

## ⚡ Comandos Rápidos

**Monolith:**
```bash
bash deploy/scripts/deploy-monolith.sh start
bash deploy/scripts/deploy-monolith.sh stop
bash deploy/scripts/deploy-monolith.sh logs
```

**Docker:**
```bash
cd deploy/scripts
docker compose up -d
docker compose down
docker compose logs -f
```

## 🔧 Stack

- **Backend:** Go 1.21+ | PostgreSQL 14+
- **Frontend:** React 18 | TypeScript | Vite
- **Deployment:** CLI Go | Docker Compose

## 📚 Precisa de Ajuda?

→ Leia `deploy/README.md` ou `deploy/docs/QUICK_START.md`

**Status:** ✅ Pronto para produção
