# 🚀 Início Rápido - Ambiente de Desenvolvimento

## Pré-requisitos

- Go 1.21+
- Node.js 20+
- PostgreSQL 14+
- Make

## Iniciar

```bash
cd deploy/dev
make start
```

Pronto! O Makefile cuida de tudo automaticamente:
- ✅ Inicia PostgreSQL automaticamente (com sudo se necessário)
- ✅ Verifica conflitos de porta
- ✅ Constrói o backend
- ✅ Inicia todos os serviços

## Acessar

- **Frontend**: http://localhost:45173 ⚡ (hot reload!)
- **Backend**: http://localhost:43000
- **Health**: http://localhost:43000/health

## Portas Utilizadas

| Componente | Porta | Motivo |
|-----------|-------|---------|
| Backend API | 43000 | Evita conflito com produção (3000) |
| Frontend (Vite) | 45173 | Evita conflito com outros (5173) |
| PostgreSQL | 5432 | Porta padrão (sistema nativo) |

## Comandos Principais

| Comando | Descrição |
|---------|-----------|
| `make start` | Iniciar ambiente |
| `make stop` | Parar serviços |
| `make restart` | Reconstruir e reiniciar |
| `make status` | Ver status dos serviços |
| `make logs` | Ver logs do backend |
| `make clean` | Limpar processos órfãos |
| `make help` | Ver todos os comandos |

## Problemas Comuns

### Código não atualiza

```bash
make clean
make start
```

### Porta em uso

```bash
make check-ports
make clean
```

### Backend não inicia

```bash
make logs
```

### PostgreSQL não inicia automaticamente

```bash
# Normalmente inicia sozinho, mas se não funcionar:
sudo systemctl start postgresql
sudo systemctl status postgresql
```

## Database

```bash
make db-status    # Ver status
make db-connect   # Abrir psql
make db-reset     # Resetar (⚠️ apaga dados!)
```

## Destruir Ambiente

```bash
make destroy
```

⚠️ Remove banco de dados, logs e binários.

---

Para documentação completa, veja [README.md](README.md).