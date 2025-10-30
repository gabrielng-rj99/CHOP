# Licenses Manager

Gestão centralizada de licenças de software. Rastreie, organize e controle todas as suas licenças em um único lugar.

## ⚡ Quick Start

### 1. Pré-requisitos
- Go 1.18+
- PostgreSQL 12+

### 2. Instalação
```bash
git clone https://github.com/seu-usuario/Licenses-Manager.git
cd Licenses-Manager
cd backend
go mod tidy
```

### 3. Configurar banco de dados
```bash
createdb licenses_manager
psql -d licenses_manager -f database/init.sql
```

### 4. Variáveis de ambiente
Crie `.env` na raiz:
```
DB_HOST=localhost
DB_PORT=5432
DB_USER=seu_usuario
DB_PASSWORD=sua_senha
DB_NAME=licenses_manager
```

### 5. Executar
```bash
go run cmd/cli/main.go
```

## 📚 Documentação

- **[SETUP.md](docs/SETUP.md)** — Instalação detalhada e troubleshooting
- **[USAGE.md](docs/USAGE.md)** — Exemplos práticos de uso e casos comuns
- **[ARCHITECTURE.md](docs/ARCHITECTURE.md)** — Visão técnica e padrões do projeto
- **[CONTRIBUTING.md](docs/CONTRIBUTING.md)** — Como contribuir

## 🎯 O que você pode fazer

### Gerenciar Empresas
```bash
go run cmd/cli/main.go
# Menu → Companies → Create/List/Archive
```

### Cadastrar Licenças
Vincule licenças a empresas, unidades e categorias com validações automáticas.

### Monitorar Vencimentos
Identifique licenças próximas do vencimento e planeje renovações.

### Filtrar por Categoria/Linha
Organize suas licenças por tipo de produto (Antivírus, Banco de Dados, etc).

## 🏗️ Arquitetura

```
backend/
├── cmd/cli/          # Interface de linha de comando
├── domain/           # Modelos de negócio
├── store/            # Lógica de dados e regras
├── database/         # Scripts SQL
└── tests/            # Testes unitários e integração
```

**Stack:** Go + PostgreSQL + CLI

## 🧪 Testes

```bash
cd backend
go test ./store -v
go test ./store -cover
```

## 📝 Estrutura de Dados

| Entidade | Descrição |
|----------|-----------|
| **Companies** | Empresas clientes |
| **Entities** | Unidades/Filiais |
| **Categories** | Classificação (Antivírus, SO, DB, etc) |
| **Lines** | Linhas de produtos (Kaspersky, Windows, SQL Server) |
| **Licenses** | Licenças de software |
| **Users** | Usuários do sistema |

## 🔗 Relacionamentos

```
Company → Entities (1:N)
Company → Licenses (1:N)
Entity → Licenses (1:N, opcional)
Category → Lines (1:N)
Line → Licenses (1:N)
```

## ⚙️ Regras de Negócio Principais

- Empresas podem ser arquivadas (soft delete)
- Licenças com datas inválidas são rejeitadas
- Não há sobreposição temporal de licenças do mesmo tipo
- Deleção em cascata respeita integridade referencial
- Status automático: Ativa / Expirando / Expirada

## 🚀 Roadmap

- [ ] API REST
- [ ] Dashboard web
- [ ] Integração com notificações (email/Slack)
- [ ] Exportação para CSV/PDF
- [ ] Auditoria de operações

## 📄 Licença

[Especificar licença do projeto]

## 🤝 Contribuindo

Veja [CONTRIBUTING.md](docs/CONTRIBUTING.md) para diretrizes.

---

**Dúvidas?** Abra uma [issue](https://github.com/seu-usuario/Licenses-Manager/issues) ou consulte a documentação.