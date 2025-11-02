# Contracts Manager

Gerenciador centralizado de contratos e licenças de software. Rastreie, valide e controle todas as suas licenças em um único lugar com integridade de dados garantida.

## ⚡ Quick Start

### Pré-requisitos
- Go 1.21+
- SQLite 3 (incluído no sistema)

### Instalação em 3 passos

```bash
# 1. Clone o repositório
git clone https://github.com/seu-usuario/Contracts-Manager.git
cd Contracts-Manager/backend

# 2. Instale dependências
go mod tidy

# 3. Execute
go run cmd/cli/main.go
```

**Pronto!** O banco de dados SQLite é criado automaticamente na primeira execução.

## 📚 Documentação

| Documento | Para quem | Tempo |
|-----------|-----------|-------|
| **[SETUP.md](docs/SETUP.md)** | Devs/Ops | 10 min |
| **[USAGE.md](docs/USAGE.md)** | Usuários | 15 min |
| **[ARCHITECTURE.md](docs/ARCHITECTURE.md)** | Devs | 20 min |
| **[CONTRIBUTING.md](docs/CONTRIBUTING.md)** | Contribuidores | 15 min |

## 🎯 O que você pode fazer

### Gerenciar Contratos
- Criar, listar, atualizar e arquivar contratos
- Validação automática de datas
- Status em tempo real: Ativo / Expirando / Expirado

### Organizar por Categorias
- Antivírus, Banco de Dados, Sistemas Operacionais, etc
- Linhas de produtos (Windows, macOS, Linux, SQL Server, Oracle, etc)
- Filtrar por categoria e linha

### Rastrear Clientes
- Cadastro de empresas (clientes)
- Suporte a dependentes (unidades, filiais)
- Soft delete para auditoria

### Autenticação
- Login com usuário e senha
- Controle de tentativas falhadas
- Sistema de bloqueio automático

## 🏗️ Estrutura

```
backend/
├── cmd/
│   ├── cli/           # Interface de linha de comando
│   ├── server/        # API (futuro)
│   └── tools/         # Utilitários (criar admin, etc)
├── domain/            # Modelos de negócio
├── store/             # Lógica de dados e validações
├── database/          # Camada de persistência
├── config/            # Configurações
└── tests/             # Testes (integrados nos arquivos)
```

**Stack:** Go 1.21+ | SQLite | CLI

## 📊 Entidades Principais

| Entidade | O que é |
|----------|---------|
| **Client** | Empresa/cliente |
| **Dependent** | Unidade, filial ou subsidiária |
| **Category** | Classificação (Antivírus, SO, DB) |
| **Line** | Produto específico (Windows 10, Oracle 19c) |
| **Contract** | Contrato/licença com datas |
| **User** | Usuário com autenticação |

## 🔄 Relacionamentos

```
Client → Dependents (1:N)
Client → Contracts (1:N)
Dependent → Contracts (1:N, opcional)
Category → Lines (1:N)
Line → Contracts (1:N)
```

## 🛡️ Regras de Negócio

- ✅ Validação de datas (end_date > start_date)
- ✅ Não há sobreposição temporal de contratos
- ✅ Clientes podem ser arquivados (soft delete)
- ✅ Integridade referencial garantida
- ✅ Status automático baseado em datas

## 🧪 Testes

```bash
cd backend

# Executar todos os testes
go test ./store -v

# Com cobertura
go test ./store -cover

# Testes específicos
go test -run TestContractCreate ./store
```

## 🚀 Build para Produção

```bash
cd backend
go build -o contracts-manager cmd/cli/main.go
./contracts-manager
```

## 📋 Roadmap

- [ ] API REST
- [ ] Dashboard web
- [ ] Notificações (email/Slack)
- [ ] Exportação (CSV/PDF)
- [ ] Auditoria detalhada

## 🤝 Contribuindo

Veja [CONTRIBUTING.md](docs/CONTRIBUTING.md) para:
- Como configurar ambiente de desenvolvimento
- Convenções de código
- Processo de pull request
- Guia de testes

## 📄 Licença

[Adicionar licença do projeto]

---

**Primeira vez?** Siga o [Quick Start](#-quick-start) acima, depois leia [SETUP.md](docs/SETUP.md).

**Dúvidas?** Consulte a [documentação completa](docs/) ou abra uma [issue](https://github.com/seu-usuario/Contracts-Manager/issues).