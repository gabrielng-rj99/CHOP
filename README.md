# Contracts Manager

Gerenciador centralizado de contratos e licenças de software. Rastreie, valide e controle todas as suas licenças em um único lugar com integridade de dados garantida.

## ⚡ Quick Start

### Pré-requisitos

**Backend:**
- Go 1.21+
- SQLite 3 (incluído no sistema)

**Frontend:**
- Node.js 18+
- npm ou yarn

### Instalação

#### Backend (API Server)

```bash
# 1. Navegue até o backend
cd backend

# 2. Instale dependências
go mod tidy

# 3. Execute o servidor
go run cmd/server/main.go
```

O servidor estará disponível em `http://localhost:8080`

#### Frontend

```bash
# 1. Navegue até o frontend
cd frontend

# 2. Instale dependências
npm install

# 3. Configure variáveis de ambiente
cp .env.example .env

# 4. Execute em modo desenvolvimento
npm run dev
```

O frontend estará disponível em `http://localhost:3000`

**Pronto!** O banco de dados SQLite é criado automaticamente na primeira execução do servidor.

## 📚 Documentação

| Documento | Para quem | Tempo |
|-----------|-----------|-------|
| **[SETUP.md](docs/SETUP.md)** | Devs/Ops | 10 min |
| **[USAGE.md](docs/USAGE.md)** | Usuários | 15 min |
| **[ARCHITECTURE.md](docs/ARCHITECTURE.md)** | Devs | 20 min |
| **[CONTRIBUTING.md](docs/CONTRIBUTING.md)** | Contribuidores | 15 min |

## 🎯 Funcionalidades

### Interface Web (Frontend)
- 🎨 Dashboard moderno com estatísticas em tempo real
- 📊 Visualização de contratos expirando e expirados
- 🔐 Sistema de autenticação seguro
- 📱 Design responsivo (mobile-first)
- ⚡ Interface rápida e intuitiva

### API REST (Backend)
- 🔒 Autenticação com Bearer Token
- 📝 CRUD completo para todas as entidades
- ✅ Validações robustas de dados
- 🛡️ Proteção contra brute-force
- 🔄 CORS configurado
- 📡 Endpoints RESTful

### Gerenciar Contratos
- Criar, listar, atualizar e arquivar contratos
- Validação automática de datas
- Status em tempo real: Ativo / Expirando / Expirado
- Notificação de contratos expirando

### Organizar por Categorias
- Antivírus, Banco de Dados, Sistemas Operacionais, etc
- Linhas de produtos (Windows, macOS, Linux, SQL Server, Oracle, etc)
- Filtrar por categoria e linha

### Rastrear Clientes
- Cadastro de empresas (clientes)
- Suporte a dependentes (unidades, filiais)
- Soft delete para auditoria
- Informações detalhadas (contatos, documentos, etc)

### Autenticação e Segurança
- Login com usuário e senha
- Senhas fortes (16+ caracteres)
- Controle de tentativas falhadas
- Sistema de bloqueio automático progressivo
- Roles: user, admin, full_admin

## 🏗️ Estrutura do Projeto

```
Contract-Manager/
├── backend/
│   ├── cmd/
│   │   ├── cli/           # Interface de linha de comando
│   │   ├── server/        # API REST HTTP
│   │   └── tools/         # Utilitários
│   ├── domain/            # Modelos de negócio
│   ├── store/             # Lógica de dados e validações
│   ├── database/          # Camada de persistência
│   └── tests/             # Testes
│
├── frontend/
│   ├── src/
│   │   ├── pages/         # Páginas React
│   │   ├── services/      # Chamadas à API
│   │   ├── store/         # Estado global (Zustand)
│   │   ├── types/         # TypeScript interfaces
│   │   └── utils/         # Funções utilitárias
│   ├── public/            # Assets estáticos
│   └── package.json
│
└── docs/                  # Documentação
```

**Stack Backend:** Go 1.21+ | SQLite | net/http

**Stack Frontend:** React 18 | TypeScript | Vite | Tailwind CSS | Zustand

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

**Backend:**
```bash
cd backend

# Executar todos os testes
go test ./store -v

# Com cobertura
go test ./store -cover

# Testes específicos
go test -run TestContractCreate ./store
```

**Frontend:**
```bash
cd frontend

# Lint
npm run lint

# Type check
npm run type-check
```

## 🚀 Build para Produção

**Backend:**
```bash
cd backend
go build -o contracts-manager cmd/server/main.go
./contracts-manager
```

**Frontend:**
```bash
cd frontend
npm run build
# Arquivos gerados em: frontend/dist/
```

## 📡 API Endpoints

**Autenticação:**
- `POST /api/register` - Registrar novo usuário
- `POST /api/login` - Login

**Contratos:**
- `GET /api/contracts` - Listar contratos
- `POST /api/contracts/create` - Criar contrato
- `GET /api/contracts/get?id=` - Obter contrato
- `PUT /api/contracts/update` - Atualizar contrato
- `DELETE /api/contracts/archive?id=` - Arquivar contrato

**Clientes:**
- `GET /api/clients` - Listar clientes
- `POST /api/clients/create` - Criar cliente
- `GET /api/clients/get?id=` - Obter cliente
- `PUT /api/clients/update` - Atualizar cliente
- `DELETE /api/clients/archive?id=` - Arquivar cliente

**Dependentes:**
- `GET /api/dependents?client_id=` - Listar dependentes
- `POST /api/dependents/create` - Criar dependente
- `PUT /api/dependents/update` - Atualizar dependente
- `DELETE /api/dependents/delete?id=` - Deletar dependente

**Categorias & Linhas:**
- `GET /api/categories` - Listar categorias
- `POST /api/categories/create` - Criar categoria
- `GET /api/lines` - Listar linhas
- `POST /api/lines/create` - Criar linha

## 📋 Roadmap

- [x] API REST completa
- [x] Dashboard web com React
- [x] Autenticação e autorização
- [x] Interface responsiva
- [ ] Importação/Exportação Excel
- [ ] Notificações (email/Slack)
- [ ] Relatórios em PDF
- [ ] Auditoria detalhada com logs
- [ ] Sistema de permissões granular
- [ ] Multi-tenancy

## 🤝 Contribuindo

Veja [CONTRIBUTING.md](docs/CONTRIBUTING.md) para:
- Como configurar ambiente de desenvolvimento
- Convenções de código
- Processo de pull request
- Guia de testes

## 📄 Licença

[Adicionar licença do projeto]

---

## 🎓 Começando

1. **Backend:** Siga as instruções em [Quick Start](#-quick-start) para iniciar o servidor
2. **Frontend:** Configure e execute o frontend
3. **Primeiro Acesso:** Registre um usuário em `/register` ou crie via CLI
4. **Explore:** Acesse o dashboard e comece a gerenciar contratos

## 📚 Mais Informações

- **Frontend:** [frontend/README.md](frontend/README.md)
- **Setup:** [docs/SETUP.md](docs/SETUP.md)
- **Arquitetura:** [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
- **Uso CLI:** [docs/USAGE.md](docs/USAGE.md)
- **Contribuir:** [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md)

**Dúvidas?** Consulte a [documentação completa](docs/) ou abra uma [issue](https://github.com/seu-usuario/Contracts-Manager/issues).