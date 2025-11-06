# Architecture — Contracts Manager

Visão técnica do sistema, padrões adotados e diretrizes de desenvolvimento.

## 🏗️ Visão Geral

Contracts Manager é um sistema para gerenciar contratos e licenças de software com validações robustas. Backend em Go, estruturado em camadas com foco em testabilidade, integridade de dados e separação de responsabilidades.

```
┌─────────────────────────────┐
│      CLI / Interface        │  (cmd/cli)
│   (Menu interativo)         │
├─────────────────────────────┤
│     Stores & Handlers       │  (store/)
│   - Business Logic          │
│   - Validations             │
│   - Data Access             │
├─────────────────────────────┤
│     Domain Models           │  (domain/)
│   - Structs                 │
│   - Value Objects           │
├─────────────────────────────┤
│   Database Layer            │  (database/)
│   - PostgreSQL              │
│   - Migrations              │
└─────────────────────────────┘
```

## 📂 Estrutura de Diretórios

```
backend/
├── cmd/
│   ├── cli/
│   │   └── main.go           # Ponto de entrada (menu CLI)
│   ├── server/
│   │   └── main.go           # API (futuro)
│   └── tools/
│       └── main.go           # Utilitários (criar admin, etc)
├── domain/
│   └── models.go             # Structs (Client, Contract, User, etc)
├── store/
│   ├── client_store.go       # CRUD + lógica de client
│   ├── contract_store.go     # CRUD + lógica de contract
│   ├── user_store.go         # CRUD + autenticação
│   ├── category_store.go     # CRUD + categorias
│   ├── dependent_store.go    # CRUD + dependentes
│   ├── store_interfaces.go   # Interfaces
│   └── *_test.go             # Testes unitários (114+)
├── database/
│   ├── database.go           # Conexão e inicialização
│   └── init.sql              # Schema e migrations
├── config/
│   └── config.go             # Configurações e ambiente
└── tests/
    └── (integrados nos *_test.go)
```

## 🔄 Fluxo de Dados

### Exemplo: Criar Contrato

```
1. CLI → Pede dados ao usuário
          ↓
2. Validação → Formatos e valores básicos
          ↓
3. Store → ContractStore.Create()
    - Valida FK (cliente, linha)
    - Verifica sobreposição de datas
    - Valida cliente não arquivado
    - Garante integridade referencial
          ↓
4. Database → INSERT contrato
          ↓
5. Retorna → UUID do contrato criado
```

## 🏛️ Padrões Adotados

### 1. Repository Pattern

Cada entidade tem um Store (repositório):

```go
// store/contract_store.go
type ContractStore struct {
    db *sql.DB
}

func (s *ContractStore) Create(contract domain.Contract) (string, error) {
    // Validações
    // INSERT
    // Retorna ID
}

func (s *ContractStore) GetByID(id string) (*domain.Contract, error) {
    // SELECT
}
```

### 2. Separação em Camadas

- **Domain:** Modelos puros, sem dependências externas
- **Store:** Lógica de negócio + acesso a dados
- **CLI:** Interface com usuário
- **Database:** Persistência

### 3. Validação em Múltiplos Níveis

```go
// Nível 1: Tipo (Go garante tipos)
type Contract struct {
    StartDate time.Time  // Not nullable
    EndDate   time.Time
}

// Nível 2: Business Logic (Store)
if !contract.StartDate.Before(contract.EndDate) {
    return fmt.Errorf("end_date must be after start_date")
}

// Nível 3: Database (Constraints)
ALTER TABLE contracts ADD CONSTRAINT 
    check_dates CHECK (end_date > start_date);
```

### 4. Soft Delete para Auditoria

Entidades não são deletadas, apenas marcadas:

```go
type Client struct {
    ID        string
    Name      string
    ArchivedAt *time.Time  // nil = ativo, com data = arquivado
}

// Queries sempre filtram
SELECT * FROM clients WHERE archived_at IS NULL;
```

### 5. Validação de Relacionamentos

Antes de criar contrato:

```go
// 1. Verifica se cliente existe
if err := cs.ClientExists(contract.ClientID); err != nil {
    return err
}

// 2. Verifica se linha existe
if err := ls.LineExists(contract.LineID); err != nil {
    return err
}

// 3. Verifica se cliente está ativo
client, _ := cs.GetByID(contract.ClientID)
if client.ArchivedAt != nil {
    return errors.New("cannot create contract for archived client")
}
```

## 📊 Modelo de Dados

### Relacionamentos

```
┌──────────────┐
│  Clients     │
└──────┬───────┘
       │ 1:N
       ├─→ Dependents (filiais)
       └─→ Contracts (licenças)

┌──────────────┐
│ Categories   │
└──────┬───────┘
       │ 1:N
       └─→ Lines (produtos)
           │ 1:N
           └─→ Contracts

┌──────────────┐
│  Contracts   │ (centro do modelo)
└──────┬───────┘
       ├─→ Clients (quem tem)
       ├─→ Lines (o que é)
       ├─→ Dependents (onde, opcional)
       └─→ Status (calculado automaticamente)

┌──────────────┐
│   Users      │ (autenticação)
└──────────────┘
```

### Entidades

| Entidade | Descrição | Relacionamentos |
|----------|-----------|-----------------|
| **Client** | Empresa/cliente | N dependents, N contracts |
| **Dependent** | Filial/unidade | 1 client, N contracts |
| **Category** | Classificação (Antivírus, DB, SO) | N lines |
| **Line** | Produto específico (Windows 10, Oracle 19c) | 1 category, N contracts |
| **Contract** | Contrato/licença com datas | 1 client, 1 line, 0-1 dependent |
| **User** | Usuário com autenticação | 1 client (atribuível) |

### Constraints Principais

- `registration_id` (CNPJ) único em clients
- Nome + CategoryID único em lines
- Nome + ClientID único em dependents
- `end_date > start_date` em contracts
- Sem sobreposição temporal para mesma linha/cliente
- Soft delete via `archived_at` NOT NULL

## 🛡️ Validações de Negócio

| Regra | Local | Erro |
|-------|-------|------|
| CNPJ válido | Store | ValidationError |
| Datas válidas | Store + DB | ValidationError |
| Cliente existe | Store | NotFoundError |
| Cliente não arquivado | Store | StateError |
| Sem sobreposição de datas | Store + DB | ConstraintError |
| Linha existe | Store | NotFoundError |
| Dependente existe (se informado) | Store | NotFoundError |
| Nome único na categoria | Database | ConstraintError |
| Integridade referencial | Database | ConstraintError |

## 🧪 Testes

### Estrutura

```
backend/store/
├── client_test.go           # 28 testes
├── contract_test.go         # 33 testes
├── user_test.go             # 19 testes
├── category_test.go         # 17 testes
├── lines_test.go            # 26 testes
├── dependent_test.go        # 11 testes
├── validation_test.go       # 4 testes
├── errors_test.go           # 6 testes
├── types_test.go            # 5 testes
└── integration_test.go      # 3 testes

Total: 114+ testes
```

### Padrão de Teste

```go
func TestCreateContract_ValidatesDates(t *testing.T) {
    contract := domain.Contract{
        Model:     "Windows 10",
        StartDate: time.Now(),
        EndDate:   time.Now().AddDate(-1, 0, 0),  // Data anterior!
    }
    
    _, err := store.Create(contract)
    
    require.Error(t, err)
    require.Contains(t, err.Error(), "end_date must be after start_date")
}
```

### Cobertura

- ✅ Casos de sucesso
- ✅ Validações
- ✅ Erros
- ✅ Edge cases
- ✅ Integridade referencial

## 🔐 Segurança

- **Prepared Statements:** Previnem SQL Injection
- **Validação de Input:** Todos os dados validados antes de usar
- **Soft Delete:** Histórico mantido para auditoria
- **Transações:** Operações multi-tabela são atômicas
- **Autenticação:** Sistema de usuários com roles
- **Proteção contra força bruta:** Bloqueio automático após falhas

## 📝 Convenções de Código

### Nomenclatura

- **Structs:** PascalCase (`Client`, `Contract`, `User`)
- **Métodos:** PascalCase (`Create`, `GetByID`, `Archive`)
- **Variáveis:** camelCase (`clientID`, `startDate`, `hasLicenses`)
- **Constantes:** UPPER_SNAKE_CASE (`MAX_NAME_LENGTH`, `DEFAULT_PAGE_SIZE`)
- **Arquivos:** snake_case (`client_store.go`, `contract_test.go`)

### Erros

```go
// ✓ Bom - descritivo
return fmt.Errorf("contract not found: %s", id)
return fmt.Errorf("end_date must be after start_date")
return fmt.Errorf("overlapping contract dates for line %s", lineID)

// ✗ Ruim - genérico
return errors.New("error")
return errors.New("invalid")
```

### Comentários

```go
// ✓ Explica o por quê
// Soft delete preserva histórico para auditoria
client.ArchivedAt = time.Now()

// ✗ Óbvio
// Set archived at to now
client.ArchivedAt = time.Now()
```

## 🔗 Dependências Externas Mínimas

```
github.com/google/uuid        # Geração de IDs (UUID v4)
github.com/jackc/pgx/v5/stdlib # Driver PostgreSQL
golang.org/x/crypto           # Hashing de senhas
```

**Stack:** Go stdlib + PostgreSQL (desenvolvimento e produção)


## 🚀 Escalabilidade e Evolução

### Preparado Para

- ✅ Múltiplas unidades por cliente (Dependents)
- ✅ Histórico de operações (via soft delete)
- ✅ Filtros complexos (por categoria, linha, status, período)
- ✅ Expiração automática de contratos
- ✅ Sistema de usuários com permissões
- ✅ Migração para PostgreSQL em produção

### Roadmap Futuro

**v1.1:**
- [ ] API REST
- [ ] Paginação em listagens
- [ ] Filtros avançados
- [ ] Export CSV/PDF

**v2.0:**
- [ ] Dashboard web
- [ ] Notificações (email/Slack)
- [ ] Auditoria detalhada
- [ ] Integração com sistemas externos

## 🤝 Para Desenvolvedores

### Adicionar Nova Entidade

1. Definir struct em `domain/models.go`
2. Criar store em `store/new_entity_store.go`
3. Criar testes em `store/new_entity_store_test.go`
4. Atualizar `database/init.sql` com tabela
5. Integrar no menu CLI (`cmd/cli/main.go`)

### Exemplo: Adicionar Campo a Contrato

**1. Domain** (`domain/models.go`):
```go
type Contract struct {
    // ... campos existentes ...
    Notes string  // Novo campo
}
```

**2. Store** (`store/contract_store.go`):
```go
// UPDATE query para incluir Notes
// Validação se necessário

func (s *ContractStore) Create(contract domain.Contract) (string, error) {
    if len(contract.Notes) > 1000 {
        return "", errors.New("notes must be 1000 characters or less")
    }
    // ... INSERT com Notes ...
}
```

**3. Tests** (`store/contract_test.go`):
```go
func TestCreateContract_WithNotes(t *testing.T) {
    contract := domain.Contract{
        // ... dados necessários ...
        Notes: "Licença para departamento de TI",
    }
    
    id, err := store.Create(contract)
    require.NoError(t, err)
    // Verificar se Notes foi salvo
}
```

**4. Database** (`database/init.sql`):
```sql
ALTER TABLE contracts ADD COLUMN notes TEXT;
```

### Executar Testes Localmente

```bash
cd backend

# Todos os testes
go test ./store -v

# Com cobertura
go test ./store -cover

# Teste específico
go test -run TestContractCreate ./store -v

# Com race detector
go test -race ./store
```

### Linting e Formatação

```bash
# Formatar código
go fmt ./...

# Lint
golangci-lint run ./...

# Análise estática
go vet ./...
```

## 📚 Referências Técnicas

### Database Layer

- Prepared statements para todas as queries
- Connection pooling automático via `database/sql`
- Transações para operações multi-tabela
- Índices em ForeignKeys e campos de busca

### Performance

- PostgreSQL para desenvolvimento e produção (escalável)
- Índices em campos frequentemente consultados
- Lazy loading de relacionamentos

## 🔍 Debugging

### Logs

```go
// Adicione em desenvolvimento
log.Printf("Creating contract: %+v", contract)
log.Printf("Query: %s", query)
```

### Testes Isolados

```bash
# Teste uma função específica
go test -run TestContractCreate ./store -v

# Com debugging
go test -v -run TestContractCreate ./store --race
```

### Inspeção de Banco

PostgreSQL:
```bash
psql $POSTGRES_DB -c "\dt"
psql $POSTGRES_DB -c "SELECT * FROM contracts LIMIT 5;"
```

PostgreSQL:
```bash
psql -d contracts_manager -c "\dt"
psql -d contracts_manager -c "SELECT * FROM contracts LIMIT 5;"
```

## 📖 Leitura Recomendada

- [Go Code Review Comments](https://github.com/golang/go/wiki/CodeReviewComments)
- [Effective Go](https://golang.org/doc/effective_go)
- [Domain-Driven Design](https://www.domainlanguage.com/ddd/)
- [Clean Architecture](https://blog.cleancoder.com/uncle-bob/2012/08/13/the-clean-architecture.html)

---

**Para usar o sistema:** Veja [USAGE.md](USAGE.md)
**Para instalar:** Veja [SETUP.md](SETUP.md)
**Para contribuir:** Veja [CONTRIBUTING.md](CONTRIBUTING.md)