# Architecture — Licenses Manager

Visão técnica do sistema, padrões adotados e diretrizes de desenvolvimento.

## 🏗️ Visão Geral

Licenses Manager é um sistema modular para gestão de licenças de software. Backend em Go, estruturado em camadas com foco em testabilidade e separação de responsabilidades.

```
┌─────────────────────────────┐
│      CLI / Interface        │  (cmd/cli)
├─────────────────────────────┤
│     Stores & Handlers       │  (store/)
│   - Business Rules          │
│   - Validations             │
├─────────────────────────────┤
│     Domain Models           │  (domain/)
│   - Structs                 │
│   - Interfaces              │
├─────────────────────────────┤
│   Database Layer            │  (database/)
│   - PostgreSQL              │
│   - Migrations              │
└─────────────────────────────┘
```

## 📂 Estrutura de Diretórios

```
backend/
├── cmd/cli/
│   └── main.go              # Ponto de entrada, menu CLI
├── domain/
│   ├── client.go            # Struct Client (empresa)
│   ├── entity.go            # Struct Entity (unidade)
│   ├── category.go          # Struct Category
│   ├── line.go              # Struct Line
│   ├── license.go           # Struct License
│   └── user.go              # Struct User
├── store/
│   ├── client_store.go      # CRUD + lógica de empresa
│   ├── entity_store.go      # CRUD + lógica de unidade
│   ├── category_store.go    # CRUD + lógica de categoria
│   ├── line_store.go        # CRUD + lógica de linha
│   ├── license_store.go     # CRUD + lógica de licença
│   └── user_store.go        # CRUD + lógica de usuário
├── database/
│   ├── init.sql             # Schema e tabelas
│   ├── diagram.drawio       # Diagrama ER
│   └── migrations/          # Scripts de evolução
└── tests/
    └── store/               # Testes unitários dos stores
```

## 🔄 Fluxo de Dados

### Exemplo: Criar Licença

```
1. CLI → Pede dados ao usuário
          ↓
2. Validação → Verifica formato e valores
          ↓
3. Store → LicenseStore.Create()
    - Valida FK (empresa, linha)
    - Verifica sobreposição de datas
    - Valida empresa não arquivada
          ↓
4. Database → INSERT licença
          ↓
5. Retorna → UUID da licença criada
```

## 🏛️ Padrões Adotados

### 1. **Separação em Camadas**

- **Domain:** Modelos puros, sem dependências externas
- **Store:** Lógica de negócio + acesso a dados
- **CLI:** Interface com usuário
- **Database:** Persistência

### 2. **Validação em Múltiplos Níveis**

```go
// Nível 1: Tipo (Go garante tipos)
type License struct {
    StartDate time.Time  // Not nullable
    EndDate   time.Time
}

// Nível 2: Business Logic (Store)
if !license.StartDate.Before(license.EndDate) {
    return fmt.Errorf("end_date must be after start_date")
}

// Nível 3: Database (Constraints)
ALTER TABLE licenses ADD CONSTRAINT 
    check_dates CHECK (end_date > start_date);
```

### 3. **Soft Delete para Auditoria**

Empresas arquivadas não são deletadas, apenas marcadas:

```go
type Client struct {
    ID        string
    Name      string
    ArchivedAt *time.Time  // nil = ativo, com data = arquivado
}

// Queries sempre filtram
SELECT * FROM companies WHERE archived_at IS NULL;
```

### 4. **Validação de Relacionamentos**

Antes de criar licença:

```go
// 1. Verifica se empresa existe
if err := cs.ClientExists(license.ClientID); err != nil {
    return err
}

// 2. Verifica se linha existe
if err := ls.LineExists(license.LineID); err != nil {
    return err
}

// 3. Verifica se empresa está ativa
client, _ := cs.GetByID(license.ClientID)
if client.ArchivedAt != nil {
    return errors.New("cannot create license for archived company")
}
```

## 📊 Modelo de Dados

### Relacionamentos

```
┌──────────────┐
│  Companies   │
└──────┬───────┘
       │ 1:N
       ├─→ Entities (unidades)
       └─→ Licenses

┌──────────────┐
│ Categories   │
└──────┬───────┘
       │ 1:N
       └─→ Lines (marcas)
           │
           └─→ Licenses

┌──────────────┐
│   Licenses   │ (centro do modelo)
└──────┬───────┘
       ├─→ Companies (empresa)
       ├─→ Lines (tipo/marca)
       └─→ Entities (unidade, opcional)
```

### Constraints Principais

- `registration_id` (CNPJ) único em companies
- Nome + CategoryID único em lines
- Nome + ClientID único em entities
- `end_date > start_date` em licenses
- Sem sobreposição temporal para mesma linha/empresa

## 🛡️ Validações de Negócio

| Regra | Local | Erro |
|-------|-------|------|
| CNPJ válido | Store | ValidationError |
| Datas válidas | Store | ValidationError |
| Empresa existe | Store | NotFoundError |
| Empresa não arquivada | Store | StateError |
| Sem sobreposição de datas | Store | ConstraintError |
| Linha existe | Store | NotFoundError |
| Nome único na categoria | Database | ConstraintError |

## 🧪 Testes

### Estrutura

```
tests/
└── store/
    ├── client_store_test.go
    ├── entity_store_test.go
    ├── category_store_test.go
    ├── line_store_test.go
    ├── license_store_test.go
    └── mocks/
        └── db_mock.go
```

### Exemplo de Teste

```go
func TestCreateLicense_ValidatesDates(t *testing.T) {
    license := domain.License{
        Name:      "Windows 10",
        StartDate: time.Now(),
        EndDate:   time.Now().AddDate(-1, 0, 0),  // Data anterior!
    }
    
    _, err := store.Create(license)
    
    require.Error(t, err)
    require.Contains(t, err.Error(), "end_date must be after start_date")
}
```

## 🔐 Segurança

- **Prepared Statements:** Previnem SQL Injection
- **Validação de Input:** Todos os dados validados antes de usar
- **Soft Delete:** Histórico mantido
- **Transações:** Operações multi-tabela são atômicas

## 🚀 Escalabilidade

### Possibilidades Futuras

1. **API REST:** Expor endpoints para integração
2. **Cache:** Redis para consultas frequentes
3. **Workers:** Background jobs para notificações
4. **Audit Log:** Tabela separada para rastreamento

### Design Preparado Para

- Múltiplas unidades por empresa ✓
- Histórico de operações (via soft delete) ✓
- Filtros complexos (categoria, linha, status) ✓
- Expiração automática de licenças ✓

## 📝 Convenções de Código

### Nomenclatura

- **Structs:** PascalCase (`Client`, `License`)
- **Métodos:** PascalCase (`Create`, `GetByID`)
- **Variáveis:** camelCase (`clientID`, `startDate`)
- **Constantes:** UPPER_SNAKE_CASE (`MAX_NAME_LENGTH`)

### Erros

```go
// ✓ Bom
return fmt.Errorf("license not found: %s", id)

// ✗ Ruim
return errors.New("error")
```

### Comentários

```go
// ✓ Explica o por quê
// Soft delete preserva histórico para auditoria
client.ArchivedAt = time.Now()

// ✗ Óbvio
// Set archived at to now
```

## 🔗 Dependências Externas Mínimas

- `database/sql` — Padrão Go
- `postgresql` — Driver do banco
- `uuid` — Geração de IDs
- Sem frameworks pesados (testabilidade)

## 📚 Evolução Planejada

### v1.0 (Atual)
- ✓ CLI funcional
- ✓ Todas as entidades
- ✓ Testes unitários

### v1.1
- [ ] API REST
- [ ] Paginação em listagens
- [ ] Filtros avançados

### v2.0
- [ ] Dashboard web
- [ ] Notificações (email/Slack)
- [ ] Relatórios (PDF/CSV)
- [ ] Auditoria detalhada

## 🤝 Para Desenvolvedores

### Adicionar Nova Entidade

1. Criar `domain/new_entity.go` com struct
2. Criar `store/new_entity_store.go` com CRUD
3. Criar `tests/store/new_entity_store_test.go`
4. Atualizar `database/init.sql` com tabela
5. Integrar no menu CLI (`cmd/cli/main.go`)

### Executar Testes

```bash
cd backend
go test ./tests/store -v
go test ./tests/store -cover
```

### Adicionar Validação

Sempre em dois lugares:

```go
// 1. No Store (lógica)
if len(name) < 1 || len(name) > 255 {
    return errors.New("name must be 1-255 characters")
}

// 2. No Database (constraint)
ALTER TABLE companies 
ADD CONSTRAINT check_name_length 
CHECK (char_length(name) >= 1 AND char_length(name) <= 255);
```

---

**Para usar o sistema:** Veja [USAGE.md](USAGE.md)
**Para instalar:** Veja [SETUP.md](SETUP.md)