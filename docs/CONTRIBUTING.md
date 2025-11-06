# Contributing — Contracts Manager

Guia para contribuidores. Obrigado por querer melhorar este projeto!

## 🚀 Começando

### 1. Fork e Clone

```bash
git clone https://github.com/seu-usuario/Contracts-Manager.git
cd Contracts-Manager
```

### 2. Criar Branch

```bash
git checkout -b feature/descricao
# ou
git checkout -b fix/descricao
```

**Convenção de nomes:**
- `feature/` — Nova funcionalidade
- `fix/` — Correção de bug
- `docs/` — Documentação
- `refactor/` — Refatoração
- `test/` — Testes

### 3. Setup Local

```bash
cd backend
go mod tidy

# Teste se tudo funciona
go test ./store -v
```

## 📝 Desenvolvendo

### Padrões de Código

```go
// ✓ Bom - função com validação
func (s *ClientStore) CreateClient(client *domain.Client) (string, error) {
    if client == nil {
        return "", errors.New("client cannot be nil")
    }
    
    if len(client.Name) == 0 {
        return "", errors.New("name is required")
    }
    
    id := uuid.New().String()
    // INSERT
    return id, nil
}

// ✗ Ruim - sem validação
func CreateClient(client domain.Client) string {
    id := uuid.New().String()
    return id
}
```

### Estrutura de Método

1. Validações de entrada
2. Regras de negócio
3. Persistência
4. Retorno (ID ou erro)

### Exemplo: Adicionar Validação

**1. Domain** (`domain/models.go`):
```go
type Contract struct {
    Model     string
    ProductKey string
    // ...
}
```

**2. Store** (`store/contract_store.go`):
```go
func (s *ContractStore) Create(contract *domain.Contract) (string, error) {
    // Validação: model não vazio
    if len(contract.Model) < 1 || len(contract.Model) > 255 {
        return "", fmt.Errorf("model must be 1-255 characters")
    }
    
    // Validação: datas válidas
    if !contract.StartDate.Before(contract.EndDate) {
        return "", errors.New("end_date must be after start_date")
    }
    
    // ... resto da lógica ...
    return id, nil
}
```

**3. Test** (`store/contract_test.go`):
```go
func TestCreateContract_ValidatesModel(t *testing.T) {
    store := setupTestStore()
    
    contract := &domain.Contract{
        Model: "", // inválido
    }
    
    _, err := store.Create(contract)
    
    require.Error(t, err)
    require.Contains(t, err.Error(), "model must be 1-255")
}

func TestCreateContract_ValidatesDates(t *testing.T) {
    store := setupTestStore()
    
    contract := &domain.Contract{
        Model:     "Windows 10",
        StartDate: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
        EndDate:   time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC), // ❌
    }
    
    _, err := store.Create(contract)
    
    require.Error(t, err)
    require.Contains(t, err.Error(), "end_date must be after start_date")
}
```

**4. Database** (`database/init.sql`):
```sql
ALTER TABLE contracts 
ADD CONSTRAINT check_model_length 
CHECK (char_length(model) >= 1 AND char_length(model) <= 255);

ALTER TABLE contracts 
ADD CONSTRAINT check_dates 
CHECK (end_date > start_date);
```

## 🧪 Testes

### Rodar Testes

```bash
cd backend

# Todos os testes
go test ./store -v

# Com cobertura
go test ./store -cover

# Teste específico
go test -run TestCreateContract ./store -v

# Com race detector
go test -race ./store
```

### Escrever Testes

Padrão: **Arrange → Act → Assert**

```go
func TestCreateContract_Success(t *testing.T) {
    // ARRANGE: Setup
    store := setupTestStore()
    contract := &domain.Contract{
        Model:      "Windows 10",
        ProductKey: "KEY123",
        StartDate:  time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
        EndDate:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
        LineID:     "line-id",
        ClientID:   "client-id",
    }
    
    // ACT: Executa
    id, err := store.Create(contract)
    
    // ASSERT: Verifica
    require.NoError(t, err)
    require.NotEmpty(t, id)
    
    // Verifica se foi salvo
    saved, err := store.GetByID(id)
    require.NoError(t, err)
    require.Equal(t, contract.Model, saved.Model)
}

func TestCreateContract_InvalidDates(t *testing.T) {
    store := setupTestStore()
    contract := &domain.Contract{
        Model:     "Windows 10",
        StartDate: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
        EndDate:   time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC), // ❌
    }
    
    _, err := store.Create(contract)
    
    require.Error(t, err)
    require.Contains(t, err.Error(), "end_date must be after start_date")
}
```

### Cobertura Esperada

- ✅ Caso de sucesso
- ✅ Validações (cada campo)
- ✅ Erros (FK não encontrada, etc)
- ✅ Edge cases (limites, valores nulos)
- ✅ Integridade referencial

### Status Atual

```bash
go test ./store -v
# 114+ testes ✅
```

## 📋 Checklist Antes de Submeter

- [ ] Código segue convenções do projeto
- [ ] Testes passam: `go test ./store -v`
- [ ] Testes adicionados para nova funcionalidade
- [ ] Documentação atualizada (se necessário)
- [ ] Commits com mensagens descritivas
- [ ] Sem console.log/print statements
- [ ] Sem dependências desnecessárias
- [ ] Rodou linter: `go fmt ./...`

## 🔄 Processo de Pull Request

### 1. Fazer Commits

```bash
git add .
git commit -m "feat: validar datas em contratos"
```

**Convenção Conventional Commits:**
- `feat:` — Nova funcionalidade
- `fix:` — Correção de bug
- `docs:` — Documentação
- `refactor:` — Refatoração
- `test:` — Testes
- `chore:` — Manutenção

### 2. Push

```bash
git push origin feature/descricao
```

### 3. Abrir Pull Request

No GitHub:
1. Compare e crie PR
2. Descreva as mudanças
3. Referencie issues relacionadas (`Closes #123`)
4. Aguarde review

**Template de PR:**

```markdown
## Descrição
O que foi feito e por quê.

## Tipo de Mudança
- [ ] Bug fix
- [ ] Nova funcionalidade
- [ ] Breaking change
- [ ] Documentação

## Testes
- [ ] Testes adicionados
- [ ] Testes passam: go test ./store -v

## Checklist
- [ ] Código segue o padrão
- [ ] Documentação atualizada
- [ ] Sem warnings
```

## 🎨 Padrões de Código

### Go

```go
// ✓ Bom
func (s *ClientStore) GetByID(id string) (*domain.Client, error) {
    if id == "" {
        return nil, errors.New("id cannot be empty")
    }

    client := &domain.Client{}
    err := s.db.QueryRow("SELECT id, name, registration_id FROM clients WHERE id = $1", id).
        Scan(&client.ID, &client.Name, &client.RegistrationID)
    
    if err == sql.ErrNoRows {
        return nil, fmt.Errorf("client not found: %s", id)
    }
    
    if err != nil {
        return nil, err
    }

    return client, nil
}

// ✗ Ruim
func GetClient(id string) (domain.Client, error) {
    row := db.QueryRow("SELECT * FROM clients WHERE id = ?", id)
    var c domain.Client
    row.Scan(&c)
    return c, nil
}
```

### Nomenclatura

```go
// Funções
Create, GetByID, GetAll, Update, Archive, Delete

// Variáveis
clientID, startDate, hasContracts, maxRetries

// Constantes
const (
    MAX_NAME_LENGTH = 255
    DEFAULT_TIMEOUT = 30 * time.Second
)
```

### Erros

```go
// ✓ Descritivo
return fmt.Errorf("contract not found: %s", id)
return fmt.Errorf("end_date must be after start_date, got %s <= %s", 
    endDate, startDate)

// ✗ Genérico
return errors.New("error")
return errors.New("invalid")
```

### Comentários

```go
// ✓ Explica o porquê
// Soft delete preserva histórico para auditoria
client.ArchivedAt = time.Now()

// ✗ Óbvio
// Set archived_at to now
client.ArchivedAt = time.Now()
```

## 📚 Atualizar Documentação

Se adicionar funcionalidade, atualize:

- **[USAGE.md](USAGE.md)** — Novo comando ou caso de uso
- **[ARCHITECTURE.md](ARCHITECTURE.md)** — Mudanças arquiteturais
- **Comentários inline** — Para lógica complexa

Exemplo:

```markdown
### Arquivar Contrato

Menu → `5. Contracts` → `4. Archive`

Marca como arquivado (soft delete), preservando histórico.
```

## 🐛 Reportar Bugs

Abra uma issue com:

1. **Descrição clara** do problema
2. **Passos para reproduzir**
3. **Comportamento esperado vs atual**
4. **Versão do Go, SO**
5. **Logs/screenshots**

Exemplo:

```
## Descrição
Ao criar contrato com datas invertidas, o sistema aceita.

## Reproduzir
1. Menu → Contracts → Create
2. Start Date: 2026-01-01
3. End Date: 2025-01-01
4. Clique Create

## Esperado
Erro: "end_date must be after start_date"

## Atual
Contrato criado sem erro

## Ambiente
- Go 1.25
- PostgreSQL 12+
```

## 💡 Sugestões de Funcionalidades

Abra uma issue com `enhancement` label ou discussion.

Descreva:
- Problema que resolve
- Solução proposta
- Alternativas consideradas
- Impacto no sistema

## 📖 Referências

- [Golang Code Review Comments](https://github.com/golang/go/wiki/CodeReviewComments)
- [Conventional Commits](https://www.conventionalcommits.org/)
- [Clean Code](https://www.oreilly.com/library/view/clean-code-a/9780136083238/)

## ✅ Diretrizes de Review

### O que Aceitar

✅ Correções de bugs com testes
✅ Novas funcionalidades bem planejadas
✅ Melhorias de documentação
✅ Refatorações que não quebram API
✅ Testes adicionais
✅ Performance improvements

### O que Não Aceitar

❌ Mudanças de estilo sem justificativa
❌ Código sem testes
❌ Breaking changes sem discussão
❌ Dependências desnecessárias
❌ Código com warnings
❌ Documentação não atualizada

## 🏆 Boas Práticas

1. **Commits atômicos** — Um conceito por commit
2. **Testes primeiro** — TDD ou cobertura após
3. **Documentação** — Atualizar sempre
4. **Review próprio** — Ler diff antes de submeter
5. **Comunicação** — Explicar decisões técnicas

## 🎯 Iniciativas Bem-Vindas

- ✅ Novos testes
- ✅ Melhorias de performance
- ✅ Correções de bugs
- ✅ Refatorações
- ✅ Documentação
- ✅ Exemplos de uso

## 📞 Precisa de Ajuda?

- 💬 Abra uma [discussion](https://github.com/seu-usuario/Contracts-Manager/discussions)
- 🐛 Reporte um [bug](https://github.com/seu-usuario/Contracts-Manager/issues)
- 📖 Leia [ARCHITECTURE.md](ARCHITECTURE.md)
- 📚 Consulte [USAGE.md](USAGE.md)

---

**Obrigado por contribuir!** 🙌

Qualquer dúvida, abra uma issue ou discussion. Estamos aqui para ajudar!