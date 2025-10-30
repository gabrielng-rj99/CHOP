# Contributing — Guia para Contribuidores

Obrigado por querer contribuir com o Licenses Manager! Este documento guia você pelo processo.

## 🚀 Começando

### 1. Fork e Clone

```bash
git clone https://github.com/seu-usuario/Licenses-Manager.git
cd Licenses-Manager
```

### 2. Criar Branch

```bash
git checkout -b feature/minha-feature
# ou
git checkout -b fix/meu-bug
```

**Convenção de nomes:**
- `feature/descricao` — Novas funcionalidades
- `fix/descricao` — Correções de bugs
- `docs/descricao` — Melhorias na documentação
- `refactor/descricao` — Refatorações

### 3. Setup Local

```bash
# Instalar dependências
cd backend
go mod tidy

# Configurar banco de dados
createdb licenses_manager_dev
psql -d licenses_manager_dev -f database/init.sql

# Criar .env
cat > ../.env << EOF
DB_HOST=localhost
DB_PORT=5432
DB_USER=seu_usuario
DB_PASSWORD=sua_senha
DB_NAME=licenses_manager_dev
EOF
```

## 📝 Desenvolvendo

### Estrutura de Código

Siga a estrutura existente:

```
domain/     ← Modelos (sem lógica)
store/      ← Lógica de negócio
cmd/cli/    ← Interface
tests/      ← Testes
database/   ← SQL
```

### Exemplo: Adicionar Validação

**1. Definir no Domain** (`domain/license.go`)

```go
type License struct {
    ID         string
    Name       string
    ProductKey string
    StartDate  time.Time
    EndDate    time.Time
    LineID     string
    ClientID   string
    EntityID   *string
}
```

**2. Implementar no Store** (`store/license_store.go`)

```go
func (s *LicenseStore) Create(license domain.License) (string, error) {
    // Validar
    if license.EndDate.Before(license.StartDate) {
        return "", fmt.Errorf("end_date must be after start_date")
    }
    
    // Persistir
    id := generateUUID()
    // ... INSERT no banco
    
    return id, nil
}
```

**3. Testar** (`tests/store/license_store_test.go`)

```go
func TestCreateLicense_ValidatesDateRange(t *testing.T) {
    store := setupTestStore()
    
    _, err := store.Create(domain.License{
        StartDate: time.Now(),
        EndDate:   time.Now().AddDate(-1, 0, 0),
    })
    
    require.Error(t, err)
    require.Contains(t, err.Error(), "end_date must be after start_date")
}
```

**4. Executar testes**

```bash
go test ./tests/store -v
```

## 🧪 Testes

### Rodar Testes Locais

```bash
cd backend

# Todos os testes
go test ./...

# Com cobertura
go test ./tests/store -cover

# Verbose
go test ./tests/store -v

# Teste específico
go test -run TestCreateLicense ./tests/store
```

### Cobertura de Testes

- Escreva testes para casos de sucesso e erro
- Valide mensagens de erro
- Teste validações de dados
- Teste relacionamentos (FK)

Exemplo:

```go
func TestCreateLicense_Success(t *testing.T) {
    // Caso de sucesso
}

func TestCreateLicense_InvalidDate(t *testing.T) {
    // Validação de data
}

func TestCreateLicense_CompanyNotFound(t *testing.T) {
    // Validação de FK
}
```

## 📋 Checklist Antes de Submeter

- [ ] Código segue as convenções do projeto
- [ ] Testes passam: `go test ./...`
- [ ] Adicionei testes para nova funcionalidade
- [ ] Documentação atualizada (se necessário)
- [ ] Commits com mensagens descritivas
- [ ] Sem console.log/print statements
- [ ] Sem dependências desnecessárias

## 🔄 Processo de Pull Request

### 1. Fazer Commit

```bash
git add .
git commit -m "feat: adicionar validação de data em licenças"
```

**Convenção de mensagens:**
- `feat:` — Nova funcionalidade
- `fix:` — Correção de bug
- `docs:` — Documentação
- `refactor:` — Refatoração
- `test:` — Testes
- `chore:` — Manutenção

### 2. Push

```bash
git push origin feature/minha-feature
```

### 3. Abrir Pull Request

No GitHub:
1. Compare e crie PR
2. Descreva as mudanças
3. Referencie issues relacionadas (`Closes #123`)
4. Aguarde review

### Template de PR

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
- [ ] Testes passam

## Checklist
- [ ] Código segue o padrão
- [ ] Documentação atualizada
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
    // ... query
    
    return client, nil
}

// ✗ Ruim
func GetClient(id string) (domain.Client, error) {
    // sem validação
    // sem ponteiro
}
```

### Nomenclatura

- **Funções:** `Create`, `GetByID`, `Delete`, `List`
- **Variáveis:** `clientID`, `startDate`, `hasLicenses`
- **Constantes:** `MAX_NAME_LENGTH`, `DEFAULT_EXPIRING_DAYS`

### Erros

```go
// ✓ Descritivo
return fmt.Errorf("license expired: %s (end_date: %s)", id, license.EndDate)

// ✗ Genérico
return errors.New("error")
```

### Comentários

```go
// ✓ Explica o por quê
// Soft delete preserva histórico para auditoria
client.ArchivedAt = time.Now()

// ✗ Óbvio
// Set archived_at to now
client.ArchivedAt = time.Now()
```

## 📚 Documentação

Se adicionar funcionalidade, atualize:

- **[USAGE.md](USAGE.md)** — Novo comando ou caso de uso
- **[ARCHITECTURE.md](ARCHITECTURE.md)** — Mudanças arquiteturais
- **Comentários inline** — Para lógica complexa

## 🐛 Relatando Bugs

Abra uma issue com:

1. **Descrição clara** do problema
2. **Passos para reproduzir**
3. **Comportamento esperado vs atual**
4. **Versão do Go, PostgreSQL**
5. **Logs/screenshots**

Exemplo:

```
## Descrição
Ao criar licença com datas invertidas, o sistema aceita.

## Reproduzir
1. Menu → Licenses → Create
2. Informe Start Date: 2025-01-01
3. Informe End Date: 2024-01-01
4. Clique Create

## Esperado
Erro: "end_date must be after start_date"

## Atual
Licença criada sem erro

## Ambiente
- Go 1.21
- PostgreSQL 15
```

## 💡 Ideias e Sugestões

Abra uma discussion ou issue com tag `enhancement`.

Descreva:
- Problema que resolve
- Solução proposta
- Alternativas consideradas
- Impacto no sistema

## 📞 Dúvidas?

1. Consulte a [documentação](../README.md)
2. Abra uma issue com `question` label
3. Verifique issues/PRs fechadas (pode ter resposta)

## ✅ Etiquetas de Issues

- `bug` — Bug confirmado
- `enhancement` — Melhoria/nova feature
- `documentation` — Docs
- `help wanted` — Precisa de ajuda
- `good first issue` — Para começar

## 🎯 Diretrizes

### O que Aceitar

✅ Correções de bugs com testes
✅ Novas funcionalidades bem planejadas
✅ Melhorias de documentação
✅ Refatorações que não quebram API

### O que Não Aceitar

❌ Mudanças de estilo sem justificativa
❌ Código sem testes
❌ Breaking changes sem discussão
❌ Dependências desnecessárias
❌ Código com warnings/lint errors

## 🚀 Mergendo PR

Após aprovação:

```bash
# Atualizar main
git checkout main
git pull origin main

# Deletar branch local
git branch -d feature/minha-feature

# Deletar branch remoto
git push origin --delete feature/minha-feature
```

## 📖 Referências

- [Go Code Review Comments](https://github.com/golang/go/wiki/CodeReviewComments)
- [Conventional Commits](https://www.conventionalcommits.org/)
- [ARCHITECTURE.md](ARCHITECTURE.md) — Design do projeto

---

**Obrigado por contribuir!** 🙌

Qualquer dúvida, abra uma issue ou discussion.