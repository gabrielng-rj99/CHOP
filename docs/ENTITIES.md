Licenses-Manager/docs/ENTITIES.md
# Entidades e Modelos de Dados — Licenses Manager

Este documento detalha todas as entidades do sistema Licenses Manager, seus campos, relacionamentos e principais regras de validação. Serve como referência para desenvolvedores, analistas e revisores de código.

---

## Visão Geral das Entidades

O Licenses Manager organiza os dados em entidades principais, cada uma representando um conceito fundamental do domínio de gestão de licenças de software:

- **Client (Empresa)**
- **Entity (Unidade/Filial)**
- **Category (Categoria de Licença)**
- **Line (Linha/Tipo de Licença)**
- **License (Licença de Software)**
- **User (Usuário do Sistema)**

---

## Estruturas de Dados

### 1. Client (Empresa)

Representa uma empresa cliente que possui licenças e unidades.

```go
type Client struct {
    ID             string     // UUID, obrigatório
    Name           string     // Obrigatório, 1-255 caracteres
    RegistrationID string     // Obrigatório, formato válido (ex: CNPJ)
    ArchivedAt     *time.Time // Opcional, marca soft delete
    CreatedAt      time.Time  // Data de criação
}
```

**Regras:**
- `RegistrationID` deve ser único.
- Não pode ser deletada se possuir licenças ativas (soft delete via `ArchivedAt`).

---

### 2. Entity (Unidade/Filial)

Representa uma unidade física ou departamento vinculado a uma empresa.

```go
type Entity struct {
    ID       string // UUID, obrigatório
    Name     string // Obrigatório, 1-255 caracteres, único por empresa
    ClientID string // Obrigatório, referência à empresa
}
```

**Regras:**
- Só pode existir se o `ClientID` for válido.
- Nome deve ser único dentro da empresa.
- Deleção desassocia licenças (não exclui).

---

### 3. Category (Categoria de Licença)

Classifica as linhas/tipos de licença.

```go
type Category struct {
    ID   string // UUID, obrigatório
    Name string // Obrigatório, 1-255 caracteres, único
}
```

**Regras:**
- Nome deve ser único (case-insensitive).
- Não pode ser deletada se houver linhas associadas.

---

### 4. Line (Linha/Tipo de Licença)

Define tipos específicos de licença dentro de uma categoria.

```go
type Line struct {
    ID         string // UUID, obrigatório
    Name       string // Obrigatório, 1-255 caracteres, único na categoria
    CategoryID string // Obrigatório, referência à categoria
}
```

**Regras:**
- Nome único dentro da categoria.
- Não pode ser deletada se houver licenças associadas.

---

### 5. License (Licença de Software)

Representa uma licença de software vinculada a empresa, linha/tipo e opcionalmente a uma unidade.

```go
type License struct {
    ID         string    // UUID, obrigatório
    Name       string    // Obrigatório, 1-255 caracteres
    ProductKey string    // Obrigatório, 1-255 caracteres
    StartDate  time.Time // Obrigatório, data válida
    EndDate    time.Time // Obrigatório, data válida > StartDate
    LineID     string    // Obrigatório, referência à linha/tipo
    ClientID   string    // Obrigatório, referência à empresa
    EntityID   *string   // Opcional, referência à unidade
}
```

**Regras:**
- Datas válidas e não sobrepostas.
- Não pode ser atribuída a empresa arquivada.
- Linha e empresa devem existir.

---

### 6. User (Usuário do Sistema)

Usuário autenticado para acesso e administração do sistema.

```go
type User struct {
    ID        string // UUID, obrigatório
    Username  string // Obrigatório, único
    Password  string // Obrigatório, hash seguro
    Role      string // Obrigatório, ex: admin, operador
    CreatedAt time.Time
}
```

**Regras:**
- Username único.
- Senha armazenada como hash.
- Controle de permissões por `Role`.

---

## Relacionamentos Entre Entidades

- **Client** 1:N **Entity** — Uma empresa pode ter várias unidades.
- **Client** 1:N **License** — Uma empresa pode ter várias licenças.
- **Entity** 1:N **License** — Uma unidade pode ter várias licenças (opcional).
- **Category** 1:N **Line** — Uma categoria pode ter várias linhas/tipos.
- **Line** 1:N **License** — Uma linha/tipo pode ter várias licenças.

---

## Validações Comuns

- IDs devem ser UUIDs válidos.
- Nomes entre 1 e 255 caracteres.
- Datas em formato ISO válido.
- Campos obrigatórios não podem ser vazios.
- Unicidade garantida por constraints no banco.

---

## Exemplos de Relacionamento

- Uma licença pode estar vinculada apenas à empresa (Client) ou também a uma unidade específica (Entity).
- Ao deletar uma empresa, todas as unidades e licenças associadas são deletadas (cascade).
- Ao deletar uma unidade, as licenças associadas têm o campo `EntityID` setado como NULL.

---

## Observações

- Todas as entidades suportam expansão futura (ex: campos extras, integrações).
- Recomenda-se versionamento das estruturas para facilitar migrações.
- As validações devem ser aplicadas tanto na camada de dados quanto na lógica de negócio.

---

## Referências

- [Arquitetura do Sistema](ARCHITECTURE.md)
- [Banco de Dados](DATABASE.md)
- [Regras de Negócio](BUSINESS_RULES.md)
- [Testes](TESTS.md)

---