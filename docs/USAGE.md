# Usage — Contracts Manager

Guia prático para usar o Contracts Manager. Aprenda os comandos e operações do dia a dia.

## 🚀 Começar

```bash
cd backend
go run cmd/cli/main.go
```

Você verá um menu interativo:

```
=== Contracts Manager ===
1. Clients
2. Dependents
3. Categories
4. Lines
5. Contracts
6. Users
0. Exit

Escolha uma opção:
```

## 👥 Gerenciar Clientes (Clients)

### Listar Clientes

Menu → `1` → `1 - List`

Exibe todos os clientes cadastrados:
```
ID: 550e8400-e29b-41d4-a716-446655440000
Nome: Acme Corporation
CNPJ/Reg: 12.345.678/0001-99
Status: Ativo
```

### Criar Novo Cliente

Menu → `1` → `2 - Create`

Informações necessárias:
- **Nome:** Nome da empresa (ex: Acme Corporation)
- **CNPJ/Registration ID:** Identificador único (ex: 12.345.678/0001-99)

Exemplo:
```
Nome: TechCorp Brasil
CNPJ: 98.765.432/0001-00
✓ Cliente criado com sucesso
ID: 550e8400-e29b-41d4-a716-446655440001
```

### Arquivar Cliente

Menu → `1` → `3 - Archive`

```
Informe o ID do cliente: 550e8400-e29b-41d4-a716-446655440001
✓ Cliente arquivado
Nota: Contratos associados ficam inativos
```

**Importante:** Clientes arquivados não recebem novos contratos.

## 🏢 Gerenciar Dependentes (Unidades/Filiais)

Dependentes são unidades, filiais ou subsidiárias de um cliente.

### Listar Dependentes

Menu → `2` → `1 - List`

```
Cliente: Acme Corporation (ID: 550e8400-...)
Dependentes:
- Filial São Paulo (ID: 660e8400-...)
- Filial Rio de Janeiro (ID: 770e8400-...)
```

### Criar Dependente

Menu → `2` → `2 - Create`

Informações:
- **Cliente ID:** ID do cliente pai
- **Nome:** Nome da filial/unidade

Exemplo:
```
ID do Cliente: 550e8400-e29b-41d4-a716-446655440001
Nome da Filial: Filial São Paulo
✓ Dependente criado
ID: 660e8400-e29b-41d4-a716-446655440002
```

## 📂 Categorias (Tipos de Produtos)

Categorize seus produtos de software.

### Criar Categoria

Menu → `3` → `1 - Create`

Exemplos de categorias:
- Antivírus
- Banco de Dados
- Sistemas Operacionais
- Office/Produtividade
- Segurança
- Desenvolvimento

Exemplo:
```
Nome: Antivírus
✓ Categoria criada
ID: 880e8400-e29b-41d4-a716-446655440003
```

### Listar Categorias

Menu → `3` → `2 - List`

```
1. Antivírus (ID: 880e8400-...)
2. Banco de Dados (ID: 990e8400-...)
3. Sistemas Operacionais (ID: aa0e8400-...)
```

## 📦 Linhas de Produtos (Product Lines)

Produtos específicos dentro de uma categoria.

### Criar Linha de Produto

Menu → `4` → `1 - Create`

Informações:
- **Categoria ID:** ID da categoria (ex: Antivírus)
- **Nome/Produto:** Nome do produto específico

Exemplos:
- Categoria: Antivírus → Linha: Kaspersky Endpoint
- Categoria: SO → Linha: Windows 10 Pro
- Categoria: BD → Linha: Oracle Database 19c

Exemplo:
```
ID da Categoria: 880e8400-e29b-41d4-a716-446655440003
Nome do Produto: Kaspersky Endpoint
✓ Linha criada
ID: bb0e8400-e29b-41d4-a716-446655440004
```

### Listar Linhas

Menu → `4` → `2 - List`

```
Categoria: Antivírus
- Kaspersky Endpoint (ID: bb0e8400-...)
- Avast Business (ID: cc0e8400-...)

Categoria: Banco de Dados
- Oracle Database 19c (ID: dd0e8400-...)
- SQL Server 2022 (ID: ee0e8400-...)
```

## 📋 Gerenciar Contratos (Licenças)

Contratos são a entidade principal do sistema. Vincule a um cliente, produto e datas.

### Criar Contrato

Menu → `5` → `1 - Create`

Informações necessárias:

| Campo | Exemplo | Descrição |
|-------|---------|-----------|
| **Nome/Model** | Windows 10 Pro | Nome do contrato |
| **Product Key** | XXXXX-XXXXX-... | Chave de licença |
| **Start Date** | 2025-01-15 | Início (formato: YYYY-MM-DD) |
| **End Date** | 2026-01-15 | Término (formato: YYYY-MM-DD) |
| **Cliente ID** | 550e8400-... | ID do cliente |
| **Linha ID** | bb0e8400-... | ID da linha (produto) |
| **Dependente ID** | (opcional) | ID da filial (deixar vazio se não aplicável) |

Exemplo:
```
Nome: Windows 10 Pro - 10 licenças
Product Key: XXXXX-XXXXX-XXXXX-XXXXX
Data de início (YYYY-MM-DD): 2025-01-15
Data de término (YYYY-MM-DD): 2026-01-15
ID do Cliente: 550e8400-e29b-41d4-a716-446655440001
ID da Linha: bb0e8400-e29b-41d4-a716-446655440004
ID do Dependente (opcional): (deixar vazio)

✓ Contrato criado
ID: ff0e8400-e29b-41d4-a716-446655440005
Status: Ativo
```

### Listar Contratos

Menu → `5` → `2 - List`

```
1. Windows 10 Pro - 10 licenças
   Status: Ativo
   Vencimento: 2026-01-15
   Cliente: Acme Corporation

2. Kaspersky Endpoint - 5 licenças
   Status: Expirando em Breve (20 dias)
   Vencimento: 2025-02-04
   Cliente: TechCorp Brasil

3. Oracle Database 19c
   Status: Expirado
   Vencimento: 2024-12-31
   Cliente: DataCorp
```

### Buscar Contrato

Menu → `5` → `3 - Search`

```
ID do Contrato: ff0e8400-e29b-41d4-a716-446655440005

Contrato encontrado:
Nome: Windows 10 Pro - 10 licenças
Cliente: Acme Corporation
Linha: Windows 10 Pro
Data início: 2025-01-15
Data término: 2026-01-15
Status: Ativo
```

### Atualizar Contrato

Menu → `5` → `4 - Update`

```
ID do Contrato: ff0e8400-e29b-41d4-a716-446655440005

Deixe em branco para não alterar:
Nome (ou Enter): 
Data término (YYYY-MM-DD ou Enter): 2026-06-15

✓ Contrato atualizado
```

### Arquivar Contrato

Menu → `5` → `5 - Archive`

```
ID do Contrato: ff0e8400-e29b-41d4-a716-446655440005
✓ Contrato arquivado (soft delete)
```

## 👤 Autenticação e Usuários

### Primeiro Acesso

Na primeira execução, crie um usuário admin:

```bash
cd backend
go run cmd/tools/main.go create_admin
```

Ou pelo menu:

Menu → `6` → `1 - Create User`

```
Username: admin
Senha: (será solicitada)
Confirmar senha: (será solicitada)
Role (user/admin/root): root

✓ Usuário criado
ID: 11aa2200-e29b-41d4-a716-446655440006
```

### Login

Quando necessário, o sistema solicitará:

```
Username: admin
Senha: ••••••••
✓ Login realizado com sucesso
```

### Roles (Permissões)

- **user:** Visualização e operações básicas
- **admin:** Gerenciamento completo
- **root:** Acesso total + gerenciamento de usuários

## 📊 Monitoramento e Relatórios

### Ver Contratos Próximos de Vencer

Menu → `5` → `2 - List`

Contratos com menos de 30 dias até vencimento aparecem como:
```
Status: Expirando em Breve (15 dias)
```

Planeje renovações com antecedência.

### Ver Contratos Expirados

Filtre na listagem:
```
Status: Expirado
```

Esses contratos precisam ser renovados ou removidos.

### Filtrar por Cliente

Menu → `5` → `2 - List`

Todos os contratos de um cliente aparecem agrupados:
```
Cliente: Acme Corporation
├─ Contrato 1 (Ativo)
├─ Contrato 2 (Expirando em Breve)
└─ Contrato 3 (Expirado)
```

## 🎯 Casos de Uso Comuns

### Caso 1: Cadastrar Nova Empresa e Primeira Licença

1. Menu → `1` → `2` → Criar cliente "Acme Corp"
2. Menu → `3` → `1` → Criar categoria "Antivírus"
3. Menu → `4` → `1` → Criar linha "Norton 360"
4. Menu → `5` → `1` → Criar contrato vinculando tudo

### Caso 2: Renovar Licença Expirando

1. Menu → `5` → `2` → Listar contratos
2. Identificar contrato com "Expirando em Breve"
3. Menu → `5` → `4` → Atualizar data de término
4. Ou Menu → `5` → `1` → Criar novo contrato

### Caso 3: Arquivar Cliente Inativo

1. Menu → `1` → `1` → Listar clientes
2. Encontrar cliente para arquivar
3. Menu → `1` → `3` → Arquivar
4. Contratos associados ficam inativos automaticamente

### Caso 4: Adicionar Filial de Um Cliente

1. Menu → `2` → `2` → Criar dependente
2. Selecionar cliente
3. Informar nome da filial
4. Menu → `5` → `1` → Criar contrato para a filial (campo "Dependente ID" opcional)

## ⚠️ Validações Importantes

### Datas

- **End date deve ser posterior a start date**
  ```
  ✗ Erro: End date must be after start date
  ```

- **Formato:** YYYY-MM-DD
  ```
  ✓ 2025-12-31 (correto)
  ✗ 31/12/2025 (errado)
  ✗ 2025-13-01 (mês inválido)
  ```

### Sobreposição de Datas

- **Não há sobreposição temporal para mesma linha e cliente**
  ```
  ✗ Erro: Overlapping contract dates for this line
  ```

### Cliente Arquivado

- **Não é possível criar contrato para cliente arquivado**
  ```
  ✗ Erro: Cannot create contract for archived client
  ```

## 🔍 Dicas de Produtividade

### Copiar IDs Facilmente

Quando listar, os IDs aparecem de forma legível para copiar:
```
ID: 550e8400-e29b-41d4-a716-446655440000
    ↑ Copie este ID
```

### Usar Tab para Autocompletar

Em alguns campos, pressione Tab para sugestões.

### Historicamente Rastreado (Soft Delete)

Contratos e clientes arquivados não são deletados:
- ✅ Histórico preservado
- ✅ Auditoria facilitada
- ✅ Recuperação possível (admin)

## ❓ FAQ Prático

**P: Como filtrar contratos por período?**
A: Lista mostra todos. Se precisar de período específico, use a busca por cliente.

**P: Posso deletar um contrato?**
A: Não permanentemente. Use "Arquivar" (soft delete). Historicamente é preservado.

**P: Qual é a diferença entre Dependente e Cliente?**
A: Cliente = Empresa. Dependente = Unidade/Filial/Subsidiária da empresa.

**P: Posso editar CNPJ de um cliente?**
A: Não. CNPJ é identificador único. Crie novo cliente se necessário.

**P: Como exportar dados?**
A: Atualmente não há export. Use cópia manual ou aguarde versão 2.0.

**P: Contratos podem ter dependente vazio?**
A: Sim, é opcional. Use quando a licença não é para filial específica.

**P: O que significa "Expirando em Breve"?**
A: Contratos com menos de 30 dias até vencimento.

**P: Como acessar dados de contrato específico?**
A: Menu → Contratos → Buscar, depois informar o ID.

## 📚 Próximos Passos

- **Leia [ARCHITECTURE.md](ARCHITECTURE.md)** para entender o design técnico
- **Consulte [CONTRIBUTING.md](CONTRIBUTING.md)** se quiser contribuir
- **Veja [SETUP.md](SETUP.md)** para configurações avançadas

---

**Precisa de ajuda?** Abra uma [issue](https://github.com/seu-usuario/Open-Generic-Hub/issues) ou consulte a documentação completa.
