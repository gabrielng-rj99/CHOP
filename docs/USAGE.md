# Usage — Guia de Uso

Exemplos práticos para usar o Licenses Manager. Todos os comandos assumem que você está rodando a CLI.

## 🚀 Iniciar a Aplicação

```bash
cd backend
go run cmd/cli/main.go
```

Você verá um menu interativo para escolher operações.

---

## 📚 Operações Básicas

### Empresas (Companies)

#### Listar todas as empresas

Menu → `1 - Companies` → `1 - List`

Exibe todas as empresas cadastradas com ID, nome e CNPJ.

#### Criar nova empresa

Menu → `1 - Companies` → `2 - Create`

```
Informe:
- Nome: Acme Corporation
- CNPJ/Registration ID: 12.345.678/0001-99
```

Resultado: Empresa criada com UUID único.

#### Arquivar empresa

Menu → `1 - Companies` → `3 - Archive`

```
Informe o ID da empresa: <uuid>
```

Empresa é marcada como arquivada (soft delete). Licenças associadas ficam inativas.

**Nota:** Empresas arquivadas não recebem novas licenças.

---

### Unidades (Entities)

#### Listar unidades de uma empresa

Menu → `2 - Entities` → `1 - List`

```
Informe o ID da empresa: <uuid>
```

Exibe todas as filiais/unidades da empresa.

#### Criar unidade

Menu → `2 - Entities` → `2 - Create`

```
Informe:
- Nome: Filial São Paulo
- Company ID: <uuid-da-empresa>
```

Unidade criada com vínculo à empresa.

#### Deletar unidade

Menu → `2 - Entities` → `3 - Delete`

```
Informe o ID da unidade: <uuid>
```

**Atenção:** Unidade só pode ser deletada se não houver licenças ativas associadas.

---

### Categorias (Categories)

#### Listar categorias

Menu → `3 - Categories` → `1 - List`

Exibe todas as categorias de licenças (ex: Antivírus, Banco de Dados, etc).

#### Criar categoria

Menu → `3 - Categories` → `2 - Create`

```
Informe o nome: Antivírus
```

Categoria criada. Nomes devem ser únicos.

---

### Linhas (Lines)

#### Listar linhas de uma categoria

Menu → `4 - Lines` → `1 - List`

```
Informe o ID da categoria: <uuid>
```

Exibe todas as marcas/linhas dentro da categoria.

#### Criar linha

Menu → `4 - Lines` → `2 - Create`

```
Informe:
- Nome: Kaspersky
- Category ID: <uuid-da-categoria>
```

Linha criada (ex: Kaspersky é uma linha dentro de Antivírus).

---

### Licenças (Licenses)

#### Listar todas as licenças

Menu → `5 - Licenses` → `1 - List`

Exibe todas as licenças do sistema com status (Ativa/Expirando/Expirada).

#### Listar licenças de uma empresa

Menu → `5 - Licenses` → `2 - Filter by Company`

```
Informe o ID da empresa: <uuid>
```

Exibe apenas licenças associadas à empresa.

#### Listar licenças próximas do vencimento

Menu → `5 - Licenses` → `3 - Expiring Soon`

Exibe licenças que vencem nos próximos 30 dias.

#### Cadastrar licença

Menu → `5 - Licenses` → `4 - Create`

```
Informe:
- Nome: Windows Server 2019 Datacenter
- Product Key: XXXXX-XXXXX-XXXXX-XXXXX
- Start Date (YYYY-MM-DD): 2024-01-01
- End Date (YYYY-MM-DD): 2025-01-01
- Line ID: <uuid-da-linha>
- Company ID: <uuid-da-empresa>
- Entity ID (opcional): <uuid-da-unidade>
```

Licença criada com todas as validações.

**Validações:**
- Data de fim deve ser posterior à data de início
- Não pode haver sobreposição temporal
- Empresa não pode estar arquivada
- Linha e empresa devem existir

#### Deletar licença

Menu → `5 - Licenses` → `5 - Delete`

```
Informe o ID da licença: <uuid>
```

Licença removida do sistema.

---

## 🔍 Casos de Uso Comuns

### Caso 1: Cadastro Completo

Você recebeu uma nova licença de software. Complete os passos:

**Passo 1:** Criar categoria (se não existir)
```
Menu → Categories → Create
Nome: Database
```

**Passo 2:** Criar linha (marca do software)
```
Menu → Lines → Create
Nome: SQL Server
Category ID: <id-da-categoria>
```

**Passo 3:** Criar empresa (se não existir)
```
Menu → Companies → Create
Nome: Acme Corp
CNPJ: 12.345.678/0001-99
```

**Passo 4:** Criar unidade (opcional)
```
Menu → Entities → Create
Nome: Filial RJ
Company ID: <id-da-empresa>
```

**Passo 5:** Cadastrar licença
```
Menu → Licenses → Create
Nome: SQL Server 2019 Standard
Product Key: ABC-123-XYZ
Start Date: 2024-01-01
End Date: 2025-01-01
Line ID: <id-da-linha>
Company ID: <id-da-empresa>
Entity ID: <id-da-unidade> (se tiver)
```

### Caso 2: Monitorar Vencimentos

Você quer saber quais licenças vencem em breve:

```
Menu → Licenses → Expiring Soon
# Exibe todas as licenças que vencem nos próximos 30 dias
```

Importante revisar antes de implementar renovações.

### Caso 3: Arquivar Empresa

Empresa encerrou operações. Você quer manter o histórico mas desativar:

```
Menu → Companies → Archive
Company ID: <uuid>
```

Todas as licenças associadas ficam inativas automaticamente.

### Caso 4: Filtrar por Categoria

Você quer listar apenas licenças de antivírus:

```
Menu → Licenses → Filter by Category
Category ID: <uuid-de-antivírus>
# Lista todos os antivírus do sistema
```

---

## 📊 Estrutura de Dados — Referência Rápida

### Companies
| Campo | Tipo | Obrigatório |
|-------|------|-------------|
| ID | UUID | ✓ |
| Name | String | ✓ |
| Registration_ID (CNPJ) | String | ✓ (único) |
| Archived_At | Timestamp | (soft delete) |
| Created_At | Timestamp | ✓ |

### Entities
| Campo | Tipo | Obrigatório |
|-------|------|-------------|
| ID | UUID | ✓ |
| Name | String | ✓ (único por empresa) |
| Client_ID | UUID | ✓ (FK) |

### Categories
| Campo | Tipo | Obrigatório |
|-------|------|-------------|
| ID | UUID | ✓ |
| Name | String | ✓ (único) |

### Lines
| Campo | Tipo | Obrigatório |
|-------|------|-------------|
| ID | UUID | ✓ |
| Name | String | ✓ (único na categoria) |
| Category_ID | UUID | ✓ (FK) |

### Licenses
| Campo | Tipo | Obrigatório |
|-------|------|-------------|
| ID | UUID | ✓ |
| Name | String | ✓ |
| Product_Key | String | ✓ |
| Start_Date | Date | ✓ |
| End_Date | Date | ✓ |
| Line_ID | UUID | ✓ (FK) |
| Client_ID | UUID | ✓ (FK) |
| Entity_ID | UUID | (opcional, FK) |

---

## ⚠️ Regras Importantes

### Relacionamentos Obrigatórios

```
License → Company (obrigatório)
License → Line (obrigatório)
License → Entity (opcional)

Line → Category (obrigatório)
Entity → Company (obrigatório)
```

### Validações

- **CNPJs:** Devem ser únicos em companies
- **Datas:** End_Date > Start_Date
- **Nomes:** Entre 1 e 255 caracteres
- **UUIDs:** Todos os IDs devem ser válidos

### Status de Licença (Automático)

- **Ativa:** Data atual está entre Start_Date e End_Date
- **Expirando:** Faltam menos de 30 dias para End_Date
- **Expirada:** End_Date já passou

---

## 🚫 Erros Comuns e Soluções

| Erro | Causa | Solução |
|------|-------|---------|
| "Company not found" | ID inválido | Verifique o UUID da empresa |
| "Line already exists" | Nome duplicado na categoria | Use outro nome ou apague a antiga |
| "Invalid date format" | Data em formato errado | Use YYYY-MM-DD |
| "Cannot delete: entity has licenses" | Unidade ainda tem licenças | Delete as licenças primeiro |
| "Archived company cannot have licenses" | Empresa arquivada | Desarquive a empresa ou crie licença em outra |

---

## 💡 Dicas Úteis

1. **Anote UUIDs:** Os IDs são gerados aleatoriamente. Copie quando criados.
2. **Backup:** Faça backup do banco de dados regularmente.
3. **Organize:** Use nomes descritivos para facilitar buscas.
4. **Verifique:** Sempre confirme datas de licenças antes de registrar.
5. **Monitore:** Revise licenças expirando mensalmente.

---

## 🔗 Próximas Etapas

- **Integração:** Futura API REST permitirá integração com sistemas externos
- **Automação:** Scripts podem consumir a API para renovações automáticas
- **Dashboard:** Visualização web das licenças está em planejamento

---

## ❓ FAQ Rápido

**P: Posso excluir uma empresa com licenças?**
R: Não, delete as licenças primeiro ou arquive a empresa (soft delete).

**P: Como diferencio os status de licença?**
R: Menu → Licenses → List. Status é exibido ao lado de cada licença.

**P: Perdi o ID de uma empresa. Como busco?**
R: Menu → Companies → List. Exibe todos com IDs.

**P: Posso mover uma licença para outra unidade?**
R: Sim, delete a atual e crie uma nova com a unidade desejada.

**P: Quanto tempo as licenças ficam no sistema após expirar?**
R: Permanecem para histórico. Crie política de arquivamento conforme necessário.

---

**Precisa de ajuda?** Consulte [SETUP.md](SETUP.md) ou [ARCHITECTURE.md](ARCHITECTURE.md).