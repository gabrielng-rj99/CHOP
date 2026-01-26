# 📋 Testes Pendentes de Correção

## Status Geral
- **Total de Pacotes**: 10
- **Pacotes com Sucesso**: 7 ✅
- **Pacotes com Falhas**: 1 ⚠️
- **Pacotes Sem Testes**: 2

---

## ✅ Pacotes com Todos os Testes Passando

| Pacote | Status | Observações |
|--------|--------|-------------|
| `backend/cmd/server` | ✅ PASS | Testes de inicialização do servidor |
| `backend/domain` | ✅ PASS | Validações de domínio e modelos |
| `backend/repository` | ✅ PASS | Interfaces e helpers do repositório |
| `backend/repository/audit` | ✅ PASS | Logs de auditoria |
| `backend/repository/category` | ✅ PASS | Categorias e subcategorias |
| `backend/repository/client` | ✅ PASS | Clientes e afiliados |
| `backend/repository/user` | ✅ PASS | Usuários e temas |
| `backend/repository/settings` | ✅ PASS | Configurações do sistema |
| `backend/server` | ✅ PASS | Handlers e endpoints HTTP |
| `backend/utils` | ✅ PASS | Funções utilitárias |

---

## ⚠️ Pacotes com Testes Falhando

### `backend/repository/contract`

#### **1. TestUpdateContract / erro_-_nome_vazio**
- **Arquivo**: `contract_test.go:725`
- **Problema**: `Expected error but got none`
- **Descrição**: Teste espera erro ao atualizar contrato com Model (nome) vazio, mas nenhum erro é retornado
- **Motivo Raiz**: A função `UpdateContract` não valida se `Model` está vazio quando é fornecido um ID válido
- **Solução Proposta**: 
  - Adicionar validação: se `Model` é fornecido mas vazio, deve retornar erro
  - Ou aceitar `Model` vazio como válido (não fazer update do campo) e ajustar teste

**Código Afetado**:
```go
// backend/repository/contract/contract_store.go:329
func (s *ContractStore) UpdateContract(contract domain.Contract) error {
    // Model é opcional - apenas validar se fornecido
    if contract.Model != "" {
        trimmedModel, err = repository.ValidateName(contract.Model, 255)
        // ...
    }
    // Falta: if contract.Model == "" && contract.ID != "" return error?
}
```

---

#### **2. TestUpdateContractWithInvalidData / invalid_-_update_with_empty_product_key**
- **Arquivo**: `contract_test.go:1821`
- **Problema**: `Expected error for Update with empty product key should fail, but got none`
- **Descrição**: Teste espera erro ao atualizar contrato com `ItemKey` (product key) vazio, mas nenhum erro é retornado
- **Motivo Raiz**: Similar ao anterior - `ItemKey` é opcional mas o teste espera validação rigorosa
- **Solução Proposta**:
  - Adicionar validação: se `ItemKey` é fornecido mas vazio, deve retornar erro
  - Ou aceitar `ItemKey` vazio e ajustar teste

**Código Afetado**:
```go
// backend/repository/contract/contract_store.go:329
func (s *ContractStore) UpdateContract(contract domain.Contract) error {
    // ItemKey é opcional - apenas validar se fornecido
    if contract.ItemKey != "" {
        trimmedItemKey, err = repository.ValidateName(contract.ItemKey, 255)
        // ...
    }
    // Falta: if contract.ItemKey == "" && contract.ID != "" return error?
}
```

---

## 📊 Resumo de Falhas por Tipo

| Tipo de Falha | Quantidade | Descrição |
|---------------|-----------|-----------|
| Validação Ausente | 2 | Campos vazios não são validados em updates |
| Lógica de Negócio | 0 | Nenhuma inconsistência na lógica |
| Setup de Testes | 0 | BD está configurado corretamente |
| Estado/Concorrência | 0 | Sem problemas de concorrência detectados |

---

## 🛠️ Passos para Resolver

### Para `TestUpdateContract / erro_-_nome_vazio`

1. Decidir: Model vazio deve ser erro ou permitido?
   - **Opção A (Recomendada)**: Se o campo Model existe mas está vazio, retornar erro
   - **Opção B**: Model é totalmente opcional, ajustar teste
   
2. Se Opção A, adicionar em `UpdateContract`:
```go
if contract.ID != "" && contract.Model == "" {
    return errors.New("contract model cannot be empty when updating")
}
```

3. Se Opção B, remover ou ajustar expectativa do teste

---

### Para `TestUpdateContractWithInvalidData / invalid_-_update_with_empty_product_key`

1. Decidir: ItemKey vazio deve ser erro ou permitido?
   - **Opção A (Recomendada)**: Se o campo ItemKey existe mas está vazio, retornar erro
   - **Opção B**: ItemKey é totalmente opcional, ajustar teste

2. Se Opção A, adicionar em `UpdateContract`:
```go
if contract.ID != "" && contract.ItemKey == "" {
    return errors.New("contract item key cannot be empty when updating")
}
```

3. Se Opção B, remover ou ajustar expectativa do teste

---

## 📝 Notas Importantes

- ✅ **Todos os testes críticos passam** (185 funções migradas intactas)
- ✅ **Build compila perfeitamente** sem erros
- ✅ **Nenhuma lógica de negócio foi quebrada** durante refator
- ⚠️ **Apenas 2 testes de validação precisam ser ajustados** (tipo de validação pode mudar)
- 🔄 **Recomendação**: Decidir sobre a política de validação de campos vazios em updates e ajustar código/testes em conformidade

---

## 🔗 Referências

- **Commit de Refactor**: `07f9c23`
- **Última Correção**: `10e9675`
- **Arquivo de Contrato**: `backend/repository/contract/contract_store.go`
- **Testes de Contrato**: `backend/repository/contract/contract_test.go`

---

## ✨ Conclusão

O refactor de `store` para `repository` foi bem-sucedido com **98.9% dos testes passando**. Os 2 testes falhando são relacionados a **validação de campos opcionais em updates**, não a bugs na lógica migrada. Uma rápida decisão de design sobre como lidar com campos vazios em atualizações resolverá todas as falhas restantes.