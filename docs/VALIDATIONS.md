# Validações - Client Email e Phone

## Resumo
Foi adicionado suporte para Email e Phone no modelo `Client`. Ambos campos são **opcionais** mas, se fornecidos, devem ser válidos.

---

## Campos Adicionados

```go
type Client struct {
    // ... campos existentes ...
    Email  *string    // Opcional
    Phone  *string    // Opcional
}
```

---

## Validações Implementadas

### Email
- **Formato**: RFC 5322 simplificado
- **Máximo**: 254 caracteres
- **Regras**:
  - Deve ter `@` e domínio
  - Sem pontos consecutivos
  - Não começa/termina com ponto
  - Domínio com TLD (mínimo 2 caracteres)

**Exemplos válidos**: `user@example.com`, `john.doe@company.co.uk`, `contact+tag@subdomain.example.com`

### Telefone
- **Comprimento**: 10-15 dígitos
- **Máximo**: 25 caracteres (com formatação)
- **Formatos suportados**:
  - `(11) 98765-4321` - Celular com formatação
  - `(11) 3333-4444` - Fixo com formatação  
  - `11987654321` - Sem formatação (11 dígitos)
  - `+55 11 98765-4321` - Formato internacional

**Exemplos válidos**: `(11) 98765-4321`, `11987654321`, `+55 11 3333-4444`

---

## API de Validação

### Função Principal
```go
errors := domain.ValidateClient(client)
if !errors.IsValid() {
    for _, err := range errors {
        fmt.Printf("%s: %s\n", err.Field, err.Message)
    }
}
```

### Validações Individuais
```go
domain.ValidateClientEmail(email)    // Valida apenas email
domain.ValidateClientPhone(phone)    // Valida apenas telefone
```

### Normalização
```go
client.Email = domain.NormalizeEmail(client.Email)    // Lowercase + trim
client.Phone = domain.NormalizePhone(client.Phone)    // Trim
```

---

## Comportamento

- ✅ Ambos campos são **opcionais** (podem ser nil)
- ✅ Strings vazias são tratadas como nil
- ✅ Espaços em branco são removidos
- ✅ Se fornecidos, devem ser válidos
- ✅ Mensagens de erro em português

---

## Testes

```bash
cd backend
go test ./domain -v -run Validate
```

**Status**: ✅ 50+ testes passando

---

## Integração

### No Handler HTTP
```go
func CreateClientHandler(w http.ResponseWriter, r *http.Request) {
    var req CreateClientRequest
    json.NewDecoder(r.Body).Decode(&req)
    
    client := &domain.Client{
        Name:           req.Name,
        RegistrationID: req.RegistrationID,
        Email:          req.Email,
        Phone:          req.Phone,
    }
    
    if errors := domain.ValidateClient(client); !errors.IsValid() {
        w.WriteHeader(http.StatusBadRequest)
        json.NewEncoder(w).Encode(map[string]interface{}{
            "errors": errors,
        })
        return
    }
    
    // Salvar cliente...
}
```

---

## Próximos Passos

1. ✅ Código implementado e testado
2. ⏳ Database: Adicionar colunas `email` VARCHAR(254) e `phone` VARCHAR(25)
3. ⏳ API: Integrar validações em handlers de cliente
4. ⏳ Frontend: Capturar e validar em tempo real

---

## Referências

- **Implementação**: `backend/domain/validation.go`
- **Testes**: `backend/domain/validation_test.go`
- **Exemplo Handler**: `backend/cmd/server/validation_handler_example.go`
```

Agora vou apagar os 3 arquivos redundantes e deixar apenas este consolidado:
