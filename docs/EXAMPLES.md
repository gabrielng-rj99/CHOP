Licenses-Manager/docs/EXAMPLES.md
# Exemplos Práticos — Licenses Manager

Este documento apresenta exemplos reais de uso dos principais comandos do sistema Licenses Manager, incluindo operações via CLI, integração com scripts e fluxos comuns para automação e gestão de licenças.

---

## 1. Gerenciamento de Empresas (CLI)

### Criar uma nova empresa
```bash
licenses-cli company create --name "Empresa Exemplo" --registration_id "12.345.678/0001-99"
```

### Listar empresas cadastradas
```bash
licenses-cli company list
```

### Arquivar uma empresa
```bash
licenses-cli company archive --id "uuid-da-empresa"
```

---

## 2. Gerenciamento de Unidades

### Criar unidade vinculada a empresa
```bash
licenses-cli entity create --name "Filial SP" --client_id "uuid-da-empresa"
```

### Listar unidades de uma empresa
```bash
licenses-cli entity list --client_id "uuid-da-empresa"
```

---

## 3. Gerenciamento de Categorias e Linhas

### Criar categoria de licença
```bash
licenses-cli category create --name "Antivírus"
```

### Criar linha vinculada à categoria
```bash
licenses-cli line create --name "Kaspersky" --category_id "uuid-da-categoria"
```

---

## 4. Cadastro de Licenças

### Cadastrar licença para empresa
```bash
licenses-cli license create \
  --name "Kaspersky Internet Security" \
  --product_key "ABC-123-XYZ" \
  --start_date "2024-01-01" \
  --end_date "2025-01-01" \
  --line_id "uuid-da-linha" \
  --client_id "uuid-da-empresa"
```

### Cadastrar licença para unidade específica
```bash
licenses-cli license create \
  --name "Windows Server 2019 Datacenter" \
  --product_key "WS-2019-DC-KEY" \
  --start_date "2024-03-01" \
  --end_date "2025-03-01" \
  --line_id "uuid-da-linha" \
  --client_id "uuid-da-empresa" \
  --entity_id "uuid-da-unidade"
```

---

## 5. Consulta de Licenças

### Listar todas as licenças de uma empresa
```bash
licenses-cli license list --client_id "uuid-da-empresa"
```

### Buscar licenças próximas do vencimento
```bash
licenses-cli license expiring --days 30
```

---

## 6. Integração com Scripts (Exemplo em Bash)

### Exportar todas as licenças para CSV
```bash
licenses-cli license list --format csv > todas_licencas.csv
```

### Automatizar renovação de licenças expirando em 30 dias
```bash
for id in $(licenses-cli license expiring --days 30 --output ids); do
  licenses-cli license renew --id "$id"
done
```

---

## 7. Exemplos de Fluxos Completos

### Cadastro completo de empresa, unidade, categoria, linha e licença
```bash
# 1. Criar empresa
COMPANY_ID=$(licenses-cli company create --name "Empresa Exemplo" --registration_id "12.345.678/0001-99" --output id)

# 2. Criar unidade
ENTITY_ID=$(licenses-cli entity create --name "Filial RJ" --client_id "$COMPANY_ID" --output id)

# 3. Criar categoria
CATEGORY_ID=$(licenses-cli category create --name "Backup" --output id)

# 4. Criar linha
LINE_ID=$(licenses-cli line create --name "Veeam" --category_id "$CATEGORY_ID" --output id)

# 5. Cadastrar licença
licenses-cli license create \
  --name "Veeam Backup & Replication" \
  --product_key "VEEAM-2024-KEY" \
  --start_date "2024-05-01" \
  --end_date "2025-05-01" \
  --line_id "$LINE_ID" \
  --client_id "$COMPANY_ID" \
  --entity_id "$ENTITY_ID"
```

---

## 8. Exemplos de Integração com API (Futuro)

> Caso o projeto evolua para expor endpoints REST, exemplos de requisições via `curl` ou ferramentas como Postman serão incluídos aqui.

---

## 9. Exemplos de Testes Automatizados

### Teste básico de criação de licença (Go)
```go
func TestCreateLicense_Success(t *testing.T) {
    license := domain.License{
        Name:       "SQL Server Standard",
        ProductKey: "SQL-STD-2024",
        StartDate:  time.Now(),
        EndDate:    time.Now().AddDate(1,0,0),
        LineID:     "uuid-da-linha",
        ClientID:   "uuid-da-empresa",
    }
    id, err := store.CreateLicense(license)
    require.NoError(t, err)
    require.NotEmpty(t, id)
}
```

---

## 10. Exemplos de Relatórios

### Gerar relatório de licenças por categoria
```bash
licenses-cli report licenses-by-category --output pdf
```

---

## Dúvidas ou Sugestões?

Consulte o arquivo [FAQ.md](FAQ.md) ou abra uma issue no repositório.

---