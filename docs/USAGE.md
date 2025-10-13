Licenses-Manager/docs/USAGE.md
# Exemplos de Uso — Licenses Manager

Este documento apresenta exemplos práticos de uso do Licenses Manager, incluindo comandos CLI e sugestões para integração via API (caso implementada).

---

## Uso via CLI

O Licenses Manager possui uma interface de linha de comando (CLI) para facilitar operações administrativas. Os exemplos abaixo assumem que o binário CLI está disponível em `backend/cmd/cli/main.go` ou compilado como `licenses-manager`.

### 1. Listar Empresas

```bash
licenses-manager company list
```
Exibe todas as empresas cadastradas.

---

### 2. Criar Nova Empresa

```bash
licenses-manager company create --name "Empresa Exemplo" --registration_id "12.345.678/0001-99"
```
Cria uma nova empresa com nome e CNPJ.

---

### 3. Listar Unidades de uma Empresa

```bash
licenses-manager entity list --client_id <UUID_da_empresa>
```
Exibe todas as unidades vinculadas à empresa informada.

---

### 4. Cadastrar Licença

```bash
licenses-manager license create \
  --name "Windows Server 2019 Datacenter" \
  --product_key "XXXXX-XXXXX-XXXXX-XXXXX" \
  --start_date "2024-01-01" \
  --end_date "2025-01-01" \
  --line_id <UUID_da_linha> \
  --client_id <UUID_da_empresa> \
  --entity_id <UUID_da_unidade>
```
Registra uma nova licença vinculada à empresa, linha e unidade.

---

### 5. Listar Licenças Próximas do Vencimento

```bash
licenses-manager license expiring --days 30
```
Exibe licenças que expiram nos próximos 30 dias.

---

### 6. Arquivar Empresa

```bash
licenses-manager company archive --id <UUID_da_empresa>
```
Arquiva a empresa, tornando-a inativa para novas licenças.

---

### 7. Deletar Licença

```bash
licenses-manager license delete --id <UUID_da_licenca>
```
Remove uma licença do sistema.

---

## Uso via API (Sugestão de Integração)

Caso o projeto evolua para expor uma API REST, os exemplos abaixo podem servir de referência para endpoints e payloads.

### 1. Criar Empresa

```http
POST /api/companies
Content-Type: application/json

{
  "name": "Empresa Exemplo",
  "registration_id": "12.345.678/0001-99"
}
```

---

### 2. Listar Licenças

```http
GET /api/licenses?client_id=<UUID_da_empresa>
```

---

### 3. Cadastrar Licença

```http
POST /api/licenses
Content-Type: application/json

{
  "name": "Windows Server 2019 Datacenter",
  "product_key": "XXXXX-XXXXX-XXXXX-XXXXX",
  "start_date": "2024-01-01",
  "end_date": "2025-01-01",
  "line_id": "<UUID_da_linha>",
  "client_id": "<UUID_da_empresa>",
  "entity_id": "<UUID_da_unidade>"
}
```

---

## Observações

- Os comandos e endpoints podem variar conforme evolução do projeto.
- Recomenda-se consultar a documentação de cada comando/endpoint para detalhes de parâmetros e respostas.
- Para integração automatizada, utilize scripts ou ferramentas como `curl`, `httpie` ou bibliotecas de clientes HTTP.

---

## Referências

- [Arquitetura do Sistema](ARCHITECTURE.md)
- [Entidades e Modelos](ENTITIES.md)
- [Regras de Negócio](BUSINESS_RULES.md)

---