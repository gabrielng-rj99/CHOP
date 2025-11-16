# 🚀 Quick Start Guide - Contract Manager

## Início Rápido em 5 Minutos

### Pré-requisitos

- **Go** 1.21+ instalado
- **Node.js** 18+ e npm
- **PostgreSQL** 12+ rodando
- Git

---

## 1️⃣ Clone e Configure

```bash
# Clone o repositório
git clone <repo-url>
cd Contract-Manager

# Configure as variáveis de ambiente do backend
cd backend
cp .env.example .env

# Edite .env com suas credenciais do PostgreSQL
nano .env
```

**Exemplo `.env`:**
```env
POSTGRES_USER=postgres
POSTGRES_PASSWORD=sua_senha
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_DB=contracts_manager
POSTGRES_SSLMODE=disable
```

---

## 2️⃣ Inicialize o Banco de Dados

```bash
# Crie o banco de dados
psql -U postgres -c "CREATE DATABASE contracts_manager;"

# Execute as migrations
cd backend/database
psql -U postgres -d contracts_manager -f schema.sql
```

---

## 3️⃣ Instale Dependências

### Backend
```bash
cd backend
go mod download
```

### Frontend
```bash
cd frontend
npm install
```

---

## 4️⃣ Execute o Sistema

### Opção A: Servidor Backend + Frontend

**Terminal 1 - Backend:**
```bash
cd backend
go run cmd/server/main.go

# Servidor rodando em: http://localhost:3000
```

**Terminal 2 - Frontend:**
```bash
cd frontend
npm run dev

# Frontend rodando em: http://localhost:8080
```

### Opção B: CLI Interativo

```bash
cd backend
go run cmd/cli/main.go

# Interface CLI com menu interativo
```

---

## 5️⃣ Acesse o Sistema

1. Abra o navegador em: **http://localhost:8080**
2. Faça login com credenciais padrão (se configurado)
3. Comece a gerenciar contratos!

---

## 📋 Funcionalidades Principais

### ✅ Contratos com Datas Flexíveis

**Criar contrato perpétuo (nunca expira):**
- Deixe "Data de Vencimento" vazia
- Status: sempre "Ativo"

**Criar contrato sem data de início:**
- Deixe "Data de Início" vazia
- Sistema trata como "sempre ativo"

**Criar contrato padrão:**
- Preencha ambas as datas
- Sistema calcula status automaticamente

---

## 🎯 Casos de Uso Comuns

### Caso 1: Licença Perpétua
```
Modelo: Licença Enterprise Perpétua
Chave: ENT-2024-001
Data Início: 01/01/2024
Data Fim: [vazio] ← Nunca expira
Status: Ativo ✅
```

### Caso 2: Sistema Legado
```
Modelo: Sistema Legado XYZ
Chave: LEGACY-001
Data Início: [vazio] ← Data desconhecida
Data Fim: 31/12/2025
Status: Ativo até expirar
```

### Caso 3: Contrato Anual
```
Modelo: Suporte Anual
Chave: SUP-2024-001
Data Início: 01/01/2024
Data Fim: 31/12/2024
Status: Calculado automaticamente
```

---

## 🔧 Comandos Úteis

### Backend

```bash
# Compilar servidor
go build -o server ./cmd/server

# Compilar CLI
go build -o cli ./cmd/cli

# Executar testes
go test ./...

# Build completo
go build ./...
```

### Frontend

```bash
# Desenvolvimento
npm run dev

# Build para produção
npm run build

# Preview da build
npm run preview
```

---

## 🐛 Troubleshooting

### Problema: Frontend não inicia

**Erro:** `Vite requires Node.js version 20.19+`

**Solução:** Já corrigido! Versões ajustadas para Node 18+
```bash
cd frontend
npm install  # Reinstalar dependências
npm run dev
```

### Problema: Erro de conexão com PostgreSQL

**Solução:**
1. Verifique se PostgreSQL está rodando:
   ```bash
   sudo systemctl status postgresql
   ```
2. Verifique credenciais no `.env`
3. Teste conexão manual:
   ```bash
   psql -U postgres -d contracts_manager
   ```

### Problema: Datas aparecem como "01/01/0001"

**Solução:** Sistema atualizado! Datas vazias agora são tratadas como `null`:
- Backend: usa `*time.Time` (nullable)
- Frontend: exibe "-" ou "Never"
- Database: armazena NULL

---

## 📚 Próximos Passos

1. **Criar Categorias e Linhas**
   - Navegue para "Categorias"
   - Crie categorias de produtos
   - Adicione linhas de produtos

2. **Cadastrar Clientes**
   - Navegue para "Clientes"
   - Adicione informações do cliente
   - Opcionalmente adicione dependentes

3. **Registrar Contratos**
   - Navegue para "Contratos"
   - Clique em "Novo Contrato"
   - Preencha os dados (datas são opcionais!)

4. **Monitorar Status**
   - Dashboard mostra contratos expirando
   - Filtros: Ativos, Expirando, Expirados
   - Busca rápida por nome/chave

---

## 📖 Documentação Completa

- **`docs/NULLABLE_DATES.md`** - Guia de datas nullable
- **`IMPLEMENTATION_COMPLETE.md`** - Status da implementação
- **`README.md`** - Documentação geral do projeto

---

## 🆘 Suporte

Encontrou um problema? Verifique:
1. Logs do backend: console onde executou o servidor
2. Console do navegador (F12) para erros de frontend
3. Arquivo de configuração `.env` está correto
4. PostgreSQL está acessível e rodando

---

## ✅ Checklist de Verificação

Antes de começar a usar, verifique:

- [ ] PostgreSQL instalado e rodando
- [ ] Banco de dados criado e schema aplicado
- [ ] Arquivo `.env` configurado corretamente
- [ ] Dependências Go instaladas (`go mod download`)
- [ ] Dependências npm instaladas (`npm install`)
- [ ] Backend compila sem erros (`go build ./...`)
- [ ] Frontend inicia sem erros (`npm run dev`)
- [ ] Consegue acessar http://localhost:8080
- [ ] Consegue criar uma categoria de teste
- [ ] Consegue criar um cliente de teste
- [ ] Consegue criar um contrato de teste

---

**🎉 Parabéns! Você está pronto para usar o Contract Manager!**

Sistema desenvolvido por **Aeontech** | Versão 2.0