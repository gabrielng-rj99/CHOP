# 🚀 Quick Start Guide - Contract Manager

Guia rápido para colocar o sistema funcionando em menos de 5 minutos.

## 📋 Pré-requisitos

Certifique-se de ter instalado:

- **Go 1.21+** - [Download](https://go.dev/dl/)
- **Node.js 18+** - [Download](https://nodejs.org/)
- **Git** - [Download](https://git-scm.com/)

## 🎯 Instalação Rápida

### 1️⃣ Clone o Repositório

```bash
git clone https://github.com/seu-usuario/Contract-Manager.git
cd Contract-Manager
```

### 2️⃣ Configure o Backend

```bash
# Navegue até o backend
cd backend

# Instale as dependências
go mod tidy

# Execute o servidor
go run cmd/server/main.go
```

✅ **Backend rodando em:** `http://localhost:8080`

O banco de dados SQLite será criado automaticamente na primeira execução.

### 3️⃣ Configure o Frontend (Nova janela/terminal)

```bash
# Navegue até o frontend (a partir da raiz do projeto)
cd frontend

# Instale as dependências
npm install

# 3. Execute em modo desenvolvimento
npm run dev
```

✅ **Frontend rodando em:** `http://localhost:3000`

## 🎉 Pronto!

Abra seu navegador em `http://localhost:3000` e você verá a tela de login.

### Primeiro Acesso

Você tem duas opções para criar seu primeiro usuário:

#### Opção 1: Via Interface Web
1. Acesse `http://localhost:3000`
2. Clique em "Cadastre-se"
3. Preencha os dados (lembre-se: senha com 16+ caracteres, números, letras e símbolos)
4. Faça login

#### Opção 2: Via CLI (Criar Admin)
```bash
cd backend
go run cmd/cli/main.go admin create
```

## 🔍 Verificando se está tudo OK

### Teste o Backend
```bash
# Em outro terminal
curl http://localhost:8080/health
```

Resposta esperada:
```json
{
  "status": "healthy",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### Teste o Frontend
Abra `http://localhost:3000` no navegador. Você deve ver a tela de login.

## 📊 Próximos Passos

Agora que o sistema está rodando:

1. **Faça login** com seu usuário
2. **Explore o Dashboard** - veja as estatísticas em tempo real
3. **Crie seu primeiro cliente** - clique em "Novo Cliente"
4. **Adicione categorias e linhas** - organize seus produtos
5. **Cadastre contratos** - comece a gerenciar suas licenças

## 🛠️ Comandos Úteis

### Backend
```bash
# Executar testes
go test ./store -v

# Build para produção
go build -o Open-Generic-Hub cmd/server/main.go

# Executar CLI
go run cmd/cli/main.go
```

### Frontend
```bash
# Modo desenvolvimento
npm run dev

# Build para produção
npm run build

# Preview da build
npm run preview
```

## 🔧 Solução de Problemas

### Backend não inicia
- Verifique se a porta 8080 está livre
- Confirme que o Go está instalado: `go version`
- Rode `go mod tidy` novamente

### Frontend não carrega
- Verifique se a porta 3000 está livre
- Confirme que o Node.js está instalado: `node --version`
- Delete `node_modules` e rode `npm install` novamente

### Erro de conexão entre Frontend e Backend
- Certifique-se que o backend está rodando em `http://localhost:8080`
- O frontend usa proxy do Vite configurado em `vite.config.js`
- Se necessário, edite o arquivo `vite.config.js` para ajustar a URL da API

### Erro ao fazer login
- Verifique se você criou um usuário
- Senha deve ter 16+ caracteres, números, letras maiúsculas/minúsculas e símbolos
- Não pode conter espaços

## 📚 Documentação Adicional

- **Frontend:** [frontend/README.md](frontend/README.md)
- **Arquitetura:** [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
- **Setup Detalhado:** [docs/SETUP.md](docs/SETUP.md)
- **Uso da CLI:** [docs/USAGE.md](docs/USAGE.md)
- **API Endpoints:** [README.md](README.md#-api-endpoints)

## 🎓 Tutorial Rápido

### Fluxo Básico de Uso

1. **Login** → Acesse com suas credenciais
2. **Dashboard** → Veja a visão geral dos contratos
3. **Categorias** → Crie categorias (ex: "Antivírus", "Sistema Operacional")
4. **Linhas** → Crie linhas de produtos (ex: "Windows 11", "Kaspersky Enterprise")
5. **Clientes** → Cadastre seus clientes/empresas
6. **Contratos** → Registre os contratos com datas de validade
7. **Monitor** → Acompanhe contratos expirando e expirados

## 💡 Dicas

- Use senhas fortes para maior segurança (16+ caracteres, números, letras e símbolos)
- Mantenha o backup do arquivo `contracts.db` (gerado pelo SQLite)
- Contratos com menos de 30 dias para vencer aparecem como "Expirando em Breve"
- Você pode arquivar clientes e contratos (soft delete) para auditoria
- O sistema possui proteção contra brute-force automática
- O frontend é construído com código limpo e zero dependências extras

## 🆘 Precisa de Ajuda?

- Leia a documentação completa em [docs/](docs/)
- Verifique issues existentes no GitHub
- Abra uma nova issue se encontrar problemas

---

**Pronto para começar?** Execute os comandos acima e em 5 minutos você estará gerenciando seus contratos! 🎉
