# Contract Manager - Frontend

Interface web simples e limpa para gerenciamento de contratos e licenças.

## Stack

- React 18
- Vite
- CSS puro (inline styles)
- Zero dependências extras

## Pré-requisitos

- Node.js 18+
- Backend rodando em `http://localhost:8080`

## Instalação

```bash
npm install
```

## Executar

```bash
# Desenvolvimento
npm run dev

# Build para produção
npm run build

# Preview da build
npm run preview
```

A aplicação estará disponível em `http://localhost:3000`

## Estrutura

```
src/
├── pages/
│   ├── Login.jsx       # Tela de login
│   ├── Dashboard.jsx   # Dashboard com estatísticas
│   ├── Contracts.jsx   # Listagem de contratos
│   └── Clients.jsx     # Listagem de clientes
├── App.jsx             # Roteamento e estado global
└── main.jsx            # Entry point
```

## Funcionalidades

- ✅ Login/Logout
- ✅ Dashboard com estatísticas em tempo real
- ✅ Listagem de contratos com filtros
- ✅ Listagem de clientes
- ✅ Design responsivo
- ✅ Código limpo e simples

## API

O frontend consome a API REST do backend em `http://localhost:8080/api`

Todos os endpoints protegidos requerem Bearer Token no header:
```
Authorization: Bearer <token>
```

## Primeiro Acesso

1. Inicie o backend
2. Execute `npm run dev`
3. Acesse `http://localhost:3000`
4. Faça login ou registre-se

## Observações

- Código JavaScript puro (sem TypeScript)
- CSS inline (sem frameworks CSS)
- Estado gerenciado via React hooks
- Sem bibliotecas de roteamento complexas
- Sem gerenciadores de estado externos