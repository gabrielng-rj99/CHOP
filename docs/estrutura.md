# Documentação Estruturada do Projeto Licenses Manager

Este documento serve como referência central para a estrutura do projeto, organização dos arquivos, testes, banco de dados e funções principais.

---

## Estrutura de Pastas

```
Licenses-Manager/
├── backend/
│   ├── cmd/              # Aplicações CLI e Server
│   ├── database/         # Scripts SQL, diagramas e documentação do banco
│   ├── domain/           # Modelos de dados (structs principais)
│   ├── store/            # Lógica de acesso e manipulação de dados
│   ├── tests/            # Testes entityários e de integração
│   └── docs/             # Documentação técnica do backend
├── docs/                 # Documentação agregada do projeto
└── README.md             # Página inicial do GitHub
```

---

## Organização dos Testes

- **backend/tests/domain/**: Testes dos modelos de dados (validações, métodos).
- **backend/tests/store/**: Testes dos stores (CRUD, integrações, regras de negócio).
- **backend/tests/store/integration_test.go**: Testes de integração entre entidades (empresa, unidade, licença, tipo, categoria).
- **backend/tests/store/licenses_test.go**: Testes específicos para licenças.
- **backend/tests/store/types_test.go**: Testes específicos para tipos/linhas.
- **backend/tests/store/category_test.go**: Testes para categorias.
- **backend/tests/store/entity_test.go**: Testes para unidades.
- **backend/tests/store/user_test.go**: Testes para usuários.

---

## Banco de Dados

- **Script de inicialização:** `backend/database/init.sql`
  - Cria as tabelas principais: `users`, `companies`, `entities`, `categories`, `types`, `licenses`.
  - Os campos principais para licenças são: `modelo`, `product_key`, `start_date`, `end_date`, `type_id`, `client_id`, `entity_id`.
  - Para tipos/linhas: `linha`, `category_id`.

- **Diagramas:**
  - `backend/database/diagram.drawio` e backups `.bkp` para visualização das relações entre tabelas.

- **Documentação dos campos:**
  - `backend/database/docs/campos.md` detalha o significado de **Categoria**, **Linha** e **Modelo**.

---

## Funções e Fluxos Principais

- **CLI:**
  - Localizado em `backend/cmd/cli/main.go`.
  - Menus para gerenciamento de empresas, licenças, unidades, categorias, linhas e usuários.
  - Fluxos de criação, edição, deleção e listagem.

- **Models:**
  - Definidos em `backend/domain/models.go`.
  - Estruturas para `Client`, `Entity`, `Category`, `Type`, `License`, `User`.

- **Stores:**
  - CRUD e regras de negócio para cada entidade.
  - Exemplo: `LicenseStore`, `TypeStore`, `CategoryStore`, etc.

- **Testes:**
  - Cobrem validações, fluxos de negócio e integração entre entidades.

---

## Recomendações para Expansão da Documentação

- Adicionar exemplos de uso dos comandos CLI.
- Documentar endpoints se houver API.
- Detalhar regras de negócio específicas (ex: renovação de licença, notificações).
- Incluir instruções de deploy e configuração do ambiente.

---

## Referências

- [README.md](../README.md): Visão geral do projeto para o GitHub.
- [backend/database/docs/campos.md](../backend/database/docs/campos.md): Detalhamento dos campos de licença.

---

Esta documentação será expandida conforme o projeto evolui. Sugestões de melhoria são bem-vindas!
