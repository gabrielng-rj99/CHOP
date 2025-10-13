Licenses-Manager/docs/ARCHITECTURE.md
# Arquitetura do Sistema — Licenses Manager

Este documento apresenta a arquitetura do Licenses Manager, detalhando os principais componentes, fluxos, padrões adotados e diretrizes para evolução do sistema.

---

## Visão Geral

Licenses Manager é um sistema modular para gestão de licenças de software, empresas, unidades, categorias, linhas e usuários. O backend é desenvolvido em Go, com foco em testabilidade, segurança, rastreabilidade e automação dos processos de TI.

---

## Componentes Principais

### 1. Backend

- **cmd/**  
  Entrada principal do sistema (CLI e Server). Gerencia inicialização, configuração e roteamento de comandos.

- **domain/**  
  Define os modelos de dados centrais (`Client`, `Entity`, `Category`, `Line`, `License`, `User`). Utiliza structs Go para garantir tipagem forte e validação.

- **store/**  
  Implementa a lógica de acesso ao banco de dados e regras de negócio. Cada entidade possui um Store dedicado, responsável por CRUD, validações e integrações.

- **database/**  
  Scripts SQL para criação e manutenção do banco. Diagramas para visualização das relações entre tabelas.

- **tests/**  
  Testes unitários e de integração, com uso extensivo de mocks para simulação de cenários e validação de regras.

- **docs/**  
  Documentação técnica detalhada do backend.

### 2. Banco de Dados

- **Relacional (PostgreSQL recomendado)**
- Tabelas principais: `users`, `companies`, `entities`, `categories`, `lines`, `licenses`
- Relacionamentos via chaves estrangeiras
- Constraints para garantir integridade referencial e unicidade

### 3. CLI (Interface de Linha de Comando)

- Menus para gerenciamento de empresas, licenças, unidades, categorias, linhas e usuários
- Fluxos de criação, edição, deleção e listagem
- Validações e feedbacks em tempo real

---

## Fluxos Principais

### Cadastro de Licença

1. Usuário seleciona empresa e unidade (opcional)
2. Escolhe categoria, linha e modelo
3. Informa dados da licença (product key, datas)
4. Sistema valida dados e persistência no banco

### Arquivamento de Empresa

1. Usuário solicita arquivamento
2. Sistema verifica se há licenças ativas
3. Se permitido, marca empresa como arquivada (soft delete)
4. Licenças associadas tornam-se inativas

### Deleção Permanente

1. Empresa deve estar arquivada
2. Usuário confirma operação
3. Sistema executa cascade delete em entidades e licenças

---

## Padrões e Diretrizes

- **Separação de responsabilidades:** Cada Store cuida de uma entidade e suas regras
- **Validação centralizada:** Antes de qualquer operação, dados são validados
- **Soft delete:** Utilizado para histórico e rastreabilidade
- **Transações:** Operações que afetam múltiplas tabelas usam transações para garantir atomicidade
- **Mocks em testes:** Permitem simular cenários de banco e garantir cobertura de regras de negócio
- **Prepared statements:** Segurança contra SQL Injection

---

## Evolução e Extensibilidade

- **API REST:** Estrutura preparada para expansão via endpoints HTTP
- **Notificações:** Possibilidade de integração com sistemas de alerta para licenças expirando
- **Auditoria:** Log de operações críticas para rastreabilidade
- **Internacionalização:** Suporte a múltiplos idiomas planejado para futuras versões

---

## Diagrama Simplificado

```
[CLI/Server]
     |
 [Stores] <--> [Database]
     |
 [Domain Models]
```

- CLI/Server interage com Stores, que encapsulam regras e acesso ao banco.
- Stores manipulam Domain Models e garantem integridade dos dados.
- Database armazena persistentemente todas as informações.

---

## Referências

- [ENTITIES.md](ENTITIES.md): Modelos de dados e entidades
- [DATABASE.md](DATABASE.md): Estrutura e scripts do banco
- [BUSINESS_RULES.md](BUSINESS_RULES.md): Regras de negócio detalhadas
- [TESTS.md](TESTS.md): Estratégia de testes e cobertura

---

Esta arquitetura foi desenhada para garantir robustez, escalabilidade e facilidade de manutenção. Sugestões para aprimoramento são bem-vindas!