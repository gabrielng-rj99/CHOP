# Regras de Negócio — Licenses Manager

Este documento detalha as regras de negócio implementadas no Licenses Manager, cobrindo validações, restrições, fluxos e comportamentos esperados para cada entidade do sistema.

---

## 1. Empresas (Clients)

- **Cadastro**
  - O campo `registration_id` (CNPJ ou equivalente) deve ser único e válido.
  - O nome da empresa é obrigatório e deve ter entre 1 e 255 caracteres.
- **Arquivamento**
  - Empresas podem ser arquivadas (soft delete) para manter histórico.
  - Empresas arquivadas não podem receber novas licenças ou unidades.
  - Licenças associadas a empresas arquivadas tornam-se inativas.
- **Deleção Permanente**
  - Só é permitida após arquivamento.
  - Remove todas as unidades e licenças associadas (cascade delete).
  - Exige confirmação administrativa.

---

## 2. Unidades (Entities)

- **Cadastro**
  - Devem estar vinculadas a uma empresa existente.
  - Nome obrigatório e único dentro da empresa.
- **Atualização**
  - Não é permitido alterar o vínculo de empresa após criação.
- **Deleção**
  - Só pode ser deletada se não houver licenças ativas associadas.
  - Deleção desassocia licenças (entity_id passa a NULL), não exclui.

---

## 3. Categorias e Linhas (Categories & Lines)

- **Categorias**
  - Nome obrigatório, único (case-insensitive).
  - Só podem ser deletadas se não houver linhas associadas.
- **Linhas**
  - Devem pertencer a uma categoria existente.
  - Nome obrigatório, único dentro da categoria.
  - Só podem ser deletadas se não houver licenças associadas.
  - Não é permitido mover linhas entre categorias.

---

## 4. Licenças (Licenses)

- **Cadastro**
  - Devem estar vinculadas a uma empresa e linha existentes.
  - Podem ser associadas a uma unidade (opcional).
  - Nome e chave do produto obrigatórios.
  - Datas de início e fim obrigatórias, fim deve ser posterior ao início.
- **Validações**
  - Não podem ser atribuídas a empresas arquivadas.
  - Não pode haver sobreposição temporal de licenças do mesmo tipo para a mesma empresa/unidade.
  - Entity_id (se fornecido) deve existir.
- **Status**
  - Ativa: data atual entre início e fim.
  - Expirando: dentro do período de alerta configurável (ex: 30 dias antes do fim).
  - Expirada: data atual após fim.

---

## 5. Validações Comuns

- Todos os IDs devem ser UUIDs válidos.
- Todos os nomes entre 1 e 255 caracteres.
- Datas em formato ISO válido.
- Campos obrigatórios não podem ser nulos ou vazios.
- Chaves estrangeiras devem existir antes de inserir/atualizar.

---

## 6. Fluxos de Operação

- **Criação**
  - Validação de todos os campos obrigatórios.
  - Verificação de unicidade e existência de relacionamentos.
- **Atualização**
  - Permite alteração de campos não relacionais.
  - Valida integridade referencial.
- **Deleção**
  - Soft delete para histórico.
  - Cascade delete apenas quando permitido pelas regras.
- **Listagem**
  - Permite filtros por status, empresa, unidade, categoria, linha e período.

---

## 7. Erros e Respostas

- **ValidationError:** Dados inválidos, campos obrigatórios ausentes, formatos incorretos.
- **NotFoundError:** Entidade ou relacionamento não existe.
- **ConstraintError:** Violação de unicidade ou chave estrangeira.
- **StateError:** Operação não permitida no estado atual (ex: tentar criar licença para empresa arquivada).

---

## 8. Auditoria e Segurança

- Todas as operações críticas devem ser registradas para auditoria.
- Permissões de usuário devem ser respeitadas para operações administrativas.
- Operações de deleção permanente exigem confirmação explícita.

---

## 9. Recomendações para Expansão

- Documentar regras específicas para renovação de licenças e notificações automáticas.
- Detalhar fluxos de integração com APIs externas, se aplicável.
- Incluir exemplos práticos de validação e tratamento de erros.

---

Esta documentação será expandida conforme novas regras forem implementadas ou ajustadas no Licenses Manager.