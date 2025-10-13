Licenses-Manager/docs/QUALITY_CHECKLIST.md
# Checklist de Qualidade — Licenses Manager

Este checklist deve ser seguido antes de aprovar Pull Requests (PRs) ou realizar novos releases do projeto Licenses Manager. Ele garante padrões mínimos de qualidade, segurança, documentação e testes.

---

## 1. Código e Estilo

- [ ] O código segue o padrão de estilo definido (naming, indentação, organização de arquivos)
- [ ] Não há código morto, duplicado ou comentado sem justificativa
- [ ] Funções e métodos possuem nomes claros e descritivos
- [ ] Variáveis e constantes são autoexplicativas
- [ ] Não há hardcodes de credenciais, tokens ou dados sensíveis

---

## 2. Documentação

- [ ] Todos os arquivos alterados/novos estão documentados
- [ ] Funções públicas possuem comentários explicativos
- [ ] Mudanças relevantes estão descritas no CHANGELOG.md
- [ ] Novos comandos, fluxos ou endpoints estão documentados em USAGE.md ou README.md
- [ ] Novas entidades ou campos estão descritos em ENTITIES.md ou FIELDS.md

---

## 3. Testes

- [ ] Novos recursos possuem testes unitários e/ou de integração
- [ ] Cobertura de testes mantida ou aumentada (verificar com `go test -cover`)
- [ ] Casos de erro e borda são contemplados nos testes
- [ ] Testes passam localmente e no CI/CD
- [ ] Mocks e fakes são usados para dependências externas

---

## 4. Segurança

- [ ] Não há exposição de dados sensíveis em logs, erros ou respostas
- [ ] Validações de entrada/sanitização de dados implementadas
- [ ] Permissões e acessos revisados para novos endpoints/fluxos
- [ ] Dependências atualizadas e sem vulnerabilidades conhecidas

---

## 5. Performance e Escalabilidade

- [ ] Consultas ao banco otimizadas e sem N+1
- [ ] Operações críticas revisadas quanto a concorrência e transações
- [ ] Não há vazamentos de recursos (conexões, arquivos, goroutines)

---

## 6. Deploy e Configuração

- [ ] Novas variáveis de ambiente/documentadas em INSTALL.md
- [ ] Scripts de deploy/testados e atualizados
- [ ] Instruções de rollback/revert disponíveis para mudanças críticas

---

## 7. Revisão e Aprovação

- [ ] PR revisado por pelo menos um membro do time
- [ ] Comentários e sugestões do review foram tratados
- [ ] Branch está atualizada com a base principal (main/master)
- [ ] Não há conflitos pendentes

---

## 8. Pós-Release

- [ ] Versão/documentada no CHANGELOG.md
- [ ] Tags e releases criadas conforme padrão do projeto
- [ ] Comunicação das mudanças para o time e usuários (se aplicável)

---

**Observação:** Este checklist deve ser atualizado conforme o projeto evolui. Sugestões de melhoria são bem-vindas!