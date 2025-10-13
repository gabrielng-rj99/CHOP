Licenses-Manager/docs/TESTS.md
# Documentação dos Testes — Licenses Manager

Este documento detalha a estratégia, estrutura e recomendações para os testes do projeto Licenses Manager, garantindo qualidade, segurança e confiabilidade nas funcionalidades implementadas.

---

## 1. Estratégia de Testes

O Licenses Manager utiliza testes automatizados para validar regras de negócio, integridade dos dados, cobertura de fluxos críticos e garantir que novas funcionalidades não quebrem o sistema existente.

- **Testes Unitários:** Validam funções e métodos isoladamente, cobrindo validações, cálculos e regras de negócio.
- **Testes de Integração:** Garantem que diferentes módulos (stores, banco de dados, CLI) funcionem corretamente juntos.
- **Testes de Regressão:** Asseguram que alterações não introduzam bugs em funcionalidades já existentes.
- **Testes de Cobertura:** Monitoram o percentual de código exercitado pelos testes.

---

## 2. Estrutura dos Testes

Os testes estão organizados conforme as principais áreas do backend:

```
backend/tests/
├── domain/         # Testes dos modelos de dados
├── store/          # Testes dos stores e regras de negócio
│   ├── licenses_test.go
│   ├── types_test.go
│   ├── category_test.go
│   ├── entity_test.go
│   ├── user_test.go
│   └── integration_test.go
```

### Exemplos de Testes por Entidade

- **ClientStore:** Criação, arquivamento, deleção permanente, unicidade de CNPJ.
- **EntityStore:** Criação, atualização, deleção, vinculação com empresa.
- **LicenseStore:** Criação, vinculação, datas válidas, status, sobreposição.
- **CategoryStore:** Criação, unicidade, deleção condicional.
- **LineStore:** Criação, vinculação, deleção condicional.

---

## 3. Checklist de Qualidade dos Testes

Para cada novo recurso, os testes devem cobrir:

- [ ] Validações de campos obrigatórios
- [ ] Formatos e tipos de dados
- [ ] Integridade referencial (FKs)
- [ ] Regras de negócio específicas
- [ ] Tratamento de erros e mensagens apropriadas
- [ ] Rollback em caso de falhas
- [ ] Cobertura de casos de sucesso e erro

### Cobertura Recomendada

- Statements: > 80%
- Branches: > 75%
- Functions: > 90%
- Lines: > 80%

---

## 4. MockDB e Simulação

Para garantir testes confiáveis e independentes do banco real, utiliza-se um sistema de MockDB:

- Simulação de queries e resultados
- Testes de erros e exceções
- Verificação de parâmetros e comportamentos esperados

---

## 5. Execução dos Testes

Para rodar todos os testes do backend:

```bash
go test ./backend/tests/store -v
```

Para verificar a cobertura:

```bash
go test ./backend/tests/store -cover
```

---

## 6. Recomendações e Boas Práticas

- Mantenha os testes independentes e reprodutíveis
- Use nomes descritivos para funções e casos de teste
- Documente comportamentos não óbvios nos próprios testes
- Atualize o checklist e documentação conforme novas regras ou entidades sejam criadas
- Realize revisão dos testes antes de cada PR ou release

---

## 7. Processo de Review

Antes do PR:
1. Execute todos os testes
2. Verifique a cobertura
3. Valide contra o checklist de qualidade
4. Atualize a documentação de testes

Durante o Review:
1. Confirme todos os itens do checklist
2. Verifique casos de borda e exceção
3. Valide mensagens de erro e logs
4. Confirme documentação atualizada

---

## 8. Referências

- [QUALITY_CHECKLIST.md](QUALITY_CHECKLIST.md): Checklist de qualidade para PRs e releases
- [backend/TESTS_BACKEND.md](backend/TESTS_BACKEND.md): Documentação detalhada dos testes do backend
- [Go Testing Documentation](https://golang.org/pkg/testing/): Guia oficial de testes em Go

---

Esta documentação será expandida conforme o projeto evolui. Sugestões de melhoria são bem-vindas!