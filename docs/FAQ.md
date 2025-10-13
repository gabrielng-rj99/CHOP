Licenses-Manager/docs/FAQ.md
# FAQ — Licenses Manager

Perguntas Frequentes sobre o projeto Licenses Manager

---

## 1. O que é o Licenses Manager?

Licenses Manager é um sistema para gestão centralizada de licenças de software, empresas, unidades, categorias, linhas e usuários, com foco em automação, rastreabilidade e segurança.

---

## 2. Quais tecnologias são utilizadas no projeto?

- Backend: Go (Golang)
- Banco de dados: PostgreSQL (recomendado)
- Testes: Go test, mocks customizados
- Documentação: Markdown

---

## 3. Como instalar e configurar o Licenses Manager?

Consulte o arquivo [INSTALL.md](INSTALL.md) para instruções detalhadas de instalação, configuração do banco de dados e execução do sistema.

---

## 4. O sistema possui interface gráfica?

Atualmente, o Licenses Manager opera via CLI (linha de comando). A arquitetura permite futura expansão para API REST ou interface web.

---

## 5. Como cadastrar uma nova licença?

Utilize o comando CLI correspondente ou siga os exemplos em [USAGE.md](USAGE.md). É necessário informar empresa, linha, categoria, modelo, datas e chave do produto.

---

## 6. Quais são os campos obrigatórios para uma licença?

- Nome/modelo
- Product key
- Data de início e fim
- Linha (type)
- Empresa (client)
- Unidade (entity, opcional)

Veja detalhes em [FIELDS.md](backend/FIELDS.md).

---

## 7. Como funciona o arquivamento de empresas?

Empresas podem ser arquivadas (soft delete) para manter histórico. Empresas arquivadas não podem receber novas licenças e suas unidades ficam inativas.

---

## 8. O sistema controla licenças expiradas ou próximas do vencimento?

Sim. Licenças são classificadas como ativas, expirando em breve ou expiradas, conforme as datas cadastradas. Relatórios podem ser gerados via CLI.

---

## 9. Como executar os testes do projeto?

Execute:
```bash
go test ./backend/tests/store -v
```
Consulte [TESTS.md](TESTS.md) para detalhes sobre cobertura e estrutura dos testes.

---

## 10. Como contribuir para o projeto?

Sugestões, correções e novas funcionalidades são bem-vindas! Siga o checklist de qualidade em [QUALITY_CHECKLIST.md](QUALITY_CHECKLIST.md) e envie seu PR.

---

## 11. Onde encontro o histórico de versões?

Consulte [CHANGELOG.md](CHANGELOG.md) para acompanhar as principais mudanças e evoluções do projeto.

---

## 12. Como reportar bugs ou solicitar novas funcionalidades?

Abra uma issue no repositório ou envie sugestões diretamente para os mantenedores conforme indicado no [README.md](README.md).

---

## 13. O projeto está pronto para produção?

O Licenses Manager está em desenvolvimento ativo. Recomenda-se testes e validação antes do uso em ambientes críticos.

---

## 14. Onde encontro mais informações técnicas?

Consulte os arquivos de documentação em `docs/` e `docs/backend/`, especialmente:
- [ARCHITECTURE.md](ARCHITECTURE.md)
- [DATABASE.md](DATABASE.md)
- [ENTITIES.md](ENTITIES.md)
- [BUSINESS_RULES.md](BUSINESS_RULES.md)

---

Se sua dúvida não está aqui, consulte os demais arquivos da documentação ou entre em contato com os mantenedores!