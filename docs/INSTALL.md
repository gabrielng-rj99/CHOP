Licenses-Manager/docs/INSTALL.md
# Guia de Instalação e Configuração — Licenses Manager

Este documento orienta a instalação, configuração e primeiros passos para rodar o Licenses Manager em ambiente de desenvolvimento ou produção.

---

## Pré-requisitos

- **Go** (versão 1.18 ou superior)
- **PostgreSQL** (ou outro banco compatível, conforme configuração)
- **Git** (para clonar o repositório)
- **Make** (opcional, para automação de comandos)
- **Ferramenta de diagramas** (Draw.io, opcional para visualizar diagramas)

---

## Passo 1: Clonando o Repositório

```bash
git clone https://github.com/seu-usuario/Licenses-Manager.git
cd Licenses-Manager
```

---

## Passo 2: Configurando o Banco de Dados

1. Crie um banco de dados PostgreSQL:
   ```bash
   createdb licenses_manager
   ```
2. Execute o script de inicialização:
   ```bash
   psql -d licenses_manager -f backend/database/init.sql
   ```
3. (Opcional) Visualize o diagrama do banco em `backend/database/diagram.drawio`.

---

## Passo 3: Configurando Variáveis de Ambiente

Crie um arquivo `.env` na raiz do projeto com os parâmetros de conexão:

```
DB_HOST=localhost
DB_PORT=5432
DB_USER=seu_usuario
DB_PASSWORD=sua_senha
DB_NAME=licenses_manager
```

---

## Passo 4: Instalando Dependências

No diretório `backend/`:

```bash
cd backend
go mod tidy
```

---

## Passo 5: Rodando a Aplicação CLI

```bash
go run cmd/cli/main.go
```

---

## Passo 6: Executando Testes

```bash
go test ./tests/store -v
go test ./tests/store -cover
```

---

## Passo 7: Configuração para Produção

- Configure variáveis de ambiente seguras.
- Utilize banco de dados dedicado.
- Implemente backups regulares.
- Considere uso de Docker para facilitar deploy.

---

## Solução de Problemas

- **Erro de conexão:** Verifique se o banco está rodando e as variáveis de ambiente estão corretas.
- **Dependências Go:** Execute `go mod tidy` para instalar pacotes faltantes.
- **Permissões:** Certifique-se que o usuário do banco tem permissões de leitura/escrita.

---

## Referências

- [Documentação do Go](https://golang.org/doc/)
- [Documentação do PostgreSQL](https://www.postgresql.org/docs/)
- [Documentação do projeto](README.md)

---

Pronto! O Licenses Manager está instalado e pronto para uso.