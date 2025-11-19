# Docker Setup Flow

Este documento explica o fluxo completo de configuração e deploy usando Docker Compose.

## 🔄 Fluxo Completo

Quando você executa a opção **"Start all services"** (opção 11) no Docker Mode, o sistema executa automaticamente o seguinte fluxo:

### 1. Verificação de Volumes ✅

O sistema verifica se existem volumes Docker do PostgreSQL:

```bash
docker volume ls -q
```

- Se volumes **EXISTEM**: pula para geração do compose (sem perguntas)
- Se volumes **NÃO EXISTEM**: inicia fluxo de primeira execução

### 2. Confirmação de Setup Inicial ⚠️

Se não houver volumes, você verá:

```
⚠️  WARNING: No existing volumes found!
This appears to be a first-time setup or volumes were removed.
Proceeding will create a fresh database (all previous data will be lost if volumes were removed).

❓ Do you want to proceed with fresh setup? (yes/no):
```

**Opções:**
- `yes` / `y`: Continua com setup
- `no` / `n`: Cancela operação

### 3. Configuração Customizada 📝

Se você confirmou, o sistema pergunta:

```
📝 Configuration Options
❓ Do you want to customize configuration (database name, user, ports, etc.)? (yes/no):
```

**Se responder `yes`:**

#### 3.1. Editor de Configuração

O sistema abre o arquivo `deploy/config/docker.ini` no seu editor de texto padrão (detecta `$EDITOR`, `$VISUAL`, ou usa `nano`/`vim`/`vi`).

**No arquivo você pode configurar:**

```ini
[docker]
# Nomes dos containers
postgres_container = postgres
backend_container = backend
frontend_container = frontend

# Portas expostas no host
postgres_port = 5432
backend_port = 3000
frontend_port = 8081

# Volume do PostgreSQL
postgres_volume = postgres_data

# Network
network_name = opengeneric-network

[database]
# Credenciais do banco (NÃO configure senha aqui)
db_name = contracts_manager
db_user = postgres
db_port = 5432

[jwt]
# Configurações JWT (NÃO configure secret aqui)
jwt_algorithm = HS256
jwt_expiration_time = 60
jwt_refresh_expiration_time = 10080
```

**⚠️ IMPORTANTE:** O arquivo contém um aviso de que as senhas (DB_PASSWORD e JWT_SECRET) serão configuradas na próxima etapa.

### 4. Configuração de Segurança 🔐

Após salvar o `docker.ini`, o sistema solicita as credenciais de segurança:

#### 4.1. Senha do Banco de Dados

```
🔐 Security Configuration
Now we need to set up security credentials:

1️⃣  Database Password
   Enter database password (leave empty for auto-generated 64-char password):
```

**Opções:**
- Digite uma senha: usa sua senha
- Deixe vazio (ENTER): gera senha aleatória de **64 caracteres** (recomendado)

#### 4.2. JWT Secret

```
2️⃣  JWT Secret
   Enter JWT secret (leave empty for auto-generated secure secret):
```

**Opções:**
- Digite um secret: usa seu secret
- Deixe vazio (ENTER): gera secret aleatório de **64 caracteres** (recomendado)

#### 4.3. Salvar Credenciais

Após gerar/definir as credenciais, você verá:

```
================================================================================
🔐 CREDENTIALS GENERATED - SAVE THESE SECURELY!
================================================================================

⚠️  IMPORTANT: Save these credentials in a password manager immediately!
   These will NOT be shown again after this setup completes.

📝 Database Password:
   [sua senha de 64 caracteres]

📝 JWT Secret:
   [seu secret de 64 caracteres]

================================================================================

💡 Recommended: Use a password manager like:
   • Bitwarden (https://bitwarden.com)
   • 1Password (https://1password.com)
   • KeePassXC (https://keepassxc.org)

✅ Press ENTER after saving the credentials to continue...
```

**⚠️ CRÍTICO:** Salve essas credenciais em um gerenciador de senhas AGORA! Elas não serão mostradas novamente.

### 5. Geração do docker-compose.yml 🔧

Após confirmar que salvou as credenciais:

```
🔧 Generating docker-compose.yml...
   Location: deploy/config/docker-compose.yml
   ✅ docker-compose.yml generated successfully

💡 TIP: You can make final adjustments to the generated file at:
   deploy/config/docker-compose.yml

   Ready to proceed? Press ENTER to continue or Ctrl+C to abort...
```

Neste ponto, você pode:
- Pressionar **ENTER**: continua com o deploy
- Pressionar **Ctrl+C**: aborta para fazer ajustes manuais no arquivo

### 6. Deploy dos Serviços 🚀

Finalmente, o sistema executa:

```bash
docker compose -f deploy/config/docker-compose.yml up -d
```

E você verá:

```
▶️  Starting all services (docker compose up -d)...
✅ All services started!
  Frontend: http://localhost:8081
  Backend:  http://localhost:3000
  Database: localhost:5432
```

## 📁 Arquivos Envolvidos

### Configuração

- **`deploy/config/docker.ini`**: Configuração principal (portas, nomes, etc.)
- **`deploy/config/templates/docker-compose.tmpl`**: Template do compose (não editar diretamente)
- **`deploy/config/docker-compose.yml`**: Arquivo final gerado (pode fazer ajustes manuais)

### Código do Fluxo

- **`deploy/cmd/docker_setup_flow.go`**: Implementação do fluxo interativo
- **`deploy/cmd/docker_compose_generator.go`**: Gerador do compose a partir do template
- **`deploy/cmd/docker_operations.go`**: Operações Docker (start, stop, etc.)

## 🔒 Segurança

### Senhas Geradas Automaticamente

O sistema usa `crypto/rand` para gerar senhas criptograficamente seguras:

```go
// Gera 64 bytes aleatórios e codifica em base64
bytes := make([]byte, 64*3/4)
rand.Read(bytes)
password := base64.URLEncoding.EncodeToString(bytes)[:64]
```

### Onde as Credenciais São Armazenadas

As credenciais **NÃO** são armazenadas em arquivos de configuração. Elas são:

1. Geradas/solicitadas no setup
2. Mostradas uma única vez na tela
3. Injetadas no `docker-compose.yml` gerado
4. Usadas como variáveis de ambiente nos containers

**⚠️ O docker-compose.yml contém as credenciais em texto plano!**

Por isso:
- Nunca faça commit do `docker-compose.yml` para repositórios públicos
- O arquivo está no `.gitignore`
- Use um gerenciador de senhas para backup

## 🔄 Execuções Subsequentes

### Quando volumes já existem

Se você executar "Start all services" novamente e os volumes já existirem:

1. ✅ Pula verificação inicial
2. ✅ Pula configuração de senhas
3. ✅ Apenas regenera o compose se necessário
4. ✅ Sobe os serviços

### Quando fazer setup novamente

Execute "Clean database and volumes" ou "Clean all" para remover volumes e forçar um novo setup na próxima execução.

## 🛠️ Troubleshooting

### Editor não abre

**Erro:** `no text editor found (set $EDITOR or $VISUAL)`

**Solução:**
```bash
export EDITOR=nano
# ou
export EDITOR=vim
# ou
export EDITOR=code --wait  # VS Code
```

### Volume não detectado

**Problema:** Sistema sempre pede setup mesmo com volumes existentes

**Verificar:**
```bash
docker volume ls | grep postgres
```

Se o volume existe mas não é detectado, verifique o nome em `docker.ini`:
```ini
[docker]
postgres_volume = nome_correto_do_volume
```

### Senha perdida

**Problema:** Perdi as credenciais geradas

**Solução:**
1. Execute "Clean database and volumes"
2. Execute "Start all services" novamente
3. O sistema gerará novas credenciais
4. **⚠️ TODOS OS DADOS SERÃO PERDIDOS**

### Ajustes manuais no compose

Se você precisa fazer ajustes manuais:

1. Edite `deploy/config/docker-compose.yml` diretamente
2. Execute manualmente: `docker compose -f deploy/config/docker-compose.yml up -d`
3. **Nota:** Na próxima regeneração, ajustes manuais serão perdidos

Para manter ajustes:
- Edite `deploy/config/templates/docker-compose.tmpl`
- Ou adicione configurações em `deploy/config/docker.ini`

## 📚 Próximos Passos

Após o deploy:

1. **Verificar status:** Opção 2 (Container Status)
2. **Ver logs:** Opções 3-6 (View Logs)
3. **Acessar aplicação:**
   - Frontend: http://localhost:8081
   - Backend API: http://localhost:3000
   - Banco de dados: localhost:5432

4. **Backup das credenciais:** Certifique-se de que salvou em um gerenciador de senhas!

## 🎯 Boas Práticas

1. ✅ Sempre use senhas auto-geradas (64 caracteres)
2. ✅ Salve credenciais em gerenciador de senhas
3. ✅ Não commite `docker-compose.yml`
4. ✅ Use volumes para persistência de dados
5. ✅ Faça backup regular dos volumes Docker
6. ✅ Revise configurações antes de gerar o compose
7. ✅ Documente mudanças customizadas no `docker.ini`

## 🔗 Referências

- Docker Compose: https://docs.docker.com/compose/
- Docker Volumes: https://docs.docker.com/storage/volumes/
- Bitwarden: https://bitwarden.com
- PostgreSQL: https://www.postgresql.org/docs/