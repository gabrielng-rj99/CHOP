# Sistema de Roles e Permissões Customizáveis

## 📋 Visão Geral

Este documento descreve o design proposto para um sistema de roles e permissões customizáveis no Contract Manager, permitindo que administradores root criem e gerenciem roles personalizadas com permissões granulares.

---

## 🎯 Objetivos

1. **Flexibilidade**: Permitir criação de roles customizadas além das padrões (root, admin, user)
2. **Granularidade**: Controle fino sobre permissões por entidade e operação
3. **Segurança**: Manter roles padrões protegidas e imutáveis
4. **Escalabilidade**: Suportar crescimento do sistema com novas entidades/operações
5. **Auditoria**: Registrar todas as mudanças em roles e permissões

---

## 🏗️ Arquitetura Proposta

### 1. Estrutura de Dados

#### Tabela: `roles`
```sql
CREATE TABLE roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(50) UNIQUE NOT NULL,
    display_name VARCHAR(100) NOT NULL,
    description TEXT,
    is_system_role BOOLEAN DEFAULT FALSE,  -- Roles padrões (root, admin, user)
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    created_by UUID REFERENCES users(id),
    CONSTRAINT chk_name_format CHECK (name ~ '^[a-z][a-z0-9_]*$')
);

-- Roles padrões (imutáveis)
INSERT INTO roles (name, display_name, description, is_system_role) VALUES
('root', 'Root', 'Acesso total ao sistema, pode criar e gerenciar roles', TRUE),
('admin', 'Administrador', 'Gerencia usuários, clientes e contratos', TRUE),
('user', 'Usuário', 'Acesso básico ao sistema', TRUE);
```

#### Tabela: `permissions`
```sql
CREATE TABLE permissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    code VARCHAR(100) UNIQUE NOT NULL,
    entity VARCHAR(50) NOT NULL,      -- user, client, contract, line, category, etc.
    action VARCHAR(50) NOT NULL,      -- create, read, update, delete, list, etc.
    description TEXT,
    created_at TIMESTAMP DEFAULT NOW(),
    CONSTRAINT chk_code_format CHECK (code = entity || '.' || action)
);

-- Exemplos de permissões
INSERT INTO permissions (code, entity, action, description) VALUES
-- Usuários
('user.create', 'user', 'create', 'Criar novos usuários'),
('user.read', 'user', 'read', 'Visualizar dados de usuários'),
('user.update', 'user', 'update', 'Editar dados de usuários'),
('user.delete', 'user', 'delete', 'Deletar usuários'),
('user.list', 'user', 'list', 'Listar usuários'),
('user.change_role', 'user', 'change_role', 'Alterar role de usuários'),
('user.change_username', 'user', 'change_username', 'Alterar username de usuários'),
('user.block', 'user', 'block', 'Bloquear/desbloquear usuários'),

-- Clientes
('client.create', 'client', 'create', 'Criar novos clientes'),
('client.read', 'client', 'read', 'Visualizar dados de clientes'),
('client.update', 'client', 'update', 'Editar dados de clientes'),
('client.delete', 'client', 'delete', 'Deletar clientes'),
('client.list', 'client', 'list', 'Listar clientes'),

-- Contratos
('contract.create', 'contract', 'create', 'Criar novos contratos'),
('contract.read', 'contract', 'read', 'Visualizar contratos'),
('contract.update', 'contract', 'update', 'Editar contratos'),
('contract.delete', 'contract', 'delete', 'Deletar contratos'),
('contract.list', 'contract', 'list', 'Listar contratos'),

-- Linhas
('line.create', 'line', 'create', 'Criar linhas'),
('line.read', 'line', 'read', 'Visualizar linhas'),
('line.update', 'line', 'update', 'Editar linhas'),
('line.delete', 'line', 'delete', 'Deletar linhas'),
('line.list', 'line', 'list', 'Listar linhas'),

-- Categorias
('category.create', 'category', 'create', 'Criar categorias'),
('category.read', 'category', 'read', 'Visualizar categorias'),
('category.update', 'category', 'update', 'Editar categorias'),
('category.delete', 'category', 'delete', 'Deletar categorias'),
('category.list', 'category', 'list', 'Listar categorias'),

-- Dependentes
('dependent.create', 'dependent', 'create', 'Criar dependentes'),
('dependent.read', 'dependent', 'read', 'Visualizar dependentes'),
('dependent.update', 'dependent', 'update', 'Editar dependentes'),
('dependent.delete', 'dependent', 'delete', 'Deletar dependentes'),
('dependent.list', 'dependent', 'list', 'Listar dependentes'),

-- Audit Logs
('audit_log.read', 'audit_log', 'read', 'Visualizar audit logs'),
('audit_log.list', 'audit_log', 'list', 'Listar audit logs'),

-- Roles (gerenciamento de permissões)
('role.create', 'role', 'create', 'Criar novas roles'),
('role.read', 'role', 'read', 'Visualizar roles'),
('role.update', 'role', 'update', 'Editar roles'),
('role.delete', 'role', 'delete', 'Deletar roles customizadas'),
('role.list', 'role', 'list', 'Listar roles'),
('role.assign_permissions', 'role', 'assign_permissions', 'Atribuir permissões a roles');
```

#### Tabela: `role_permissions`
```sql
CREATE TABLE role_permissions (
    role_id UUID REFERENCES roles(id) ON DELETE CASCADE,
    permission_id UUID REFERENCES permissions(id) ON DELETE CASCADE,
    granted_at TIMESTAMP DEFAULT NOW(),
    granted_by UUID REFERENCES users(id),
    PRIMARY KEY (role_id, permission_id)
);

-- Permissões da role 'root' (acesso total)
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
CROSS JOIN permissions p
WHERE r.name = 'root';

-- Permissões da role 'admin' (gerenciamento exceto roles)
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
CROSS JOIN permissions p
WHERE r.name = 'admin'
AND p.entity IN ('user', 'client', 'contract', 'line', 'category', 'dependent')
AND p.action NOT IN ('change_role', 'change_username');

-- Permissões da role 'user' (leitura e criação básica)
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
CROSS JOIN permissions p
WHERE r.name = 'user'
AND p.entity IN ('client', 'contract', 'line', 'category', 'dependent')
AND p.action IN ('read', 'list', 'create', 'update');
```

#### Atualizar Tabela: `users`
```sql
-- Manter compatibilidade, mas role agora referencia a tabela roles
ALTER TABLE users ADD COLUMN role_id UUID REFERENCES roles(id);

-- Migrar roles existentes
UPDATE users u
SET role_id = r.id
FROM roles r
WHERE u.role = r.name;

-- Após migração completa, pode remover a coluna antiga (opcional)
-- ALTER TABLE users DROP COLUMN role;
```

---

## 🔧 Implementação Backend (Go)

### 1. Domain Models

```go
// domain/role.go
package domain

import "time"

type Role struct {
    ID            string     `json:"id"`
    Name          string     `json:"name"`
    DisplayName   string     `json:"display_name"`
    Description   *string    `json:"description,omitempty"`
    IsSystemRole  bool       `json:"is_system_role"`
    IsActive      bool       `json:"is_active"`
    CreatedAt     time.Time  `json:"created_at"`
    UpdatedAt     time.Time  `json:"updated_at"`
    CreatedBy     *string    `json:"created_by,omitempty"`
    Permissions   []Permission `json:"permissions,omitempty"`
}

type Permission struct {
    ID          string    `json:"id"`
    Code        string    `json:"code"`
    Entity      string    `json:"entity"`
    Action      string    `json:"action"`
    Description *string   `json:"description,omitempty"`
    CreatedAt   time.Time `json:"created_at"`
}

type RolePermission struct {
    RoleID       string    `json:"role_id"`
    PermissionID string    `json:"permission_id"`
    GrantedAt    time.Time `json:"granted_at"`
    GrantedBy    *string   `json:"granted_by,omitempty"`
}
```

### 2. Role Store

```go
// store/role_store.go
package store

type RoleStore struct {
    db DBInterface
}

func NewRoleStore(db DBInterface) *RoleStore {
    return &RoleStore{db: db}
}

// CreateRole - Apenas root pode criar roles
func (s *RoleStore) CreateRole(name, displayName string, description *string, createdBy string) (*domain.Role, error)

// GetRoleByID - Buscar role por ID
func (s *RoleStore) GetRoleByID(roleID string) (*domain.Role, error)

// GetRoleByName - Buscar role por nome
func (s *RoleStore) GetRoleByName(name string) (*domain.Role, error)

// ListRoles - Listar todas as roles ativas
func (s *RoleStore) ListRoles(includeInactive bool) ([]domain.Role, error)

// UpdateRole - Atualizar role (não permite atualizar system roles)
func (s *RoleStore) UpdateRole(roleID, displayName string, description *string) error

// DeleteRole - Deletar role customizada (não permite deletar system roles)
func (s *RoleStore) DeleteRole(roleID string) error

// GetRolePermissions - Buscar todas as permissões de uma role
func (s *RoleStore) GetRolePermissions(roleID string) ([]domain.Permission, error)

// GrantPermission - Conceder permissão a uma role
func (s *RoleStore) GrantPermission(roleID, permissionID, grantedBy string) error

// RevokePermission - Revogar permissão de uma role
func (s *RoleStore) RevokePermission(roleID, permissionID string) error

// HasPermission - Verificar se role tem permissão específica
func (s *RoleStore) HasPermission(roleID, permissionCode string) (bool, error)

// ListPermissions - Listar todas as permissões disponíveis
func (s *RoleStore) ListPermissions() ([]domain.Permission, error)

// GetPermissionsByEntity - Listar permissões por entidade
func (s *RoleStore) GetPermissionsByEntity(entity string) ([]domain.Permission, error)
```

### 3. Permission Middleware

```go
// cmd/server/permission_middleware.go
package main

import (
    "net/http"
    "strings"
)

// requirePermission - Middleware que verifica se usuário tem permissão específica
func (s *Server) requirePermission(permissionCode string, next http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        claims, err := getClaimsFromRequest(r, s.userStore)
        if err != nil {
            respondError(w, http.StatusUnauthorized, "Token inválido ou não fornecido")
            return
        }

        // Root sempre tem todas as permissões
        if claims.Role == "root" {
            next(w, r)
            return
        }

        // Buscar role do usuário
        user, err := s.userStore.GetUserByID(claims.UserID)
        if err != nil || user.RoleID == nil {
            respondError(w, http.StatusForbidden, "Role do usuário não encontrada")
            return
        }

        // Verificar se tem a permissão
        hasPermission, err := s.roleStore.HasPermission(*user.RoleID, permissionCode)
        if err != nil || !hasPermission {
            log.Printf("Permissão negada: user=%s, permission=%s", claims.Username, permissionCode)
            respondError(w, http.StatusForbidden, "Você não tem permissão para esta ação")
            return
        }

        next(w, r)
    }
}

// Exemplo de uso nas rotas:
// http.HandleFunc("/api/users", s.requirePermission("user.list", s.handleUsers))
// http.HandleFunc("/api/clients", s.requirePermission("client.list", s.handleClients))
```

---

## 🎨 Interface do Frontend

### 1. Página de Gerenciamento de Roles

**Rota:** `/roles`

**Componentes:**
- `RolesList.jsx` - Lista de todas as roles
- `RoleForm.jsx` - Criar/editar role
- `PermissionsMatrix.jsx` - Matriz visual de permissões
- `RoleAssignment.jsx` - Atribuir role a usuários

### 2. Matriz de Permissões

```
+--------------------+--------+------+--------+--------+------+
| Entidade           | Criar  | Ler  | Editar | Deletar| Listar|
+--------------------+--------+------+--------+--------+------+
| Usuários           |   ✓    |  ✓   |   ✓    |   ✗    |   ✓  |
| Clientes           |   ✓    |  ✓   |   ✓    |   ✓    |   ✓  |
| Contratos          |   ✓    |  ✓   |   ✓    |   ✓    |   ✓  |
| Linhas             |   ✓    |  ✓   |   ✓    |   ✓    |   ✓  |
| Categorias         |   ✓    |  ✓   |   ✓    |   ✗    |   ✓  |
| Dependentes        |   ✓    |  ✓   |   ✓    |   ✓    |   ✓  |
| Audit Logs         |   ✗    |  ✓   |   ✗    |   ✗    |   ✓  |
+--------------------+--------+------+--------+--------+------+
```

### 3. Exemplos de Roles Customizadas

#### Role: `gestor_comercial`
**Permissões:**
- `client.*` (todas operações em clientes)
- `contract.create`, `contract.read`, `contract.update`, `contract.list`
- `line.read`, `line.list`
- `category.read`, `category.list`

#### Role: `operador`
**Permissões:**
- `client.read`, `client.list`
- `contract.read`, `contract.update`, `contract.list`
- `line.*` (todas operações em linhas)
- `dependent.*` (todas operações em dependentes)

#### Role: `auditor`
**Permissões:**
- Todas permissões de `read` e `list`
- `audit_log.read`, `audit_log.list`
- Nenhuma permissão de `create`, `update` ou `delete`

---

## 🔒 Regras de Segurança

1. **System Roles são imutáveis**
   - `root`, `admin`, `user` não podem ser deletadas ou renomeadas
   - Permissões de `root` não podem ser modificadas

2. **Apenas root pode gerenciar roles**
   - Criar, editar, deletar roles customizadas
   - Atribuir/revogar permissões

3. **Hierarquia de roles**
   - `root` > `admin` > roles customizadas > `user`
   - Usuários só podem gerenciar roles abaixo de sua hierarquia

4. **Validações**
   - Nome de role deve ser único e em snake_case
   - Não pode existir role sem permissões
   - Ao deletar role, usuários com essa role devem ser reatribuídos

5. **Auditoria completa**
   - Todas operações em roles são registradas no audit log
   - Mudanças de permissões são rastreadas

---

## 📊 Migrations

### Ordem de Execução:

1. `03_create_roles_table.sql` - Criar tabela de roles
2. `04_create_permissions_table.sql` - Criar tabela de permissões
3. `05_create_role_permissions_table.sql` - Criar tabela de relacionamento
4. `06_populate_default_permissions.sql` - Popular permissões padrão
5. `07_populate_default_roles.sql` - Popular roles padrão
6. `08_migrate_user_roles.sql` - Migrar usuários para novo sistema

---

## 🚀 Roadmap de Implementação

### Fase 1: Backend (Semana 1-2)
- [ ] Criar tabelas e migrations
- [ ] Implementar RoleStore
- [ ] Implementar PermissionStore
- [ ] Criar middleware de permissões
- [ ] Atualizar todos os handlers para usar permissões

### Fase 2: API (Semana 2-3)
- [ ] Endpoints CRUD de roles
- [ ] Endpoints de gerenciamento de permissões
- [ ] Endpoints de atribuição de roles a usuários
- [ ] Documentar API no Swagger/Postman

### Fase 3: Frontend (Semana 3-4)
- [ ] Página de listagem de roles
- [ ] Formulário de criação/edição de role
- [ ] Matriz de permissões interativa
- [ ] Atribuição de roles a usuários
- [ ] Visualização de permissões efetivas

### Fase 4: Testes e Refinamentos (Semana 4-5)
- [ ] Testes unitários
- [ ] Testes de integração
- [ ] Testes de segurança
- [ ] Documentação de usuário
- [ ] Treinamento da equipe

---

## 📝 Exemplos de Uso

### Criar Role via API
```bash
POST /api/roles
{
  "name": "gestor_comercial",
  "display_name": "Gestor Comercial",
  "description": "Gerencia clientes e contratos"
}
```

### Atribuir Permissões
```bash
POST /api/roles/{role_id}/permissions
{
  "permission_codes": [
    "client.create",
    "client.read",
    "client.update",
    "client.list",
    "contract.create",
    "contract.read",
    "contract.update",
    "contract.list"
  ]
}
```

### Atribuir Role a Usuário
```bash
PUT /api/users/{user_id}/role
{
  "role_id": "uuid-da-role"
}
```

### Verificar Permissões de um Usuário
```bash
GET /api/users/{user_id}/permissions
```

Resposta:
```json
{
  "role": {
    "id": "...",
    "name": "gestor_comercial",
    "display_name": "Gestor Comercial"
  },
  "permissions": [
    {
      "code": "client.create",
      "entity": "client",
      "action": "create",
      "description": "Criar novos clientes"
    },
    // ...
  ]
}
```

---

## 🔍 Considerações Futuras

1. **Permissões por Campo**
   - Controlar quais campos o usuário pode ver/editar
   - Ex: usuário pode ver contratos mas não valores

2. **Permissões Temporárias**
   - Conceder permissões por tempo limitado
   - Útil para acessos temporários

3. **Grupos de Permissões**
   - Agrupar permissões relacionadas
   - Facilitar atribuição em massa

4. **Delegação de Permissões**
   - Permitir que admins deleguem permissões específicas
   - Sem precisar de intervenção do root

5. **Permissões Condicionais**
   - Baseadas em regras (ex: só pode editar seus próprios registros)
   - Baseadas em contexto (ex: horário, localização)

---

**Autor:** Sistema Contract Manager  
**Última Atualização:** 2024-11-16  
**Versão:** 1.0.0