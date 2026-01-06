/*
 * Client Hub Open Project
 * Copyright (C) 2025 Client Hub Contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

-- ============================================
-- CORE MODULE
-- ============================================
-- Este arquivo contém as tabelas e dados essenciais do sistema:
-- - system_settings: Configurações globais
-- - roles: Papéis de usuário
-- - permissions: Permissões disponíveis
-- - role_permissions: Mapeamento role <-> permission
--
-- Deve ser executado após 01_extensions.sql

-- ============================================
-- SYSTEM SETTINGS
-- ============================================
CREATE TABLE IF NOT EXISTS system_settings (
    key VARCHAR(255) PRIMARY KEY,
    value TEXT,
    description TEXT,
    category VARCHAR(100) DEFAULT 'general',
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ============================================
-- ROLES
-- ============================================
CREATE TABLE IF NOT EXISTS roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name CITEXT UNIQUE NOT NULL,
    display_name VARCHAR(255) NOT NULL,
    description TEXT,
    is_system BOOLEAN DEFAULT FALSE,
    is_active BOOLEAN DEFAULT TRUE,
    priority INTEGER NOT NULL DEFAULT 0,
    created_by_user_id UUID,
    is_single_user BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_roles_name ON roles(name);
CREATE INDEX IF NOT EXISTS idx_roles_priority ON roles(priority DESC);
CREATE INDEX IF NOT EXISTS idx_roles_is_system ON roles(is_system);
CREATE INDEX IF NOT EXISTS idx_roles_is_single_user ON roles(is_single_user) WHERE is_single_user = TRUE;

-- ============================================
-- PERMISSIONS
-- ============================================
CREATE TABLE IF NOT EXISTS permissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    resource VARCHAR(100) NOT NULL,
    action VARCHAR(50) NOT NULL,
    display_name VARCHAR(255) NOT NULL,
    description TEXT,
    category VARCHAR(100) DEFAULT 'general',
    UNIQUE(resource, action)
);

CREATE INDEX IF NOT EXISTS idx_permissions_resource ON permissions(resource);
CREATE INDEX IF NOT EXISTS idx_permissions_action ON permissions(action);

-- ============================================
-- ROLE <-> PERMISSION MAPPING
-- ============================================
CREATE TABLE IF NOT EXISTS role_permissions (
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id UUID NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (role_id, permission_id)
);

CREATE INDEX IF NOT EXISTS idx_role_permissions_role ON role_permissions(role_id);
CREATE INDEX IF NOT EXISTS idx_role_permissions_permission ON role_permissions(permission_id);

-- ============================================
-- DEFAULT ROLES
-- ============================================
-- Níveis de Prioridade:
--   100     = Crítico (root de sistema, não editável)
--   50-99   = Alto (administradores)
--   10-49   = Médio (operadores/usuários padrão)
--   1-9     = Baixo (visualizadores/convidados)

-- Role: Root (Super Admin) - Prioridade Crítica
INSERT INTO roles (id, name, display_name, description, is_system, is_active, priority)
VALUES (
    'a0000000-0000-0000-0000-000000000001',
    'root',
    'Super Administrador',
    'Acesso total ao sistema. Não pode ser modificado ou deletado. Único role com prioridade 100.',
    TRUE,
    TRUE,
    100
) ON CONFLICT (name) DO UPDATE SET
    display_name = EXCLUDED.display_name,
    description = EXCLUDED.description,
    priority = EXCLUDED.priority;

-- Role: Admin - Prioridade Alta
INSERT INTO roles (id, name, display_name, description, is_system, is_active, priority)
VALUES (
    'a0000000-0000-0000-0000-000000000002',
    'admin',
    'Administrador',
    'Gerencia usuários e tem acesso à maioria das funcionalidades. Não pode modificar configurações críticas do sistema.',
    TRUE,
    TRUE,
    50
) ON CONFLICT (name) DO UPDATE SET
    display_name = EXCLUDED.display_name,
    description = EXCLUDED.description,
    priority = EXCLUDED.priority;

-- Role: User - Prioridade Média
INSERT INTO roles (id, name, display_name, description, is_system, is_active, priority)
VALUES (
    'a0000000-0000-0000-0000-000000000003',
    'user',
    'Usuário',
    'Acesso padrão para operações do dia-a-dia. Pode criar, editar e arquivar registros.',
    TRUE,
    TRUE,
    10
) ON CONFLICT (name) DO UPDATE SET
    display_name = EXCLUDED.display_name,
    description = EXCLUDED.description,
    priority = EXCLUDED.priority;

-- Role: Viewer (Somente Leitura) - Prioridade Baixa
INSERT INTO roles (id, name, display_name, description, is_system, is_active, priority)
VALUES (
    'a0000000-0000-0000-0000-000000000004',
    'viewer',
    'Visualizador',
    'Acesso somente leitura. Não pode criar, editar ou deletar registros.',
    TRUE,
    TRUE,
    1
) ON CONFLICT (name) DO UPDATE SET
    display_name = EXCLUDED.display_name,
    description = EXCLUDED.description,
    priority = EXCLUDED.priority;

-- ============================================
-- PERMISSIONS - Clientes
-- ============================================
INSERT INTO permissions (id, resource, action, display_name, description, category) VALUES
('b0000000-0000-0000-0000-000000000001', 'clients', 'create', 'Criar Clientes', 'Permite criar novos clientes', 'Clientes'),
('b0000000-0000-0000-0000-000000000002', 'clients', 'read', 'Visualizar Clientes', 'Permite visualizar clientes', 'Clientes'),
('b0000000-0000-0000-0000-000000000003', 'clients', 'update', 'Editar Clientes', 'Permite editar clientes existentes', 'Clientes'),
('b0000000-0000-0000-0000-000000000004', 'clients', 'delete', 'Deletar Clientes', 'Permite deletar clientes permanentemente', 'Clientes'),
('b0000000-0000-0000-0000-000000000005', 'clients', 'archive', 'Arquivar Clientes', 'Permite arquivar/desarquivar clientes', 'Clientes'),
('b0000000-0000-0000-0000-000000000006', 'clients', 'export', 'Exportar Clientes', 'Permite exportar dados de clientes em diferentes formatos', 'Clientes')
ON CONFLICT (resource, action) DO UPDATE SET
    display_name = EXCLUDED.display_name,
    description = EXCLUDED.description,
    category = EXCLUDED.category;

-- ============================================
-- PERMISSIONS - Filiais (Sub-entidades)
-- ============================================
INSERT INTO permissions (id, resource, action, display_name, description, category) VALUES
('b0000000-0000-0000-0000-000000000011', 'affiliates', 'create', 'Criar Filiais', 'Permite criar novas filiais vinculadas a clientes', 'Filiais'),
('b0000000-0000-0000-0000-000000000012', 'affiliates', 'read', 'Visualizar Filiais', 'Permite visualizar filiais', 'Filiais'),
('b0000000-0000-0000-0000-000000000013', 'affiliates', 'update', 'Editar Filiais', 'Permite editar filiais existentes', 'Filiais'),
('b0000000-0000-0000-0000-000000000014', 'affiliates', 'delete', 'Deletar Filiais', 'Permite deletar filiais permanentemente', 'Filiais')
ON CONFLICT (resource, action) DO UPDATE SET
    display_name = EXCLUDED.display_name,
    description = EXCLUDED.description,
    category = EXCLUDED.category;

-- ============================================
-- PERMISSIONS - Contratos
-- ============================================
INSERT INTO permissions (id, resource, action, display_name, description, category) VALUES
('b0000000-0000-0000-0000-000000000021', 'contracts', 'create', 'Criar Contratos', 'Permite criar novos contratos', 'Contratos'),
('b0000000-0000-0000-0000-000000000022', 'contracts', 'read', 'Visualizar Contratos', 'Permite visualizar contratos', 'Contratos'),
('b0000000-0000-0000-0000-000000000023', 'contracts', 'update', 'Editar Contratos', 'Permite editar contratos existentes', 'Contratos'),
('b0000000-0000-0000-0000-000000000024', 'contracts', 'delete', 'Deletar Contratos', 'Permite deletar contratos permanentemente', 'Contratos'),
('b0000000-0000-0000-0000-000000000025', 'contracts', 'archive', 'Arquivar Contratos', 'Permite arquivar/desarquivar contratos', 'Contratos'),
('b0000000-0000-0000-0000-000000000026', 'contracts', 'export', 'Exportar Contratos', 'Permite exportar dados de contratos em diferentes formatos', 'Contratos')
ON CONFLICT (resource, action) DO UPDATE SET
    display_name = EXCLUDED.display_name,
    description = EXCLUDED.description,
    category = EXCLUDED.category;

-- ============================================
-- PERMISSIONS - Categorias e Subcategorias
-- ============================================
INSERT INTO permissions (id, resource, action, display_name, description, category) VALUES
('b0000000-0000-0000-0000-000000000031', 'categories', 'create', 'Criar Categorias', 'Permite criar novas categorias de contratos', 'Categorias'),
('b0000000-0000-0000-0000-000000000032', 'categories', 'read', 'Visualizar Categorias', 'Permite visualizar categorias e subcategorias', 'Categorias'),
('b0000000-0000-0000-0000-000000000033', 'categories', 'update', 'Editar Categorias', 'Permite editar categorias existentes', 'Categorias'),
('b0000000-0000-0000-0000-000000000034', 'categories', 'delete', 'Deletar Categorias', 'Permite deletar categorias permanentemente', 'Categorias'),
('b0000000-0000-0000-0000-000000000035', 'categories', 'archive', 'Arquivar Categorias', 'Permite arquivar/desarquivar categorias', 'Categorias'),
('b0000000-0000-0000-0000-000000000041', 'subcategories', 'create', 'Criar Subcategorias', 'Permite criar novas subcategorias', 'Categorias'),
('b0000000-0000-0000-0000-000000000042', 'subcategories', 'read', 'Visualizar Subcategorias', 'Permite visualizar subcategorias', 'Categorias'),
('b0000000-0000-0000-0000-000000000043', 'subcategories', 'update', 'Editar Subcategorias', 'Permite editar subcategorias existentes', 'Categorias'),
('b0000000-0000-0000-0000-000000000044', 'subcategories', 'delete', 'Deletar Subcategorias', 'Permite deletar subcategorias', 'Categorias')
ON CONFLICT (resource, action) DO UPDATE SET
    display_name = EXCLUDED.display_name,
    description = EXCLUDED.description,
    category = EXCLUDED.category;

-- ============================================
-- PERMISSIONS - Usuários
-- ============================================
INSERT INTO permissions (id, resource, action, display_name, description, category) VALUES
('b0000000-0000-0000-0000-000000000051', 'users', 'create', 'Criar Usuários', 'Permite criar novos usuários do sistema', 'Usuários'),
('b0000000-0000-0000-0000-000000000052', 'users', 'read', 'Visualizar Usuários', 'Permite visualizar lista e detalhes de usuários', 'Usuários'),
('b0000000-0000-0000-0000-000000000053', 'users', 'update', 'Editar Usuários', 'Permite editar dados de outros usuários', 'Usuários'),
('b0000000-0000-0000-0000-000000000054', 'users', 'delete', 'Deletar Usuários', 'Permite deletar usuários permanentemente', 'Usuários'),
('b0000000-0000-0000-0000-000000000055', 'users', 'block', 'Bloquear/Desbloquear Usuários', 'Permite bloquear e desbloquear acesso de usuários', 'Usuários'),
('b0000000-0000-0000-0000-000000000056', 'users', 'manage_roles', 'Gerenciar Papéis de Usuários', 'Permite alterar o papel/role atribuído a usuários', 'Usuários'),
('b0000000-0000-0000-0000-000000000101', 'users', 'create_admin', 'Criar Administradores', 'Permite criar usuários com role admin', 'Usuários'),
('b0000000-0000-0000-0000-000000000102', 'users', 'create_user', 'Criar Usuários Padrão', 'Permite criar usuários com role user', 'Usuários'),
('b0000000-0000-0000-0000-000000000103', 'users', 'create_viewer', 'Criar Visualizadores', 'Permite criar usuários com role viewer', 'Usuários'),
('b0000000-0000-0000-0000-000000000104', 'users', 'create_custom', 'Criar Usuários Personalizados', 'Permite criar usuários com roles customizados', 'Usuários'),
('b0000000-0000-0000-0000-000000000105', 'users', 'manage_sessions', 'Gerenciar Sessões', 'Permite visualizar e encerrar sessões de usuários', 'Usuários'),
('b0000000-0000-0000-0000-000000000106', 'users', 'reset_password', 'Resetar Senhas', 'Permite forçar reset de senha de usuários', 'Usuários'),
('b0000000-0000-0000-0000-000000000107', 'users', 'view_activity', 'Ver Atividade de Usuários', 'Permite visualizar log de atividades de usuários', 'Usuários')
ON CONFLICT (resource, action) DO UPDATE SET
    display_name = EXCLUDED.display_name,
    description = EXCLUDED.description,
    category = EXCLUDED.category;

-- ============================================
-- PERMISSIONS - Auditoria
-- ============================================
INSERT INTO permissions (id, resource, action, display_name, description, category) VALUES
('b0000000-0000-0000-0000-000000000061', 'audit_logs', 'read', 'Visualizar Logs de Auditoria', 'Permite visualizar histórico de ações do sistema', 'Auditoria'),
('b0000000-0000-0000-0000-000000000062', 'audit_logs', 'export', 'Exportar Logs de Auditoria', 'Permite exportar logs de auditoria em diferentes formatos', 'Auditoria'),
('b0000000-0000-0000-0000-000000000131', 'audit_logs', 'read_all', 'Ver Todos os Logs', 'Permite visualizar logs de auditoria de todo o sistema', 'Auditoria'),
('b0000000-0000-0000-0000-000000000132', 'audit_logs', 'read_own', 'Ver Logs Próprios', 'Permite visualizar apenas logs das próprias ações', 'Auditoria'),
('b0000000-0000-0000-0000-000000000133', 'audit_logs', 'delete', 'Deletar Logs', 'Permite remover logs de auditoria (uso crítico)', 'Auditoria'),
('b0000000-0000-0000-0000-000000000134', 'audit_logs', 'configure', 'Configurar Auditoria', 'Permite configurar retenção e tipos de log', 'Auditoria')
ON CONFLICT (resource, action) DO UPDATE SET
    display_name = EXCLUDED.display_name,
    description = EXCLUDED.description,
    category = EXCLUDED.category;

-- ============================================
-- PERMISSIONS - Sistema e Segurança
-- ============================================
INSERT INTO permissions (id, resource, action, display_name, description, category) VALUES
('b0000000-0000-0000-0000-000000000071', 'settings', 'read', 'Visualizar Configurações', 'Permite visualizar configurações gerais do sistema', 'Sistema'),
('b0000000-0000-0000-0000-000000000072', 'settings', 'update', 'Alterar Configurações', 'Permite alterar configurações gerais (branding, labels, etc)', 'Sistema'),
('b0000000-0000-0000-0000-000000000073', 'settings', 'manage_security', 'Gerenciar Segurança', 'Permite configurar políticas de senha, bloqueio e sessão', 'Sistema'),
('b0000000-0000-0000-0000-000000000074', 'settings', 'manage_branding', 'Gerenciar Marca', 'Permite alterar logo, nome e identidade visual', 'Sistema'),
('b0000000-0000-0000-0000-000000000121', 'settings', 'manage_labels', 'Gerenciar Rótulos', 'Permite personalizar rótulos/labels do sistema', 'Sistema'),
('b0000000-0000-0000-0000-000000000122', 'settings', 'manage_uploads', 'Gerenciar Uploads', 'Permite fazer upload de arquivos (logos, etc)', 'Sistema'),
('b0000000-0000-0000-0000-000000000123', 'settings', 'view_system_info', 'Ver Informações do Sistema', 'Permite visualizar versão, status, estatísticas', 'Sistema')
ON CONFLICT (resource, action) DO UPDATE SET
    display_name = EXCLUDED.display_name,
    description = EXCLUDED.description,
    category = EXCLUDED.category;

-- ============================================
-- PERMISSIONS - Segurança Avançada
-- ============================================
INSERT INTO permissions (id, resource, action, display_name, description, category) VALUES
('b0000000-0000-0000-0000-000000000111', 'security', 'manage_password_policy', 'Gerenciar Política de Senha', 'Permite configurar políticas de senha do sistema', 'Segurança'),
('b0000000-0000-0000-0000-000000000112', 'security', 'manage_session_policy', 'Gerenciar Política de Sessão', 'Permite configurar duração de sessão e refresh token', 'Segurança'),
('b0000000-0000-0000-0000-000000000113', 'security', 'manage_lock_policy', 'Gerenciar Política de Bloqueio', 'Permite configurar níveis de bloqueio de conta', 'Segurança'),
('b0000000-0000-0000-0000-000000000114', 'security', 'manage_rate_limit', 'Gerenciar Rate Limiting', 'Permite configurar limites de requisições', 'Segurança'),
('b0000000-0000-0000-0000-000000000115', 'security', 'view_security_logs', 'Ver Logs de Segurança', 'Permite visualizar tentativas de login e bloqueios', 'Segurança')
ON CONFLICT (resource, action) DO UPDATE SET
    display_name = EXCLUDED.display_name,
    description = EXCLUDED.description,
    category = EXCLUDED.category;

-- ============================================
-- PERMISSIONS - Papéis (Roles)
-- ============================================
INSERT INTO permissions (id, resource, action, display_name, description, category) VALUES
('b0000000-0000-0000-0000-000000000141', 'roles', 'create', 'Criar Papéis', 'Permite criar novos papéis/roles personalizados', 'Sistema'),
('b0000000-0000-0000-0000-000000000142', 'roles', 'read', 'Visualizar Papéis', 'Permite visualizar lista de papéis e suas permissões', 'Sistema'),
('b0000000-0000-0000-0000-000000000143', 'roles', 'update', 'Editar Papéis', 'Permite modificar papéis existentes e suas permissões', 'Sistema'),
('b0000000-0000-0000-0000-000000000144', 'roles', 'delete', 'Deletar Papéis', 'Permite deletar papéis personalizados (não de sistema)', 'Sistema'),
('b0000000-0000-0000-0000-000000000124', 'roles', 'manage_permissions', 'Gerenciar Permissões de Roles', 'Permite atribuir/remover permissões de roles', 'Sistema'),
('b0000000-0000-0000-0000-000000000125', 'roles', 'manage_custom', 'Gerenciar Roles Personalizados', 'Permite criar/editar/deletar roles customizados', 'Sistema')
ON CONFLICT (resource, action) DO UPDATE SET
    display_name = EXCLUDED.display_name,
    description = EXCLUDED.description,
    category = EXCLUDED.category;

-- ============================================
-- PERMISSIONS - Tema e Aparência
-- ============================================
INSERT INTO permissions (id, resource, action, display_name, description, category) VALUES
('b0000000-0000-0000-0000-000000000081', 'theme', 'read', 'Visualizar Tema', 'Permite visualizar configurações de tema', 'Aparência'),
('b0000000-0000-0000-0000-000000000082', 'theme', 'update', 'Alterar Tema Pessoal', 'Permite personalizar tema da própria conta', 'Aparência'),
('b0000000-0000-0000-0000-000000000083', 'theme', 'manage_global', 'Gerenciar Tema Global', 'Permite definir tema padrão do sistema', 'Aparência'),
('b0000000-0000-0000-0000-000000000084', 'theme', 'manage_permissions', 'Gerenciar Permissões de Tema', 'Permite definir quem pode editar temas', 'Aparência')
ON CONFLICT (resource, action) DO UPDATE SET
    display_name = EXCLUDED.display_name,
    description = EXCLUDED.description,
    category = EXCLUDED.category;

-- ============================================
-- PERMISSIONS - Dashboard
-- ============================================
INSERT INTO permissions (id, resource, action, display_name, description, category) VALUES
('b0000000-0000-0000-0000-000000000091', 'dashboard', 'read', 'Visualizar Dashboard', 'Permite acessar o painel principal do sistema', 'Dashboard'),
('b0000000-0000-0000-0000-000000000092', 'dashboard', 'export', 'Exportar Relatórios', 'Permite exportar relatórios e estatísticas do dashboard', 'Dashboard'),
('b0000000-0000-0000-0000-000000000093', 'dashboard', 'configure', 'Configurar Dashboard', 'Permite personalizar widgets e exibição do dashboard', 'Dashboard')
ON CONFLICT (resource, action) DO UPDATE SET
    display_name = EXCLUDED.display_name,
    description = EXCLUDED.description,
    category = EXCLUDED.category;

-- ============================================
-- ROLE PERMISSIONS MAPPINGS
-- ============================================

-- ROOT: Todas as permissões (sempre terá tudo)
INSERT INTO role_permissions (role_id, permission_id)
SELECT 'a0000000-0000-0000-0000-000000000001', id FROM permissions
ON CONFLICT DO NOTHING;

-- ADMIN: Maioria das permissões, exceto gestão de roles e segurança crítica
INSERT INTO role_permissions (role_id, permission_id)
SELECT 'a0000000-0000-0000-0000-000000000002', id FROM permissions
WHERE
    -- Não pode gerenciar roles de sistema
    resource != 'roles'
    -- Não pode alterar configurações de segurança crítica
    AND NOT (resource = 'settings' AND action = 'manage_security')
    AND NOT (resource = 'security' AND action IN ('manage_password_policy', 'manage_session_policy', 'manage_lock_policy', 'manage_rate_limit'))
    -- Não pode atribuir roles a usuários (apenas root)
    AND NOT (resource = 'users' AND action = 'manage_roles')
    -- Não pode criar admins
    AND NOT (resource = 'users' AND action = 'create_admin')
    -- Não pode deletar logs de auditoria
    AND NOT (resource = 'audit_logs' AND action = 'delete')
ON CONFLICT DO NOTHING;

-- USER: Operações do dia-a-dia, sem deletar permanentemente
INSERT INTO role_permissions (role_id, permission_id)
SELECT 'a0000000-0000-0000-0000-000000000003', id FROM permissions
WHERE
    -- Clientes: criar, ler, editar, arquivar (não deletar)
    (resource = 'clients' AND action IN ('create', 'read', 'update', 'archive'))
    -- Filiais: criar, ler, editar (não deletar)
    OR (resource = 'affiliates' AND action IN ('create', 'read', 'update'))
    -- Contratos: criar, ler, editar, arquivar (não deletar)
    OR (resource = 'contracts' AND action IN ('create', 'read', 'update', 'archive'))
    -- Categorias: apenas ler
    OR (resource = 'categories' AND action = 'read')
    OR (resource = 'subcategories' AND action = 'read')
    -- Tema: ler e editar próprio
    OR (resource = 'theme' AND action IN ('read', 'update'))
    -- Dashboard: ler
    OR (resource = 'dashboard' AND action = 'read')
    -- Auditoria: ver apenas logs próprios
    OR (resource = 'audit_logs' AND action = 'read_own')
ON CONFLICT DO NOTHING;

-- VIEWER: Apenas leitura
INSERT INTO role_permissions (role_id, permission_id)
SELECT 'a0000000-0000-0000-0000-000000000004', id FROM permissions
WHERE
    action = 'read'
    AND resource IN ('clients', 'affiliates', 'contracts', 'categories', 'subcategories', 'dashboard', 'theme')
ON CONFLICT DO NOTHING;

-- ============================================
-- SYSTEM SETTINGS - Theme
-- ============================================
INSERT INTO system_settings (key, value, description, category)
VALUES ('permissions.users_can_edit_theme', 'false', 'Permite que usuários comuns personalizem seu tema', 'theme')
ON CONFLICT (key) DO UPDATE SET
    description = EXCLUDED.description,
    category = EXCLUDED.category,
    updated_at = CURRENT_TIMESTAMP;

INSERT INTO system_settings (key, value, description, category)
VALUES ('permissions.admins_can_edit_theme', 'true', 'Permite que administradores personalizem seu tema', 'theme')
ON CONFLICT (key) DO UPDATE SET
    description = EXCLUDED.description,
    category = EXCLUDED.category,
    updated_at = CURRENT_TIMESTAMP;

INSERT INTO system_settings (key, value, description, category)
VALUES ('allowed_themes', 'amber,amethyst,aqua,arcade,arctic,aurora,autumn,beach,bee,berry,blue_orange,candy,celeste,coral,cosmic,dark,default,dragon,earthy,emerald,forest,galaxy,gold,grape,honey,lavender,light,lime,matrix,mermaid,midnight,mint,monokai,neon,neon_city,ocean,olive,pastel,pastel_ocean,pink,pumpkin,purple_yellow,red_green,ruby,sapphire,scarlet,solarized,spring,summer,sunflower,sunset,synthwave,teal,terracotta,tiger,violet,volcanic,winter,zen', 'Lista de temas permitidos', 'theme')
ON CONFLICT (key) DO UPDATE SET
    value = EXCLUDED.value,
    description = EXCLUDED.description,
    category = EXCLUDED.category;

INSERT INTO system_settings (key, value, description, category)
VALUES ('global_theme.preset', 'default', 'Tema padrão global do sistema', 'theme')
ON CONFLICT (key) DO UPDATE SET
    value = EXCLUDED.value,
    description = EXCLUDED.description,
    category = EXCLUDED.category;

-- ============================================
-- SYSTEM SETTINGS - Dashboard
-- ============================================
INSERT INTO system_settings (key, value, description, category)
VALUES ('dashboard.show_birthdays', 'true', 'Exibir widget de aniversariantes no dashboard', 'dashboard')
ON CONFLICT (key) DO UPDATE SET
    description = EXCLUDED.description,
    category = EXCLUDED.category,
    updated_at = CURRENT_TIMESTAMP;

INSERT INTO system_settings (key, value, description, category)
VALUES ('dashboard.birthdays_days_ahead', '7', 'Mostrar aniversariantes dos próximos X dias', 'dashboard')
ON CONFLICT (key) DO UPDATE SET
    description = EXCLUDED.description,
    category = EXCLUDED.category,
    updated_at = CURRENT_TIMESTAMP;

INSERT INTO system_settings (key, value, description, category)
VALUES ('dashboard.show_recent_activity', 'true', 'Exibir widget de atividade recente', 'dashboard')
ON CONFLICT (key) DO UPDATE SET
    description = EXCLUDED.description,
    category = EXCLUDED.category,
    updated_at = CURRENT_TIMESTAMP;

INSERT INTO system_settings (key, value, description, category)
VALUES ('dashboard.recent_activity_count', '10', 'Número de itens de atividade recente a exibir', 'dashboard')
ON CONFLICT (key) DO UPDATE SET
    description = EXCLUDED.description,
    category = EXCLUDED.category,
    updated_at = CURRENT_TIMESTAMP;

INSERT INTO system_settings (key, value, description, category)
VALUES ('dashboard.show_statistics', 'true', 'Exibir widget de estatísticas (totais de clientes, contratos, etc)', 'dashboard')
ON CONFLICT (key) DO UPDATE SET
    description = EXCLUDED.description,
    category = EXCLUDED.category,
    updated_at = CURRENT_TIMESTAMP;

INSERT INTO system_settings (key, value, description, category)
VALUES ('dashboard.show_expiring_contracts', 'true', 'Exibir widget de contratos próximos ao vencimento', 'dashboard')
ON CONFLICT (key) DO UPDATE SET
    description = EXCLUDED.description,
    category = EXCLUDED.category,
    updated_at = CURRENT_TIMESTAMP;

INSERT INTO system_settings (key, value, description, category)
VALUES ('dashboard.expiring_days_ahead', '30', 'Mostrar contratos que vencem nos próximos X dias', 'dashboard')
ON CONFLICT (key) DO UPDATE SET
    description = EXCLUDED.description,
    category = EXCLUDED.category,
    updated_at = CURRENT_TIMESTAMP;

INSERT INTO system_settings (key, value, description, category)
VALUES ('dashboard.show_quick_actions', 'true', 'Exibir botões de ações rápidas no dashboard', 'dashboard')
ON CONFLICT (key) DO UPDATE SET
    description = EXCLUDED.description,
    category = EXCLUDED.category,
    updated_at = CURRENT_TIMESTAMP;

-- ============================================
-- SYSTEM SETTINGS - Notifications
-- ============================================
INSERT INTO system_settings (key, value, description, category)
VALUES ('notifications.email', '', 'E-mail para notificações do sistema (vazio = desabilitado)', 'notifications')
ON CONFLICT (key) DO UPDATE SET
    description = EXCLUDED.description,
    category = EXCLUDED.category,
    updated_at = CURRENT_TIMESTAMP;

INSERT INTO system_settings (key, value, description, category)
VALUES ('notifications.phone', '', 'Telefone para notificações SMS (vazio = desabilitado)', 'notifications')
ON CONFLICT (key) DO UPDATE SET
    description = EXCLUDED.description,
    category = EXCLUDED.category,
    updated_at = CURRENT_TIMESTAMP;

INSERT INTO system_settings (key, value, description, category)
VALUES ('notifications.notify_on_login_failure', 'false', 'Enviar notificação em tentativas de login falhas', 'notifications')
ON CONFLICT (key) DO UPDATE SET
    description = EXCLUDED.description,
    category = EXCLUDED.category,
    updated_at = CURRENT_TIMESTAMP;

INSERT INTO system_settings (key, value, description, category)
VALUES ('notifications.notify_on_user_blocked', 'true', 'Enviar notificação quando um usuário for bloqueado', 'notifications')
ON CONFLICT (key) DO UPDATE SET
    description = EXCLUDED.description,
    category = EXCLUDED.category,
    updated_at = CURRENT_TIMESTAMP;

INSERT INTO system_settings (key, value, description, category)
VALUES ('notifications.notify_on_contract_expiry', 'true', 'Enviar notificação quando contratos estiverem próximos ao vencimento', 'notifications')
ON CONFLICT (key) DO UPDATE SET
    description = EXCLUDED.description,
    category = EXCLUDED.category,
    updated_at = CURRENT_TIMESTAMP;

-- ============================================
-- SYSTEM SETTINGS - Audit
-- ============================================
INSERT INTO system_settings (key, value, description, category)
VALUES ('audit.retention_days', '365', 'Dias para manter logs de auditoria (0 = manter para sempre)', 'audit')
ON CONFLICT (key) DO UPDATE SET
    description = EXCLUDED.description,
    category = EXCLUDED.category,
    updated_at = CURRENT_TIMESTAMP;

INSERT INTO system_settings (key, value, description, category)
VALUES ('audit.log_reads', 'false', 'Registrar operações de leitura no log (aumenta volume de dados)', 'audit')
ON CONFLICT (key) DO UPDATE SET
    description = EXCLUDED.description,
    category = EXCLUDED.category,
    updated_at = CURRENT_TIMESTAMP;

INSERT INTO system_settings (key, value, description, category)
VALUES ('audit.log_login_success', 'true', 'Registrar logins bem-sucedidos', 'audit')
ON CONFLICT (key) DO UPDATE SET
    description = EXCLUDED.description,
    category = EXCLUDED.category,
    updated_at = CURRENT_TIMESTAMP;

INSERT INTO system_settings (key, value, description, category)
VALUES ('audit.log_login_failure', 'true', 'Registrar tentativas de login falhas', 'audit')
ON CONFLICT (key) DO UPDATE SET
    description = EXCLUDED.description,
    category = EXCLUDED.category,
    updated_at = CURRENT_TIMESTAMP;
