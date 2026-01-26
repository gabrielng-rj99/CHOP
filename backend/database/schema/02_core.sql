/*
 * Client Hub Open Project
 * Copyright (C) 2026 Client Hub Contributors
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
-- ROLE PERMISSIONS - Settings
-- ============================================

-- ROOT: Todas as permissões de settings
INSERT INTO role_permissions (role_id, permission_id)
SELECT 'a0000000-0000-0000-0000-000000000001', id FROM permissions
WHERE resource = 'settings'
ON CONFLICT DO NOTHING;

-- ADMIN: Settings exceto manage_security
INSERT INTO role_permissions (role_id, permission_id)
SELECT 'a0000000-0000-0000-0000-000000000002', id FROM permissions
WHERE resource = 'settings' AND action != 'manage_security'
ON CONFLICT DO NOTHING;

-- ============================================
-- ROLE PERMISSIONS - Roles
-- ============================================

-- ROOT: Todas as permissões de roles
INSERT INTO role_permissions (role_id, permission_id)
SELECT 'a0000000-0000-0000-0000-000000000001', id FROM permissions
WHERE resource = 'roles'
ON CONFLICT DO NOTHING;

-- ============================================
-- ROLE PERMISSIONS - Theme
-- ============================================

-- ROOT: Todas as permissões de theme
INSERT INTO role_permissions (role_id, permission_id)
SELECT 'a0000000-0000-0000-0000-000000000001', id FROM permissions
WHERE resource = 'theme'
ON CONFLICT DO NOTHING;

-- ADMIN: Theme exceto manage_permissions
INSERT INTO role_permissions (role_id, permission_id)
SELECT 'a0000000-0000-0000-0000-000000000002', id FROM permissions
WHERE resource = 'theme' AND action != 'manage_permissions'
ON CONFLICT DO NOTHING;

-- USER: Theme read e update
INSERT INTO role_permissions (role_id, permission_id)
SELECT 'a0000000-0000-0000-0000-000000000003', id FROM permissions
WHERE resource = 'theme' AND action IN ('read', 'update')
ON CONFLICT DO NOTHING;

-- VIEWER: Theme read
INSERT INTO role_permissions (role_id, permission_id)
SELECT 'a0000000-0000-0000-0000-000000000004', id FROM permissions
WHERE resource = 'theme' AND action = 'read'
ON CONFLICT DO NOTHING;

-- ============================================
-- ROLE PERMISSIONS - Dashboard
-- ============================================

-- ROOT: Todas as permissões de dashboard
INSERT INTO role_permissions (role_id, permission_id)
SELECT 'a0000000-0000-0000-0000-000000000001', id FROM permissions
WHERE resource = 'dashboard'
ON CONFLICT DO NOTHING;

-- ADMIN: Todas as permissões de dashboard
INSERT INTO role_permissions (role_id, permission_id)
SELECT 'a0000000-0000-0000-0000-000000000002', id FROM permissions
WHERE resource = 'dashboard'
ON CONFLICT DO NOTHING;

-- USER: Dashboard read
INSERT INTO role_permissions (role_id, permission_id)
SELECT 'a0000000-0000-0000-0000-000000000003', id FROM permissions
WHERE resource = 'dashboard' AND action = 'read'
ON CONFLICT DO NOTHING;

-- VIEWER: Dashboard read
INSERT INTO role_permissions (role_id, permission_id)
SELECT 'a0000000-0000-0000-0000-000000000004', id FROM permissions
WHERE resource = 'dashboard' AND action = 'read'
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
