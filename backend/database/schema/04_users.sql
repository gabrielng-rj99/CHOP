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
-- USERS MODULE
-- ============================================
-- Este arquivo contém tabelas relacionadas a usuários:
-- - users: Usuários do sistema
-- - user_theme_settings: Preferências de tema por usuário
--
-- Deve ser executado após 03_security.sql

-- ============================================
-- USERS
-- ============================================
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY,
    username CITEXT UNIQUE,
    display_name VARCHAR(255),
    password_hash VARCHAR(255),
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP,

    -- Role (legacy string + new FK)
    role VARCHAR(50),
    role_id UUID REFERENCES roles(id) ON DELETE SET NULL,

    -- Security: login attempts and locks
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    lock_level INTEGER NOT NULL DEFAULT 0,
    locked_until TIMESTAMP,
    auth_secret VARCHAR(64),

    -- Security: tracking
    last_login_at TIMESTAMP,
    last_login_ip VARCHAR(45),
    password_changed_at TIMESTAMP,
    must_change_password BOOLEAN DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_users_role_id ON users(role_id);
CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);
CREATE INDEX IF NOT EXISTS idx_users_deleted ON users(deleted_at) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);

-- ============================================
-- FK: password_history -> users
-- ============================================
-- A tabela password_history foi criada em 03_security.sql
-- Agora que users existe, adicionamos a FK

ALTER TABLE password_history
    DROP CONSTRAINT IF EXISTS fk_password_history_user;
ALTER TABLE password_history
    ADD CONSTRAINT fk_password_history_user
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;

-- ============================================
-- USER THEME SETTINGS
-- ============================================
CREATE TABLE IF NOT EXISTS user_theme_settings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL UNIQUE,

    -- Theme preset (name of predefined theme or 'custom')
    theme_preset VARCHAR(100) NOT NULL DEFAULT 'default',

    -- Theme mode preference
    theme_mode VARCHAR(20) NOT NULL DEFAULT 'system' CHECK (theme_mode IN ('light', 'dark', 'system')),

    -- Layout mode preference
    layout_mode VARCHAR(20) NOT NULL DEFAULT 'standard' CHECK (layout_mode IN ('centralized', 'standard', 'full', 'compact', 'spacious', 'comfortable', 'wide')),

    -- Custom colors (only used when theme_preset = 'custom')
    -- All colors must be valid hex format (#RGB or #RRGGBB)
    primary_color VARCHAR(7) CHECK (primary_color IS NULL OR primary_color ~ '^#([0-9A-Fa-f]{3}|[0-9A-Fa-f]{6})$'),
    secondary_color VARCHAR(7) CHECK (secondary_color IS NULL OR secondary_color ~ '^#([0-9A-Fa-f]{3}|[0-9A-Fa-f]{6})$'),
    background_color VARCHAR(7) CHECK (background_color IS NULL OR background_color ~ '^#([0-9A-Fa-f]{3}|[0-9A-Fa-f]{6})$'),
    surface_color VARCHAR(7) CHECK (surface_color IS NULL OR surface_color ~ '^#([0-9A-Fa-f]{3}|[0-9A-Fa-f]{6})$'),
    text_color VARCHAR(7) CHECK (text_color IS NULL OR text_color ~ '^#([0-9A-Fa-f]{3}|[0-9A-Fa-f]{6})$'),
    text_secondary_color VARCHAR(7) CHECK (text_secondary_color IS NULL OR text_secondary_color ~ '^#([0-9A-Fa-f]{3}|[0-9A-Fa-f]{6})$'),
    border_color VARCHAR(7) CHECK (border_color IS NULL OR border_color ~ '^#([0-9A-Fa-f]{3}|[0-9A-Fa-f]{6})$'),

    -- Accessibility settings
    high_contrast BOOLEAN NOT NULL DEFAULT FALSE,
    color_blind_mode VARCHAR(20) NOT NULL DEFAULT 'none' CHECK (color_blind_mode IN ('none', 'protanopia', 'deuteranopia', 'tritanopia')),
    dyslexic_font BOOLEAN NOT NULL DEFAULT FALSE,

    -- Font settings
    font_general VARCHAR(100) DEFAULT 'System',
    font_title VARCHAR(100) DEFAULT 'System',
    font_table_title VARCHAR(100) DEFAULT 'System',

    -- Timestamps
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    -- Foreign key constraint
    CONSTRAINT fk_user_theme_settings_user FOREIGN KEY (user_id)
        REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_user_theme_settings_user_id ON user_theme_settings(user_id);

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
-- ROLE PERMISSIONS - Users
-- ============================================

-- ROOT: Todas as permissões de users
INSERT INTO role_permissions (role_id, permission_id)
SELECT 'a0000000-0000-0000-0000-000000000001', id FROM permissions
WHERE resource = 'users'
ON CONFLICT DO NOTHING;

-- ADMIN: Users exceto manage_roles e create_admin
INSERT INTO role_permissions (role_id, permission_id)
SELECT 'a0000000-0000-0000-0000-000000000002', id FROM permissions
WHERE resource = 'users' AND action NOT IN ('manage_roles', 'create_admin')
ON CONFLICT DO NOTHING;
