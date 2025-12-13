/*
 * Entity Hub Open Project
 * Copyright (C) 2025 Entity Hub Contributors
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

-- schema.sql adaptado para PostgreSQL com case-insensitive collation
--
-- ATENÇÃO: Este arquivo contém APENAS a estrutura do banco (DDL).
-- Os dados iniciais (roles, permissions, settings) estão em arquivos separados:
--   - seeds/01_roles_permissions.sql
--   - seeds/02_system_settings.sql
--   - seeds/03_role_password_policies.sql
--
-- Para aplicar mudanças em um banco existente:
-- 1. Execute este schema.sql
-- 2. Execute os arquivos de seeds em ordem numérica
--
-- Para criar do zero:
-- DROP DATABASE entity_hub;
-- CREATE DATABASE entity_hub;
-- E então execute este script seguido dos seeds.

-- Extensão para case-insensitive (se necessário)
CREATE EXTENSION IF NOT EXISTS citext;

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
-- ROLES AND PERMISSIONS SYSTEM
-- ============================================

-- Tabela de Roles personalizáveis
CREATE TABLE IF NOT EXISTS roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name CITEXT UNIQUE NOT NULL,           -- 'root', 'admin', 'user', 'viewer', etc.
    display_name VARCHAR(255) NOT NULL,     -- 'Administrador', 'Usuário', etc.
    description TEXT,
    is_system BOOLEAN DEFAULT FALSE,        -- roles de sistema não podem ser deletados
    is_active BOOLEAN DEFAULT TRUE,         -- permite desativar roles sem deletar
    priority INTEGER NOT NULL DEFAULT 0,    -- maior = mais privilegiado (root=100, admin=50, user=10, viewer=1)
    created_by_user_id UUID,                -- NULL para roles de sistema, UUID para personalizados
    is_single_user BOOLEAN DEFAULT FALSE,   -- TRUE para roles únicos criados para um usuário específico
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Tabela de Permissões disponíveis
CREATE TABLE IF NOT EXISTS permissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    resource VARCHAR(100) NOT NULL,         -- 'entities', 'users', 'settings', etc.
    action VARCHAR(50) NOT NULL,            -- 'create', 'read', 'update', 'delete', 'archive', 'export', 'manage'
    display_name VARCHAR(255) NOT NULL,     -- 'Criar Entidades', 'Visualizar Usuários', etc.
    description TEXT,
    category VARCHAR(100) DEFAULT 'general', -- para agrupar na UI
    UNIQUE(resource, action)
);

-- Associação Role ↔ Permission
CREATE TABLE IF NOT EXISTS role_permissions (
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id UUID NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (role_id, permission_id)
);

-- Índices para performance
CREATE INDEX IF NOT EXISTS idx_roles_name ON roles(name);
CREATE INDEX IF NOT EXISTS idx_roles_priority ON roles(priority DESC);
CREATE INDEX IF NOT EXISTS idx_roles_is_system ON roles(is_system);
CREATE INDEX IF NOT EXISTS idx_roles_is_single_user ON roles(is_single_user) WHERE is_single_user = TRUE;
CREATE INDEX IF NOT EXISTS idx_permissions_resource ON permissions(resource);
CREATE INDEX IF NOT EXISTS idx_permissions_action ON permissions(action);
CREATE INDEX IF NOT EXISTS idx_role_permissions_role ON role_permissions(role_id);
CREATE INDEX IF NOT EXISTS idx_role_permissions_permission ON role_permissions(permission_id);

-- ============================================
-- ROLE PASSWORD POLICIES
-- ============================================
-- Políticas de senha específicas por role
-- Roles sem política usam configurações globais de system_settings

CREATE TABLE IF NOT EXISTS role_password_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,

    -- Política de senha
    min_length INTEGER NOT NULL DEFAULT 16,
    max_length INTEGER NOT NULL DEFAULT 128,
    require_uppercase BOOLEAN NOT NULL DEFAULT TRUE,
    require_lowercase BOOLEAN NOT NULL DEFAULT TRUE,
    require_numbers BOOLEAN NOT NULL DEFAULT TRUE,
    require_special BOOLEAN NOT NULL DEFAULT TRUE,

    -- Caracteres especiais permitidos (vazio = todos)
    allowed_special_chars VARCHAR(100) DEFAULT '!@#$%^&*()_+-=[]{}|;:,.<>?',

    -- Expiração e histórico
    max_age_days INTEGER NOT NULL DEFAULT 0,           -- 0 = nunca expira
    history_count INTEGER NOT NULL DEFAULT 0,          -- 0 = não verifica histórico
    min_age_hours INTEGER NOT NULL DEFAULT 0,          -- 0 = pode trocar imediatamente

    -- Complexidade adicional
    min_unique_chars INTEGER NOT NULL DEFAULT 0,       -- 0 = sem requisito
    no_username_in_password BOOLEAN NOT NULL DEFAULT TRUE,
    no_common_passwords BOOLEAN NOT NULL DEFAULT TRUE,

    -- Metadados
    description TEXT,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    -- Um role só pode ter uma política
    UNIQUE(role_id)
);

CREATE INDEX IF NOT EXISTS idx_role_password_policies_role ON role_password_policies(role_id);
CREATE INDEX IF NOT EXISTS idx_role_password_policies_active ON role_password_policies(is_active) WHERE is_active = TRUE;

-- ============================================
-- PASSWORD HISTORY (para verificação de reutilização)
-- ============================================
CREATE TABLE IF NOT EXISTS password_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_password_history_user ON password_history(user_id);
CREATE INDEX IF NOT EXISTS idx_password_history_created ON password_history(user_id, created_at DESC);

-- ============================================
-- USERS (atualizado para usar role_id)
-- ============================================
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY,
    username CITEXT UNIQUE,
    display_name VARCHAR(255),
    password_hash VARCHAR(255),
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP,
    -- Mantém role como string para compatibilidade, mas adiciona role_id
    role VARCHAR(50),                       -- 'root', 'admin', 'user', 'viewer' (legacy, para compatibilidade)
    role_id UUID REFERENCES roles(id) ON DELETE SET NULL,  -- Nova FK para roles
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    lock_level INTEGER NOT NULL DEFAULT 0,
    locked_until TIMESTAMP,
    auth_secret VARCHAR(64),
    -- Novos campos para segurança
    last_login_at TIMESTAMP,
    last_login_ip VARCHAR(45),
    password_changed_at TIMESTAMP,
    must_change_password BOOLEAN DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_users_role_id ON users(role_id);
CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);
CREATE INDEX IF NOT EXISTS idx_users_deleted ON users(deleted_at) WHERE deleted_at IS NULL;

-- Adicionar FK de password_history para users (após criação de users)
ALTER TABLE password_history
    DROP CONSTRAINT IF EXISTS fk_password_history_user;
ALTER TABLE password_history
    ADD CONSTRAINT fk_password_history_user
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;

-- ============================================
-- ENTITIES
-- ============================================
CREATE TABLE IF NOT EXISTS entities (
    id UUID PRIMARY KEY,
    name CITEXT NOT NULL,
    registration_id CITEXT,
    nickname CITEXT,
    birth_date DATE,
    email CITEXT,
    phone VARCHAR(50),
    address TEXT,
    notes TEXT,
    status VARCHAR(50) NOT NULL DEFAULT 'ativo',
    tags TEXT,
    contact_preference VARCHAR(50),
    last_contact_date TIMESTAMP,
    next_action_date TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    documents TEXT,
    archived_at TIMESTAMP,
    CONSTRAINT unique_registration_id_when_not_null UNIQUE (registration_id)
);

CREATE UNIQUE INDEX unique_name_when_no_registration ON entities(name) WHERE registration_id IS NULL;

-- ============================================
-- SUB-ENTITIES
-- ============================================
CREATE TABLE IF NOT EXISTS sub_entities (
    id UUID PRIMARY KEY,
    name CITEXT NOT NULL,
    entity_id UUID NOT NULL,
    description TEXT,
    birth_date DATE,
    email CITEXT,
    phone VARCHAR(50),
    address TEXT,
    notes TEXT,
    status VARCHAR(50) NOT NULL DEFAULT 'ativo',
    tags TEXT,
    contact_preference VARCHAR(50),
    documents TEXT,
    FOREIGN KEY (entity_id) REFERENCES entities(id) ON DELETE CASCADE,
    CONSTRAINT unique_sub_entity_name_per_entity UNIQUE (entity_id, name)
);

-- ============================================
-- CATEGORIES
-- ============================================
CREATE TABLE IF NOT EXISTS categories (
    id UUID PRIMARY KEY,
    name CITEXT UNIQUE NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'ativo',
    archived_at TIMESTAMP
);

-- ============================================
-- SUBCATEGORIES
-- ============================================
CREATE TABLE IF NOT EXISTS subcategories (
    id UUID PRIMARY KEY,
    name CITEXT NOT NULL,
    category_id UUID NOT NULL,
    deleted_at TIMESTAMP,
    archived_at TIMESTAMP,
    FOREIGN KEY (category_id) REFERENCES categories(id) ON DELETE CASCADE,
    CONSTRAINT unique_subcategory_name_per_category UNIQUE (category_id, name)
);

-- ============================================
-- AGREEMENTS
-- ============================================
CREATE TABLE IF NOT EXISTS agreements (
    id UUID PRIMARY KEY,
    model CITEXT,
    item_key CITEXT UNIQUE,
    start_date TIMESTAMP,
    end_date TIMESTAMP,
    subcategory_id UUID NOT NULL,
    entity_id UUID NOT NULL,
    sub_entity_id UUID,
    archived_at TIMESTAMP,
    FOREIGN KEY (subcategory_id) REFERENCES subcategories(id),
    FOREIGN KEY (entity_id) REFERENCES entities(id) ON DELETE CASCADE,
    FOREIGN KEY (sub_entity_id) REFERENCES sub_entities(id) ON DELETE SET NULL
);

-- ============================================
-- AUDIT LOGS
-- ============================================
CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY,
    timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    operation VARCHAR(50) NOT NULL,
    entity VARCHAR(50) NOT NULL,
    entity_id VARCHAR(255) NOT NULL,
    admin_id UUID,
    admin_username CITEXT,
    old_value TEXT,
    new_value TEXT,
    status VARCHAR(20) NOT NULL DEFAULT 'success',
    error_message TEXT,
    ip_address VARCHAR(45),
    user_agent TEXT,
    request_method VARCHAR(10),
    request_path VARCHAR(512),
    request_id VARCHAR(100),
    response_code INTEGER,
    execution_time_ms INTEGER,
    FOREIGN KEY (admin_id) REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_entity ON audit_logs(entity, entity_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_admin_id ON audit_logs(admin_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_operation ON audit_logs(operation);
CREATE INDEX IF NOT EXISTS idx_audit_logs_request_id ON audit_logs(request_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_status ON audit_logs(status);
CREATE INDEX IF NOT EXISTS idx_audit_logs_ip ON audit_logs(ip_address);

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

    -- Timestamps
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    -- Foreign key constraint
    CONSTRAINT fk_user_theme_settings_user FOREIGN KEY (user_id)
        REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_user_theme_settings_user_id ON user_theme_settings(user_id);

-- ============================================
-- IP-BASED BRUTE FORCE PROTECTION
-- ============================================
CREATE TABLE IF NOT EXISTS login_attempts (
    ip_address VARCHAR(45) PRIMARY KEY,
    failed_attempts INTEGER DEFAULT 0,
    lock_level INTEGER DEFAULT 0,
    locked_until TIMESTAMP,
    last_attempt_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_login_attempts_locked ON login_attempts(locked_until) WHERE locked_until IS NOT NULL;

-- ============================================
-- INSTRUÇÕES DE USO
-- ============================================
--
-- Após executar este schema, execute os seeds em ordem:
--
-- 1. seeds/01_roles_permissions.sql
--    - Cria roles padrão (root, admin, user, viewer, financeiro)
--    - Cria todas as permissões do sistema
--    - Mapeia permissões para cada role
--
-- 2. seeds/02_system_settings.sql
--    - Configurações de segurança (bloqueio, sessão, rate limiting)
--    - Configurações de dashboard
--    - Configurações de notificações
--    - Configurações de auditoria
--
-- 3. seeds/03_role_password_policies.sql
--    - Políticas de senha específicas por role
--    - Root: mais rigorosa (24 chars, expira 90 dias)
--    - Admin: rigorosa (16 chars, expira 180 dias)
--    - User: moderada (12 chars, expira anualmente)
--    - Viewer: básica (8 chars, não expira)
--
-- Para desenvolvimento/testes:
--   psql -d entity_hub -f schema.sql
--   psql -d entity_hub -f seeds/01_roles_permissions.sql
--   psql -d entity_hub -f seeds/02_system_settings.sql
--   psql -d entity_hub -f seeds/03_role_password_policies.sql
--
-- Ou em um único comando:
--   cat schema.sql seeds/*.sql | psql -d entity_hub
