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
-- SECURITY MODULE
-- ============================================
-- Este arquivo contém tabelas e dados de segurança:
-- - role_password_policies: Políticas de senha por role
-- - role_session_policies: Políticas de sessão por role
-- - password_history: Histórico de senhas (para evitar reutilização)
-- - login_attempts: Proteção contra brute force por IP
-- - system_settings de segurança
--
-- Deve ser executado após 02_core.sql

-- ============================================
-- ROLE PASSWORD POLICIES
-- ============================================
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
    max_age_days INTEGER NOT NULL DEFAULT 0,
    history_count INTEGER NOT NULL DEFAULT 0,
    min_age_hours INTEGER NOT NULL DEFAULT 0,

    -- Complexidade adicional
    min_unique_chars INTEGER NOT NULL DEFAULT 0,
    no_username_in_password BOOLEAN NOT NULL DEFAULT TRUE,
    no_common_passwords BOOLEAN NOT NULL DEFAULT TRUE,

    -- Metadados
    description TEXT,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    UNIQUE(role_id)
);

CREATE INDEX IF NOT EXISTS idx_role_password_policies_role ON role_password_policies(role_id);
CREATE INDEX IF NOT EXISTS idx_role_password_policies_active ON role_password_policies(is_active) WHERE is_active = TRUE;

-- ============================================
-- ROLE SESSION POLICIES
-- ============================================
CREATE TABLE IF NOT EXISTS role_session_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    session_duration_minutes INT NOT NULL DEFAULT 60,
    refresh_token_duration_minutes INT NOT NULL DEFAULT 10080,
    max_concurrent_sessions INT DEFAULT NULL,
    idle_timeout_minutes INT DEFAULT NULL,
    require_2fa BOOLEAN DEFAULT FALSE,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(role_id, is_active)
);

CREATE INDEX IF NOT EXISTS idx_role_session_policies_role ON role_session_policies(role_id);
CREATE INDEX IF NOT EXISTS idx_role_session_policies_active ON role_session_policies(is_active);

-- ============================================
-- PASSWORD HISTORY
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
-- PASSWORD POLICIES - Data
-- ============================================

-- ROOT: Política mais rigorosa
INSERT INTO role_password_policies (
    role_id,
    min_length,
    max_length,
    require_uppercase,
    require_lowercase,
    require_numbers,
    require_special,
    max_age_days,
    history_count,
    min_age_hours,
    min_unique_chars,
    no_username_in_password,
    no_common_passwords,
    description
) VALUES (
    'a0000000-0000-0000-0000-000000000001',
    24,
    128,
    TRUE,
    TRUE,
    TRUE,
    TRUE,
    90,
    5,
    24,
    12,
    TRUE,
    TRUE,
    'Política de senha para Super Administradores (root). Máxima segurança requerida.'
) ON CONFLICT (role_id) DO UPDATE SET
    min_length = EXCLUDED.min_length,
    max_length = EXCLUDED.max_length,
    require_uppercase = EXCLUDED.require_uppercase,
    require_lowercase = EXCLUDED.require_lowercase,
    require_numbers = EXCLUDED.require_numbers,
    require_special = EXCLUDED.require_special,
    max_age_days = EXCLUDED.max_age_days,
    history_count = EXCLUDED.history_count,
    min_age_hours = EXCLUDED.min_age_hours,
    min_unique_chars = EXCLUDED.min_unique_chars,
    no_username_in_password = EXCLUDED.no_username_in_password,
    no_common_passwords = EXCLUDED.no_common_passwords,
    description = EXCLUDED.description,
    updated_at = CURRENT_TIMESTAMP;

-- ADMIN: Política rigorosa
INSERT INTO role_password_policies (
    role_id,
    min_length,
    max_length,
    require_uppercase,
    require_lowercase,
    require_numbers,
    require_special,
    max_age_days,
    history_count,
    min_age_hours,
    min_unique_chars,
    no_username_in_password,
    no_common_passwords,
    description
) VALUES (
    'a0000000-0000-0000-0000-000000000002',
    16,
    128,
    TRUE,
    TRUE,
    TRUE,
    TRUE,
    180,
    3,
    1,
    8,
    TRUE,
    TRUE,
    'Política de senha para Administradores. Alta segurança requerida.'
) ON CONFLICT (role_id) DO UPDATE SET
    min_length = EXCLUDED.min_length,
    max_length = EXCLUDED.max_length,
    require_uppercase = EXCLUDED.require_uppercase,
    require_lowercase = EXCLUDED.require_lowercase,
    require_numbers = EXCLUDED.require_numbers,
    require_special = EXCLUDED.require_special,
    max_age_days = EXCLUDED.max_age_days,
    history_count = EXCLUDED.history_count,
    min_age_hours = EXCLUDED.min_age_hours,
    min_unique_chars = EXCLUDED.min_unique_chars,
    no_username_in_password = EXCLUDED.no_username_in_password,
    no_common_passwords = EXCLUDED.no_common_passwords,
    description = EXCLUDED.description,
    updated_at = CURRENT_TIMESTAMP;

-- USER: Política moderada
INSERT INTO role_password_policies (
    role_id,
    min_length,
    max_length,
    require_uppercase,
    require_lowercase,
    require_numbers,
    require_special,
    max_age_days,
    history_count,
    min_age_hours,
    min_unique_chars,
    no_username_in_password,
    no_common_passwords,
    description
) VALUES (
    'a0000000-0000-0000-0000-000000000003',
    12,
    128,
    TRUE,
    TRUE,
    TRUE,
    FALSE,
    365,
    0,
    0,
    6,
    TRUE,
    TRUE,
    'Política de senha para Usuários padrão. Segurança moderada.'
) ON CONFLICT (role_id) DO UPDATE SET
    min_length = EXCLUDED.min_length,
    max_length = EXCLUDED.max_length,
    require_uppercase = EXCLUDED.require_uppercase,
    require_lowercase = EXCLUDED.require_lowercase,
    require_numbers = EXCLUDED.require_numbers,
    require_special = EXCLUDED.require_special,
    max_age_days = EXCLUDED.max_age_days,
    history_count = EXCLUDED.history_count,
    min_age_hours = EXCLUDED.min_age_hours,
    min_unique_chars = EXCLUDED.min_unique_chars,
    no_username_in_password = EXCLUDED.no_username_in_password,
    no_common_passwords = EXCLUDED.no_common_passwords,
    description = EXCLUDED.description,
    updated_at = CURRENT_TIMESTAMP;

-- VIEWER: Política básica
INSERT INTO role_password_policies (
    role_id,
    min_length,
    max_length,
    require_uppercase,
    require_lowercase,
    require_numbers,
    require_special,
    max_age_days,
    history_count,
    min_age_hours,
    min_unique_chars,
    no_username_in_password,
    no_common_passwords,
    description
) VALUES (
    'a0000000-0000-0000-0000-000000000004',
    8,
    128,
    TRUE,
    TRUE,
    FALSE,
    FALSE,
    0,
    0,
    0,
    4,
    TRUE,
    TRUE,
    'Política de senha para Visualizadores. Segurança básica (acesso somente leitura).'
) ON CONFLICT (role_id) DO UPDATE SET
    min_length = EXCLUDED.min_length,
    max_length = EXCLUDED.max_length,
    require_uppercase = EXCLUDED.require_uppercase,
    require_lowercase = EXCLUDED.require_lowercase,
    require_numbers = EXCLUDED.require_numbers,
    require_special = EXCLUDED.require_special,
    max_age_days = EXCLUDED.max_age_days,
    history_count = EXCLUDED.history_count,
    min_age_hours = EXCLUDED.min_age_hours,
    min_unique_chars = EXCLUDED.min_unique_chars,
    no_username_in_password = EXCLUDED.no_username_in_password,
    no_common_passwords = EXCLUDED.no_common_passwords,
    description = EXCLUDED.description,
    updated_at = CURRENT_TIMESTAMP;

-- ============================================
-- SESSION POLICIES - Data
-- ============================================

-- ROOT: Sessão de 8 horas, refresh token de 30 dias
INSERT INTO role_session_policies (
    role_id,
    session_duration_minutes,
    refresh_token_duration_minutes,
    max_concurrent_sessions,
    idle_timeout_minutes,
    require_2fa
) VALUES (
    'a0000000-0000-0000-0000-000000000001',
    480,
    43200,
    NULL,
    NULL,
    FALSE
) ON CONFLICT (role_id, is_active) DO UPDATE SET
    session_duration_minutes = EXCLUDED.session_duration_minutes,
    refresh_token_duration_minutes = EXCLUDED.refresh_token_duration_minutes,
    max_concurrent_sessions = EXCLUDED.max_concurrent_sessions,
    idle_timeout_minutes = EXCLUDED.idle_timeout_minutes,
    require_2fa = EXCLUDED.require_2fa,
    updated_at = CURRENT_TIMESTAMP;

-- ADMIN: Sessão de 4 horas, refresh token de 7 dias
INSERT INTO role_session_policies (
    role_id,
    session_duration_minutes,
    refresh_token_duration_minutes,
    max_concurrent_sessions,
    idle_timeout_minutes,
    require_2fa
) VALUES (
    'a0000000-0000-0000-0000-000000000002',
    240,
    10080,
    3,
    120,
    FALSE
) ON CONFLICT (role_id, is_active) DO UPDATE SET
    session_duration_minutes = EXCLUDED.session_duration_minutes,
    refresh_token_duration_minutes = EXCLUDED.refresh_token_duration_minutes,
    max_concurrent_sessions = EXCLUDED.max_concurrent_sessions,
    idle_timeout_minutes = EXCLUDED.idle_timeout_minutes,
    require_2fa = EXCLUDED.require_2fa,
    updated_at = CURRENT_TIMESTAMP;

-- USER: Sessão de 1 hora, refresh token de 1 dia
INSERT INTO role_session_policies (
    role_id,
    session_duration_minutes,
    refresh_token_duration_minutes,
    max_concurrent_sessions,
    idle_timeout_minutes,
    require_2fa
) VALUES (
    'a0000000-0000-0000-0000-000000000003',
    60,
    1440,
    2,
    60,
    FALSE
) ON CONFLICT (role_id, is_active) DO UPDATE SET
    session_duration_minutes = EXCLUDED.session_duration_minutes,
    refresh_token_duration_minutes = EXCLUDED.refresh_token_duration_minutes,
    max_concurrent_sessions = EXCLUDED.max_concurrent_sessions,
    idle_timeout_minutes = EXCLUDED.idle_timeout_minutes,
    require_2fa = EXCLUDED.require_2fa,
    updated_at = CURRENT_TIMESTAMP;

-- VIEWER: Sessão de 30 minutos, refresh token de 12 horas
INSERT INTO role_session_policies (
    role_id,
    session_duration_minutes,
    refresh_token_duration_minutes,
    max_concurrent_sessions,
    idle_timeout_minutes,
    require_2fa
) VALUES (
    'a0000000-0000-0000-0000-000000000004',
    30,
    720,
    1,
    30,
    FALSE
) ON CONFLICT (role_id, is_active) DO UPDATE SET
    session_duration_minutes = EXCLUDED.session_duration_minutes,
    refresh_token_duration_minutes = EXCLUDED.refresh_token_duration_minutes,
    max_concurrent_sessions = EXCLUDED.max_concurrent_sessions,
    idle_timeout_minutes = EXCLUDED.idle_timeout_minutes,
    require_2fa = EXCLUDED.require_2fa,
    updated_at = CURRENT_TIMESTAMP;

-- ============================================
-- SYSTEM SETTINGS - Security: Login Lock
-- ============================================
INSERT INTO system_settings (key, value, description, category)
VALUES ('security.lock_level_1_attempts', '3', 'Tentativas de login para ativar bloqueio nível 1', 'security')
ON CONFLICT (key) DO UPDATE SET
    description = EXCLUDED.description,
    category = EXCLUDED.category,
    updated_at = CURRENT_TIMESTAMP;

INSERT INTO system_settings (key, value, description, category)
VALUES ('security.lock_level_1_duration', '300', 'Duração do bloqueio nível 1 em segundos (5 minutos)', 'security')
ON CONFLICT (key) DO UPDATE SET
    description = EXCLUDED.description,
    category = EXCLUDED.category,
    updated_at = CURRENT_TIMESTAMP;

INSERT INTO system_settings (key, value, description, category)
VALUES ('security.lock_level_2_attempts', '5', 'Tentativas de login para ativar bloqueio nível 2', 'security')
ON CONFLICT (key) DO UPDATE SET
    description = EXCLUDED.description,
    category = EXCLUDED.category,
    updated_at = CURRENT_TIMESTAMP;

INSERT INTO system_settings (key, value, description, category)
VALUES ('security.lock_level_2_duration', '900', 'Duração do bloqueio nível 2 em segundos (15 minutos)', 'security')
ON CONFLICT (key) DO UPDATE SET
    description = EXCLUDED.description,
    category = EXCLUDED.category,
    updated_at = CURRENT_TIMESTAMP;

INSERT INTO system_settings (key, value, description, category)
VALUES ('security.lock_level_3_attempts', '10', 'Tentativas de login para ativar bloqueio nível 3', 'security')
ON CONFLICT (key) DO UPDATE SET
    description = EXCLUDED.description,
    category = EXCLUDED.category,
    updated_at = CURRENT_TIMESTAMP;

INSERT INTO system_settings (key, value, description, category)
VALUES ('security.lock_level_3_duration', '3600', 'Duração do bloqueio nível 3 em segundos (60 minutos)', 'security')
ON CONFLICT (key) DO UPDATE SET
    description = EXCLUDED.description,
    category = EXCLUDED.category,
    updated_at = CURRENT_TIMESTAMP;

INSERT INTO system_settings (key, value, description, category)
VALUES ('security.lock_level_manual_attempts', '15', 'Tentativas para bloqueio permanente (requer desbloqueio manual)', 'security')
ON CONFLICT (key) DO UPDATE SET
    description = EXCLUDED.description,
    category = EXCLUDED.category,
    updated_at = CURRENT_TIMESTAMP;

-- Legacy settings (mantidos para compatibilidade)
INSERT INTO system_settings (key, value, description, category)
VALUES ('security.login_block_time', '300', '[Legacy] Tempo de bloqueio padrão em segundos', 'security')
ON CONFLICT (key) DO UPDATE SET
    description = EXCLUDED.description,
    category = EXCLUDED.category,
    updated_at = CURRENT_TIMESTAMP;

INSERT INTO system_settings (key, value, description, category)
VALUES ('security.login_attempts', '5', '[Legacy] Tentativas antes do bloqueio', 'security')
ON CONFLICT (key) DO UPDATE SET
    description = EXCLUDED.description,
    category = EXCLUDED.category,
    updated_at = CURRENT_TIMESTAMP;

-- ============================================
-- SYSTEM SETTINGS - Security: Password (Global)
-- ============================================
INSERT INTO system_settings (key, value, description, category)
VALUES ('security.password_min_length', '8', 'Tamanho mínimo da senha (padrão global, range: 8-128)', 'security')
ON CONFLICT (key) DO UPDATE SET
    description = EXCLUDED.description,
    category = EXCLUDED.category,
    updated_at = CURRENT_TIMESTAMP;

INSERT INTO system_settings (key, value, description, category)
VALUES ('security.password_max_length', '128', 'Tamanho máximo da senha (padrão global, range: 8-256)', 'security')
ON CONFLICT (key) DO UPDATE SET
    description = EXCLUDED.description,
    category = EXCLUDED.category,
    updated_at = CURRENT_TIMESTAMP;

INSERT INTO system_settings (key, value, description, category)
VALUES ('security.password_require_uppercase', 'true', 'Exigir pelo menos uma letra maiúscula', 'security')
ON CONFLICT (key) DO UPDATE SET
    description = EXCLUDED.description,
    category = EXCLUDED.category,
    updated_at = CURRENT_TIMESTAMP;

INSERT INTO system_settings (key, value, description, category)
VALUES ('security.password_require_lowercase', 'true', 'Exigir pelo menos uma letra minúscula', 'security')
ON CONFLICT (key) DO UPDATE SET
    description = EXCLUDED.description,
    category = EXCLUDED.category,
    updated_at = CURRENT_TIMESTAMP;

INSERT INTO system_settings (key, value, description, category)
VALUES ('security.password_require_numbers', 'true', 'Exigir pelo menos um número', 'security')
ON CONFLICT (key) DO UPDATE SET
    description = EXCLUDED.description,
    category = EXCLUDED.category,
    updated_at = CURRENT_TIMESTAMP;

INSERT INTO system_settings (key, value, description, category)
VALUES ('security.password_require_special', 'true', 'Exigir pelo menos um caractere especial (!@#$%^&*...)', 'security')
ON CONFLICT (key) DO UPDATE SET
    description = EXCLUDED.description,
    category = EXCLUDED.category,
    updated_at = CURRENT_TIMESTAMP;

INSERT INTO system_settings (key, value, description, category)
VALUES ('security.password_max_age_days', '0', 'Dias para expiração da senha (0 = nunca expira)', 'security')
ON CONFLICT (key) DO UPDATE SET
    description = EXCLUDED.description,
    category = EXCLUDED.category,
    updated_at = CURRENT_TIMESTAMP;

INSERT INTO system_settings (key, value, description, category)
VALUES ('security.password_history_count', '0', 'Número de senhas anteriores que não podem ser reutilizadas (0 = desabilitado)', 'security')
ON CONFLICT (key) DO UPDATE SET
    description = EXCLUDED.description,
    category = EXCLUDED.category,
    updated_at = CURRENT_TIMESTAMP;

INSERT INTO system_settings (key, value, description, category)
VALUES ('security.password_entropy_min_bits', '90', 'Entropia mínima recomendada em bits (apenas para UI/info)', 'security')
ON CONFLICT (key) DO UPDATE SET
    description = EXCLUDED.description,
    category = EXCLUDED.category,
    updated_at = CURRENT_TIMESTAMP;

-- ============================================
-- SYSTEM SETTINGS - Security: Session/JWT
-- ============================================
INSERT INTO system_settings (key, value, description, category)
VALUES ('security.session_duration', '60', 'Duração do token de acesso em minutos', 'security')
ON CONFLICT (key) DO UPDATE SET
    description = EXCLUDED.description,
    category = EXCLUDED.category,
    updated_at = CURRENT_TIMESTAMP;

INSERT INTO system_settings (key, value, description, category)
VALUES ('security.refresh_token_duration', '10080', 'Duração do refresh token em minutos (padrão: 7 dias)', 'security')
ON CONFLICT (key) DO UPDATE SET
    description = EXCLUDED.description,
    category = EXCLUDED.category,
    updated_at = CURRENT_TIMESTAMP;

INSERT INTO system_settings (key, value, description, category)
VALUES ('security.single_session', 'false', 'Permitir apenas uma sessão ativa por usuário', 'security')
ON CONFLICT (key) DO UPDATE SET
    description = EXCLUDED.description,
    category = EXCLUDED.category,
    updated_at = CURRENT_TIMESTAMP;

-- ============================================
-- SYSTEM SETTINGS - Security: Rate Limiting
-- ============================================
INSERT INTO system_settings (key, value, description, category)
VALUES ('security.rate_limit', '5', 'Limite de requisições por segundo por IP', 'security')
ON CONFLICT (key) DO UPDATE SET
    description = EXCLUDED.description,
    category = EXCLUDED.category,
    updated_at = CURRENT_TIMESTAMP;

INSERT INTO system_settings (key, value, description, category)
VALUES ('security.rate_burst', '10', 'Burst máximo de requisições permitido', 'security')
ON CONFLICT (key) DO UPDATE SET
    description = EXCLUDED.description,
    category = EXCLUDED.category,
    updated_at = CURRENT_TIMESTAMP;
