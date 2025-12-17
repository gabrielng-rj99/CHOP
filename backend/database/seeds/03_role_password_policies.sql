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

-- ============================================
-- ROLE PASSWORD POLICIES SEED DATA
-- ============================================
-- Este arquivo define políticas de senha específicas para cada role.
-- Roles sem política definida usarão as configurações globais de system_settings.
--
-- A ideia é permitir requisitos mais rigorosos para roles privilegiados
-- e requisitos mais leves para roles com menos acesso.
--
-- Execute após schema.sql e 01_roles_permissions.sql

-- ============================================
-- TABELA DE POLÍTICAS DE SENHA POR ROLE
-- ============================================
-- Nota: Esta tabela precisa ser criada no schema.sql
-- Adicionando aqui como CREATE IF NOT EXISTS para garantir existência

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
-- POLÍTICA: ROOT (Super Administrador)
-- ============================================
-- Política mais rigorosa do sistema
-- Senha longa, complexa, com expiração e histórico

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
    'a0000000-0000-0000-0000-000000000001',  -- root
    24,      -- min_length: 24 caracteres mínimo
    128,     -- max_length: 128 caracteres máximo
    TRUE,    -- require_uppercase
    TRUE,    -- require_lowercase
    TRUE,    -- require_numbers
    TRUE,    -- require_special
    90,      -- max_age_days: expira a cada 90 dias
    5,       -- history_count: não pode repetir últimas 5 senhas
    24,      -- min_age_hours: só pode trocar após 24h
    12,      -- min_unique_chars: pelo menos 12 caracteres diferentes
    TRUE,    -- no_username_in_password
    TRUE,    -- no_common_passwords
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

-- ============================================
-- POLÍTICA: ADMIN (Administrador)
-- ============================================
-- Política rigorosa, mas menos que root
-- Senha média-longa, complexa, com expiração

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
    'a0000000-0000-0000-0000-000000000002',  -- admin
    16,      -- min_length: 16 caracteres mínimo
    128,     -- max_length: 128 caracteres máximo
    TRUE,    -- require_uppercase
    TRUE,    -- require_lowercase
    TRUE,    -- require_numbers
    TRUE,    -- require_special
    180,     -- max_age_days: expira a cada 180 dias (6 meses)
    3,       -- history_count: não pode repetir últimas 3 senhas
    1,       -- min_age_hours: só pode trocar após 1h
    8,       -- min_unique_chars: pelo menos 8 caracteres diferentes
    TRUE,    -- no_username_in_password
    TRUE,    -- no_common_passwords
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

-- ============================================
-- POLÍTICA: USER (Usuário Padrão)
-- ============================================
-- Política moderada
-- Senha média, com requisitos básicos de complexidade

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
    'a0000000-0000-0000-0000-000000000003',  -- user
    12,      -- min_length: 12 caracteres mínimo
    128,     -- max_length: 128 caracteres máximo
    TRUE,    -- require_uppercase
    TRUE,    -- require_lowercase
    TRUE,    -- require_numbers
    FALSE,   -- require_special: OPCIONAL para usuários comuns
    365,     -- max_age_days: expira anualmente (ou 0 para nunca)
    0,       -- history_count: sem verificação de histórico
    0,       -- min_age_hours: pode trocar a qualquer momento
    6,       -- min_unique_chars: pelo menos 6 caracteres diferentes
    TRUE,    -- no_username_in_password
    TRUE,    -- no_common_passwords
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

-- ============================================
-- POLÍTICA: VIEWER (Visualizador)
-- ============================================
-- Política mais leve (apenas leitura = menor risco)
-- Senha curta, com requisitos mínimos

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
    'a0000000-0000-0000-0000-000000000004',  -- viewer
    8,       -- min_length: 8 caracteres mínimo
    128,     -- max_length: 128 caracteres máximo
    TRUE,    -- require_uppercase
    TRUE,    -- require_lowercase
    FALSE,   -- require_numbers: OPCIONAL
    FALSE,   -- require_special: OPCIONAL
    0,       -- max_age_days: nunca expira
    0,       -- history_count: sem verificação de histórico
    0,       -- min_age_hours: pode trocar a qualquer momento
    4,       -- min_unique_chars: pelo menos 4 caracteres diferentes
    TRUE,    -- no_username_in_password
    TRUE,    -- no_common_passwords
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
-- NOTA: POLÍTICAS PARA ROLES PERSONALIZADOS
-- ============================================
-- Roles personalizados como "financeiro", "operador", "suporte" etc.
-- devem ter suas políticas de senha configuradas via interface
-- administrativa após a criação do role.
--
-- Exemplo comentado de como seria a estrutura para um role "financeiro":
--
-- INSERT INTO role_password_policies (
--     role_id,
--     min_length,
--     max_length,
--     require_uppercase,
--     require_lowercase,
--     require_numbers,
--     require_special,
--     max_age_days,
--     history_count,
--     min_age_hours,
--     min_unique_chars,
--     no_username_in_password,
--     no_common_passwords,
--     description
-- ) VALUES (
--     'role_uuid_aqui',  -- UUID do role personalizado
--     16,      -- min_length: 16 caracteres mínimo
--     128,     -- max_length: 128 caracteres máximo
--     TRUE,    -- require_uppercase
--     TRUE,    -- require_lowercase
--     TRUE,    -- require_numbers
--     TRUE,    -- require_special
--     90,      -- max_age_days: expira a cada 90 dias
--     3,       -- history_count: não pode repetir últimas 3 senhas
--     1,       -- min_age_hours: só pode trocar após 1h
--     8,       -- min_unique_chars: pelo menos 8 caracteres diferentes
--     TRUE,    -- no_username_in_password
--     TRUE,    -- no_common_passwords
--     'Descrição da política de senha.'
-- );

-- ============================================
-- DOCUMENTAÇÃO E NOTAS
-- ============================================
--
-- Para criar política para um novo role:
-- 1. Obtenha o UUID do role da tabela roles
-- 2. Copie um INSERT acima e ajuste os valores
-- 3. Execute o INSERT
--
-- Campos explicados:
-- - min_length/max_length: Limites de tamanho da senha
-- - require_*: Booleanos para exigir tipos de caracteres
-- - max_age_days: Dias até a senha expirar (0 = nunca)
-- - history_count: Quantas senhas antigas não podem ser reutilizadas
-- - min_age_hours: Horas mínimas entre trocas de senha (previne abuse)
-- - min_unique_chars: Mínimo de caracteres únicos (evita "aaaaaaaa")
-- - no_username_in_password: Bloqueia senhas contendo o username
-- - no_common_passwords: Verifica contra lista de senhas comuns
--
-- Para roles personalizados (criados via UI):
-- Se não tiver política específica, usará as configurações globais
-- de system_settings (security.password_*).
--
-- Prioridade de aplicação:
-- 1. Política específica do role (role_password_policies)
-- 2. Configurações globais (system_settings.security.password_*)
-- 3. Defaults hardcoded no backend (fallback final)
