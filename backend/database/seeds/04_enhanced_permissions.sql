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
-- ENHANCED PERMISSIONS SEED DATA
-- ============================================
-- Este arquivo adiciona permissões granulares avançadas para:
-- - Gerenciamento de usuários com nível máximo de role
-- - Controle de sessão e refresh token por role
-- - Políticas de senha por role
-- - Permissões de auditoria
-- - Permissões de branding/aparência
-- Execute após 01_roles_permissions.sql

-- ============================================
-- ADDITIONAL PERMISSIONS - Usuários (Granular)
-- ============================================
INSERT INTO permissions (id, resource, action, display_name, description, category) VALUES
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
-- ADDITIONAL PERMISSIONS - Segurança
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
-- ADDITIONAL PERMISSIONS - Sistema/Configurações
-- ============================================
INSERT INTO permissions (id, resource, action, display_name, description, category) VALUES
('b0000000-0000-0000-0000-000000000121', 'settings', 'manage_labels', 'Gerenciar Rótulos', 'Permite personalizar rótulos/labels do sistema', 'Sistema'),
('b0000000-0000-0000-0000-000000000122', 'settings', 'manage_uploads', 'Gerenciar Uploads', 'Permite fazer upload de arquivos (logos, etc)', 'Sistema'),
('b0000000-0000-0000-0000-000000000123', 'settings', 'view_system_info', 'Ver Informações do Sistema', 'Permite visualizar versão, status, estatísticas', 'Sistema'),
('b0000000-0000-0000-0000-000000000124', 'roles', 'manage_permissions', 'Gerenciar Permissões de Roles', 'Permite atribuir/remover permissões de roles', 'Sistema'),
('b0000000-0000-0000-0000-000000000125', 'roles', 'manage_custom', 'Gerenciar Roles Personalizados', 'Permite criar/editar/deletar roles customizados', 'Sistema')
ON CONFLICT (resource, action) DO UPDATE SET
    display_name = EXCLUDED.display_name,
    description = EXCLUDED.description,
    category = EXCLUDED.category;

-- ============================================
-- ADDITIONAL PERMISSIONS - Auditoria
-- ============================================
INSERT INTO permissions (id, resource, action, display_name, description, category) VALUES
('b0000000-0000-0000-0000-000000000131', 'audit_logs', 'read_all', 'Ver Todos os Logs', 'Permite visualizar logs de auditoria de todo o sistema', 'Auditoria'),
('b0000000-0000-0000-0000-000000000132', 'audit_logs', 'read_own', 'Ver Logs Próprios', 'Permite visualizar apenas logs das próprias ações', 'Auditoria'),
('b0000000-0000-0000-0000-000000000133', 'audit_logs', 'delete', 'Deletar Logs', 'Permite remover logs de auditoria (uso crítico)', 'Auditoria'),
('b0000000-0000-0000-0000-000000000134', 'audit_logs', 'configure', 'Configurar Auditoria', 'Permite configurar retenção e tipos de log', 'Auditoria')
ON CONFLICT (resource, action) DO UPDATE SET
    display_name = EXCLUDED.display_name,
    description = EXCLUDED.description,
    category = EXCLUDED.category;

-- ============================================
-- UPDATE ROLE PERMISSIONS - ROOT (adicionar novas)
-- ============================================
-- Root sempre tem todas as permissões
INSERT INTO role_permissions (role_id, permission_id)
SELECT 'a0000000-0000-0000-0000-000000000001', id FROM permissions
WHERE id LIKE 'b0000000-0000-0000-0000-00000001%'
ON CONFLICT DO NOTHING;

-- ============================================
-- UPDATE ROLE PERMISSIONS - ADMIN
-- ============================================
-- Admin pode gerenciar usuários (exceto criar admins e gerenciar roles de usuários)
-- Admin pode ver logs de auditoria mas não deletar
-- Admin pode gerenciar sessões e resetar senhas
INSERT INTO role_permissions (role_id, permission_id)
SELECT 'a0000000-0000-0000-0000-000000000002', id FROM permissions
WHERE
    -- Pode criar users, viewers e custom (mas não admins)
    (resource = 'users' AND action IN ('create_user', 'create_viewer', 'create_custom', 'manage_sessions', 'reset_password', 'view_activity'))
    -- Pode ver logs de segurança mas não gerenciar políticas
    OR (resource = 'security' AND action IN ('view_security_logs'))
    -- Pode gerenciar labels e uploads
    OR (resource = 'settings' AND action IN ('manage_labels', 'manage_uploads', 'view_system_info'))
    -- Pode ver logs de auditoria mas não deletar
    OR (resource = 'audit_logs' AND action IN ('read_all', 'export'))
ON CONFLICT DO NOTHING;

-- ============================================
-- UPDATE ROLE PERMISSIONS - USER
-- ============================================
-- User pode apenas ver seus próprios logs
INSERT INTO role_permissions (role_id, permission_id)
SELECT 'a0000000-0000-0000-0000-000000000003', id FROM permissions
WHERE
    -- Pode ver apenas seus próprios logs de auditoria
    (resource = 'audit_logs' AND action = 'read_own')
ON CONFLICT DO NOTHING;

-- ============================================
-- UPDATE ROLE PERMISSIONS - VIEWER
-- ============================================
-- Viewer não recebe permissões adicionais (apenas leitura básica)

-- ============================================
-- ROLE SESSION/TOKEN POLICIES
-- ============================================
-- Tabela para políticas de sessão por role
CREATE TABLE IF NOT EXISTS role_session_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    session_duration_minutes INT NOT NULL DEFAULT 60,
    refresh_token_duration_minutes INT NOT NULL DEFAULT 10080,
    max_concurrent_sessions INT DEFAULT NULL, -- NULL = ilimitado
    idle_timeout_minutes INT DEFAULT NULL, -- NULL = sem timeout de inatividade
    require_2fa BOOLEAN DEFAULT FALSE,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(role_id, is_active)
);

CREATE INDEX IF NOT EXISTS idx_role_session_policies_role ON role_session_policies(role_id);
CREATE INDEX IF NOT EXISTS idx_role_session_policies_active ON role_session_policies(is_active);

-- ============================================
-- DEFAULT SESSION POLICIES POR ROLE
-- ============================================

-- ROOT: Sessão de 8 horas, refresh token de 30 dias, sem limites
INSERT INTO role_session_policies (
    role_id,
    session_duration_minutes,
    refresh_token_duration_minutes,
    max_concurrent_sessions,
    idle_timeout_minutes,
    require_2fa
) VALUES (
    'a0000000-0000-0000-0000-000000000001', -- root
    480,  -- 8 horas
    43200, -- 30 dias
    NULL, -- sem limite
    NULL, -- sem timeout
    FALSE
) ON CONFLICT (role_id, is_active) DO UPDATE SET
    session_duration_minutes = EXCLUDED.session_duration_minutes,
    refresh_token_duration_minutes = EXCLUDED.refresh_token_duration_minutes,
    max_concurrent_sessions = EXCLUDED.max_concurrent_sessions,
    idle_timeout_minutes = EXCLUDED.idle_timeout_minutes,
    require_2fa = EXCLUDED.require_2fa,
    updated_at = CURRENT_TIMESTAMP;

-- ADMIN: Sessão de 4 horas, refresh token de 7 dias, máx 3 sessões
INSERT INTO role_session_policies (
    role_id,
    session_duration_minutes,
    refresh_token_duration_minutes,
    max_concurrent_sessions,
    idle_timeout_minutes,
    require_2fa
) VALUES (
    'a0000000-0000-0000-0000-000000000002', -- admin
    240,  -- 4 horas
    10080, -- 7 dias
    3,    -- máximo 3 sessões simultâneas
    120,  -- 2 horas de inatividade
    FALSE
) ON CONFLICT (role_id, is_active) DO UPDATE SET
    session_duration_minutes = EXCLUDED.session_duration_minutes,
    refresh_token_duration_minutes = EXCLUDED.refresh_token_duration_minutes,
    max_concurrent_sessions = EXCLUDED.max_concurrent_sessions,
    idle_timeout_minutes = EXCLUDED.idle_timeout_minutes,
    require_2fa = EXCLUDED.require_2fa,
    updated_at = CURRENT_TIMESTAMP;

-- USER: Sessão de 1 hora, refresh token de 1 dia, máx 2 sessões
INSERT INTO role_session_policies (
    role_id,
    session_duration_minutes,
    refresh_token_duration_minutes,
    max_concurrent_sessions,
    idle_timeout_minutes,
    require_2fa
) VALUES (
    'a0000000-0000-0000-0000-000000000003', -- user
    60,   -- 1 hora
    1440, -- 1 dia
    2,    -- máximo 2 sessões simultâneas
    60,   -- 1 hora de inatividade
    FALSE
) ON CONFLICT (role_id, is_active) DO UPDATE SET
    session_duration_minutes = EXCLUDED.session_duration_minutes,
    refresh_token_duration_minutes = EXCLUDED.refresh_token_duration_minutes,
    max_concurrent_sessions = EXCLUDED.max_concurrent_sessions,
    idle_timeout_minutes = EXCLUDED.idle_timeout_minutes,
    require_2fa = EXCLUDED.require_2fa,
    updated_at = CURRENT_TIMESTAMP;

-- VIEWER: Sessão de 30 minutos, refresh token de 12 horas, máx 1 sessão
INSERT INTO role_session_policies (
    role_id,
    session_duration_minutes,
    refresh_token_duration_minutes,
    max_concurrent_sessions,
    idle_timeout_minutes,
    require_2fa
) VALUES (
    'a0000000-0000-0000-0000-000000000004', -- viewer
    30,   -- 30 minutos
    720,  -- 12 horas
    1,    -- máximo 1 sessão
    30,   -- 30 minutos de inatividade
    FALSE
) ON CONFLICT (role_id, is_active) DO UPDATE SET
    session_duration_minutes = EXCLUDED.session_duration_minutes,
    refresh_token_duration_minutes = EXCLUDED.refresh_token_duration_minutes,
    max_concurrent_sessions = EXCLUDED.max_concurrent_sessions,
    idle_timeout_minutes = EXCLUDED.idle_timeout_minutes,
    require_2fa = EXCLUDED.require_2fa,
    updated_at = CURRENT_TIMESTAMP;

-- ============================================
-- COMENTÁRIOS E DOCUMENTAÇÃO
-- ============================================
--
-- POLÍTICAS DE SESSÃO POR ROLE:
-- - session_duration_minutes: Duração do token JWT principal
-- - refresh_token_duration_minutes: Duração do refresh token
-- - max_concurrent_sessions: Número máximo de sessões simultâneas (NULL = ilimitado)
-- - idle_timeout_minutes: Tempo de inatividade antes de expirar sessão (NULL = sem timeout)
-- - require_2fa: Se true, força autenticação de dois fatores
--
-- PERMISSÕES GRANULARES DE CRIAÇÃO DE USUÁRIOS:
-- - users:create_admin: Apenas ROOT pode criar admins
-- - users:create_user: Admin+ pode criar usuários padrão
-- - users:create_viewer: Admin+ pode criar visualizadores
-- - users:create_custom: Admin+ pode criar usuários com roles customizados
-- - users:manage_roles: Apenas ROOT pode alterar roles de usuários existentes
--
-- HIERARQUIA DE NÍVEIS:
-- - ROOT (100): Acesso total, pode criar qualquer tipo de usuário
-- - ADMIN (50): Pode criar user/viewer/custom, gerenciar maioria das configs
-- - USER (10): Operações do dia-a-dia, sem gestão administrativa
-- - VIEWER (1): Apenas visualização
--
-- Para criar roles personalizados:
-- 1. Defina prioridade entre 11-49 para roles operacionais
-- 2. Atribua permissões específicas via UI ou SQL
-- 3. Configure política de sessão personalizada se necessário
-- 4. Configure política de senha personalizada (tabela role_password_policies)
