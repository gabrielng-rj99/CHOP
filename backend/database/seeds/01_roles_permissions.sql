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
-- ROLES AND PERMISSIONS SEED DATA
-- ============================================
-- Este arquivo contém os dados iniciais para o sistema de roles e permissões.
-- Separado do schema.sql para facilitar manutenção e atualizações futuras.
--
-- Níveis de Prioridade:
--   100     = Crítico (root de sistema, não editável)
--   50-99   = Alto (administradores)
--   10-49   = Médio (operadores/usuários padrão)
--   1-9     = Baixo (visualizadores/convidados)
--
-- Execute após schema.sql

-- ============================================
-- DEFAULT ROLES
-- ============================================

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

-- NOTA: Roles personalizados como "financeiro", "operador", "suporte" etc.
-- devem ser criados via interface administrativa, não como roles de sistema.
-- Abaixo está um exemplo comentado de como seria a estrutura:
--
-- INSERT INTO roles (id, name, display_name, description, is_system, is_active, priority)
-- VALUES (
--     'a0000000-0000-0000-0000-000000000005',
--     'financeiro',
--     'Financeiro',
--     'Acesso focado em acordos e relatórios financeiros.',
--     FALSE,  -- is_system = FALSE para roles customizados
--     TRUE,
--     25
-- );

-- ============================================
-- PERMISSIONS - Entidades
-- ============================================
INSERT INTO permissions (id, resource, action, display_name, description, category) VALUES
('b0000000-0000-0000-0000-000000000001', 'entities', 'create', 'Criar Entidades', 'Permite criar novas entidades/clientes', 'Entidades'),
('b0000000-0000-0000-0000-000000000002', 'entities', 'read', 'Visualizar Entidades', 'Permite visualizar entidades/clientes', 'Entidades'),
('b0000000-0000-0000-0000-000000000003', 'entities', 'update', 'Editar Entidades', 'Permite editar entidades/clientes existentes', 'Entidades'),
('b0000000-0000-0000-0000-000000000004', 'entities', 'delete', 'Deletar Entidades', 'Permite deletar entidades/clientes permanentemente', 'Entidades'),
('b0000000-0000-0000-0000-000000000005', 'entities', 'archive', 'Arquivar Entidades', 'Permite arquivar/desarquivar entidades', 'Entidades'),
('b0000000-0000-0000-0000-000000000006', 'entities', 'export', 'Exportar Entidades', 'Permite exportar dados de entidades em diferentes formatos', 'Entidades')
ON CONFLICT (resource, action) DO UPDATE SET
    display_name = EXCLUDED.display_name,
    description = EXCLUDED.description,
    category = EXCLUDED.category;

-- ============================================
-- PERMISSIONS - Sub-entidades
-- ============================================
INSERT INTO permissions (id, resource, action, display_name, description, category) VALUES
('b0000000-0000-0000-0000-000000000011', 'sub_entities', 'create', 'Criar Sub-entidades', 'Permite criar novas sub-entidades vinculadas a entidades', 'Sub-entidades'),
('b0000000-0000-0000-0000-000000000012', 'sub_entities', 'read', 'Visualizar Sub-entidades', 'Permite visualizar sub-entidades', 'Sub-entidades'),
('b0000000-0000-0000-0000-000000000013', 'sub_entities', 'update', 'Editar Sub-entidades', 'Permite editar sub-entidades existentes', 'Sub-entidades'),
('b0000000-0000-0000-0000-000000000014', 'sub_entities', 'delete', 'Deletar Sub-entidades', 'Permite deletar sub-entidades permanentemente', 'Sub-entidades')
ON CONFLICT (resource, action) DO UPDATE SET
    display_name = EXCLUDED.display_name,
    description = EXCLUDED.description,
    category = EXCLUDED.category;

-- ============================================
-- PERMISSIONS - Acordos
-- ============================================
INSERT INTO permissions (id, resource, action, display_name, description, category) VALUES
('b0000000-0000-0000-0000-000000000021', 'agreements', 'create', 'Criar Acordos', 'Permite criar novos acordos/contratos', 'Acordos'),
('b0000000-0000-0000-0000-000000000022', 'agreements', 'read', 'Visualizar Acordos', 'Permite visualizar acordos/contratos', 'Acordos'),
('b0000000-0000-0000-0000-000000000023', 'agreements', 'update', 'Editar Acordos', 'Permite editar acordos/contratos existentes', 'Acordos'),
('b0000000-0000-0000-0000-000000000024', 'agreements', 'delete', 'Deletar Acordos', 'Permite deletar acordos/contratos permanentemente', 'Acordos'),
('b0000000-0000-0000-0000-000000000025', 'agreements', 'archive', 'Arquivar Acordos', 'Permite arquivar/desarquivar acordos', 'Acordos'),
('b0000000-0000-0000-0000-000000000026', 'agreements', 'export', 'Exportar Acordos', 'Permite exportar dados de acordos em diferentes formatos', 'Acordos')
ON CONFLICT (resource, action) DO UPDATE SET
    display_name = EXCLUDED.display_name,
    description = EXCLUDED.description,
    category = EXCLUDED.category;

-- ============================================
-- PERMISSIONS - Categorias e Subcategorias
-- ============================================
INSERT INTO permissions (id, resource, action, display_name, description, category) VALUES
('b0000000-0000-0000-0000-000000000031', 'categories', 'create', 'Criar Categorias', 'Permite criar novas categorias de acordos', 'Categorias'),
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
('b0000000-0000-0000-0000-000000000056', 'users', 'manage_roles', 'Gerenciar Papéis de Usuários', 'Permite alterar o papel/role atribuído a usuários', 'Usuários')
ON CONFLICT (resource, action) DO UPDATE SET
    display_name = EXCLUDED.display_name,
    description = EXCLUDED.description,
    category = EXCLUDED.category;

-- ============================================
-- PERMISSIONS - Auditoria
-- ============================================
INSERT INTO permissions (id, resource, action, display_name, description, category) VALUES
('b0000000-0000-0000-0000-000000000061', 'audit_logs', 'read', 'Visualizar Logs de Auditoria', 'Permite visualizar histórico de ações do sistema', 'Auditoria'),
('b0000000-0000-0000-0000-000000000062', 'audit_logs', 'export', 'Exportar Logs de Auditoria', 'Permite exportar logs de auditoria em diferentes formatos', 'Auditoria')
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
('b0000000-0000-0000-0000-000000000074', 'settings', 'manage_branding', 'Gerenciar Marca', 'Permite alterar logo, nome e identidade visual', 'Sistema')
ON CONFLICT (resource, action) DO UPDATE SET
    display_name = EXCLUDED.display_name,
    description = EXCLUDED.description,
    category = EXCLUDED.category;

-- ============================================
-- PERMISSIONS - Papéis (Roles)
-- ============================================
INSERT INTO permissions (id, resource, action, display_name, description, category) VALUES
('b0000000-0000-0000-0000-000000000101', 'roles', 'create', 'Criar Papéis', 'Permite criar novos papéis/roles personalizados', 'Sistema'),
('b0000000-0000-0000-0000-000000000102', 'roles', 'read', 'Visualizar Papéis', 'Permite visualizar lista de papéis e suas permissões', 'Sistema'),
('b0000000-0000-0000-0000-000000000103', 'roles', 'update', 'Editar Papéis', 'Permite modificar papéis existentes e suas permissões', 'Sistema'),
('b0000000-0000-0000-0000-000000000104', 'roles', 'delete', 'Deletar Papéis', 'Permite deletar papéis personalizados (não de sistema)', 'Sistema')
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

-- Limpa mapeamentos existentes para recriação (opcional, comentar se quiser preservar customizações)
-- DELETE FROM role_permissions WHERE role_id IN (
--     'a0000000-0000-0000-0000-000000000001',
--     'a0000000-0000-0000-0000-000000000002',
--     'a0000000-0000-0000-0000-000000000003',
--     'a0000000-0000-0000-0000-000000000004',
--     'a0000000-0000-0000-0000-000000000005'
-- );

-- ROOT: Todas as permissões (sempre terá tudo, independente do banco - validado em código também)
INSERT INTO role_permissions (role_id, permission_id)
SELECT 'a0000000-0000-0000-0000-000000000001', id FROM permissions
ON CONFLICT DO NOTHING;

-- ADMIN: Maioria das permissões, exceto gestão de roles e segurança crítica
INSERT INTO role_permissions (role_id, permission_id)
SELECT 'a0000000-0000-0000-0000-000000000002', id FROM permissions
WHERE
    -- Não pode gerenciar roles
    resource != 'roles'
    -- Não pode alterar configurações de segurança
    AND NOT (resource = 'settings' AND action = 'manage_security')
    -- Não pode atribuir roles a usuários (apenas root)
    AND NOT (resource = 'users' AND action = 'manage_roles')
ON CONFLICT DO NOTHING;

-- USER: Operações do dia-a-dia, sem deletar permanentemente
INSERT INTO role_permissions (role_id, permission_id)
SELECT 'a0000000-0000-0000-0000-000000000003', id FROM permissions
WHERE
    -- Entidades: criar, ler, editar, arquivar (não deletar)
    (resource = 'entities' AND action IN ('create', 'read', 'update', 'archive'))
    -- Sub-entidades: criar, ler, editar (não deletar)
    OR (resource = 'sub_entities' AND action IN ('create', 'read', 'update'))
    -- Acordos: criar, ler, editar, arquivar (não deletar)
    OR (resource = 'agreements' AND action IN ('create', 'read', 'update', 'archive'))
    -- Categorias: apenas ler
    OR (resource = 'categories' AND action = 'read')
    OR (resource = 'subcategories' AND action = 'read')
    -- Tema: ler e editar próprio
    OR (resource = 'theme' AND action IN ('read', 'update'))
    -- Dashboard: ler
    OR (resource = 'dashboard' AND action = 'read')
ON CONFLICT DO NOTHING;

-- VIEWER: Apenas leitura
INSERT INTO role_permissions (role_id, permission_id)
SELECT 'a0000000-0000-0000-0000-000000000004', id FROM permissions
WHERE
    action = 'read'
    AND resource IN ('entities', 'sub_entities', 'agreements', 'categories', 'subcategories', 'dashboard', 'theme')
ON CONFLICT DO NOTHING;

-- NOTA: Permissões para roles personalizados como "financeiro" devem ser
-- configuradas via interface administrativa após criar o role.
-- Exemplo comentado de como seria a estrutura:
--
-- INSERT INTO role_permissions (role_id, permission_id)
-- SELECT 'role_uuid_aqui', id FROM permissions
-- WHERE
--     (resource = 'agreements' AND action IN ('create', 'read', 'update', 'archive', 'export'))
--     OR (resource = 'entities' AND action IN ('read', 'update'))
--     OR (resource = 'sub_entities' AND action = 'read')
--     OR (resource = 'categories' AND action = 'read')
--     OR (resource = 'subcategories' AND action = 'read')
--     OR (resource = 'dashboard' AND action IN ('read', 'export'))
--     OR (resource = 'theme' AND action = 'read')
-- ON CONFLICT DO NOTHING;

-- ============================================
-- COMENTÁRIOS E DOCUMENTAÇÃO
-- ============================================
--
-- Para adicionar uma nova permissão:
-- 1. Adicione um INSERT na seção de PERMISSIONS com um novo UUID
-- 2. Adicione o mapeamento nas seções de ROLE PERMISSIONS
--
-- Para criar um novo role de sistema:
-- 1. Adicione um INSERT na seção de DEFAULT ROLES
-- 2. Defina a prioridade adequada (1-9 baixa, 10-49 média, 50-99 alta)
-- 3. Adicione os mapeamentos de permissões
--
-- Prioridade 100 é reservada EXCLUSIVAMENTE para o role 'root'
--
-- Roles personalizados (criados pela UI) não devem ser adicionados aqui,
-- pois são gerenciados dinamicamente pelo sistema.
