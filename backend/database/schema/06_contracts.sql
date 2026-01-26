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
-- CONTRACTS MODULE
-- ============================================
-- Este arquivo contém tabelas de contratos:
-- - categories: Categorias de contratos
-- - subcategories: Subcategorias de contratos
-- - contracts: Contratos
--
-- Deve ser executado após 05_clients.sql

-- ============================================
-- CATEGORIES
-- ============================================
CREATE TABLE IF NOT EXISTS categories (
    id UUID PRIMARY KEY,
    name CITEXT UNIQUE NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'ativo',
    archived_at TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_categories_name ON categories(name);
CREATE INDEX IF NOT EXISTS idx_categories_status ON categories(status);
CREATE INDEX IF NOT EXISTS idx_categories_archived ON categories(archived_at) WHERE archived_at IS NULL;

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

CREATE INDEX IF NOT EXISTS idx_subcategories_category_id ON subcategories(category_id);
CREATE INDEX IF NOT EXISTS idx_subcategories_name ON subcategories(name);
CREATE INDEX IF NOT EXISTS idx_subcategories_archived ON subcategories(archived_at) WHERE archived_at IS NULL;

-- ============================================
-- CONTRACTS
-- ============================================
CREATE TABLE IF NOT EXISTS contracts (
    id UUID PRIMARY KEY,
    model CITEXT,
    item_key CITEXT UNIQUE,
    start_date TIMESTAMP,
    end_date TIMESTAMP,
    subcategory_id UUID NOT NULL,
    client_id UUID NOT NULL,
    affiliate_id UUID,
    archived_at TIMESTAMP,
    FOREIGN KEY (subcategory_id) REFERENCES subcategories(id),
    FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE,
    FOREIGN KEY (affiliate_id) REFERENCES affiliates(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_contracts_subcategory_id ON contracts(subcategory_id);
CREATE INDEX IF NOT EXISTS idx_contracts_client_id ON contracts(client_id);
CREATE INDEX IF NOT EXISTS idx_contracts_affiliate_id ON contracts(affiliate_id);
CREATE INDEX IF NOT EXISTS idx_contracts_item_key ON contracts(item_key);
CREATE INDEX IF NOT EXISTS idx_contracts_end_date ON contracts(end_date);
CREATE INDEX IF NOT EXISTS idx_contracts_archived ON contracts(archived_at) WHERE archived_at IS NULL;

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
-- ROLE PERMISSIONS - Categories
-- ============================================

-- ROOT: Todas as permissões de categories
INSERT INTO role_permissions (role_id, permission_id)
SELECT 'a0000000-0000-0000-0000-000000000001', id FROM permissions
WHERE resource = 'categories'
ON CONFLICT DO NOTHING;

-- ADMIN: Todas as permissões de categories
INSERT INTO role_permissions (role_id, permission_id)
SELECT 'a0000000-0000-0000-0000-000000000002', id FROM permissions
WHERE resource = 'categories'
ON CONFLICT DO NOTHING;

-- USER: Categories read
INSERT INTO role_permissions (role_id, permission_id)
SELECT 'a0000000-0000-0000-0000-000000000003', id FROM permissions
WHERE resource = 'categories' AND action = 'read'
ON CONFLICT DO NOTHING;

-- VIEWER: Categories read
INSERT INTO role_permissions (role_id, permission_id)
SELECT 'a0000000-0000-0000-0000-000000000004', id FROM permissions
WHERE resource = 'categories' AND action = 'read'
ON CONFLICT DO NOTHING;

-- ============================================
-- ROLE PERMISSIONS - Subcategories
-- ============================================

-- ROOT: Todas as permissões de subcategories
INSERT INTO role_permissions (role_id, permission_id)
SELECT 'a0000000-0000-0000-0000-000000000001', id FROM permissions
WHERE resource = 'subcategories'
ON CONFLICT DO NOTHING;

-- ADMIN: Todas as permissões de subcategories
INSERT INTO role_permissions (role_id, permission_id)
SELECT 'a0000000-0000-0000-0000-000000000002', id FROM permissions
WHERE resource = 'subcategories'
ON CONFLICT DO NOTHING;

-- USER: Subcategories read
INSERT INTO role_permissions (role_id, permission_id)
SELECT 'a0000000-0000-0000-0000-000000000003', id FROM permissions
WHERE resource = 'subcategories' AND action = 'read'
ON CONFLICT DO NOTHING;

-- VIEWER: Subcategories read
INSERT INTO role_permissions (role_id, permission_id)
SELECT 'a0000000-0000-0000-0000-000000000004', id FROM permissions
WHERE resource = 'subcategories' AND action = 'read'
ON CONFLICT DO NOTHING;

-- ============================================
-- ROLE PERMISSIONS - Contracts
-- ============================================

-- ROOT: Todas as permissões de contracts
INSERT INTO role_permissions (role_id, permission_id)
SELECT 'a0000000-0000-0000-0000-000000000001', id FROM permissions
WHERE resource = 'contracts'
ON CONFLICT DO NOTHING;

-- ADMIN: Todas as permissões de contracts
INSERT INTO role_permissions (role_id, permission_id)
SELECT 'a0000000-0000-0000-0000-000000000002', id FROM permissions
WHERE resource = 'contracts'
ON CONFLICT DO NOTHING;

-- USER: Contracts create, read, update, archive (não delete)
INSERT INTO role_permissions (role_id, permission_id)
SELECT 'a0000000-0000-0000-0000-000000000003', id FROM permissions
WHERE resource = 'contracts' AND action IN ('create', 'read', 'update', 'archive')
ON CONFLICT DO NOTHING;

-- VIEWER: Contracts read
INSERT INTO role_permissions (role_id, permission_id)
SELECT 'a0000000-0000-0000-0000-000000000004', id FROM permissions
WHERE resource = 'contracts' AND action = 'read'
ON CONFLICT DO NOTHING;
