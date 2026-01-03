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
