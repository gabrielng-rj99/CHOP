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
-- CLIENTS MODULE
-- ============================================
-- Este arquivo contém tabelas de clientes:
-- - clients: Clientes principais
-- - affiliates: Afiliados vinculados a clientes
--
-- Deve ser executado após 04_users.sql

-- ============================================
-- CLIENTS
-- ============================================
CREATE TABLE IF NOT EXISTS clients (
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

-- Unique name when no registration_id
CREATE UNIQUE INDEX IF NOT EXISTS unique_name_when_no_registration ON clients(name) WHERE registration_id IS NULL;

CREATE INDEX IF NOT EXISTS idx_clients_name ON clients(name);
CREATE INDEX IF NOT EXISTS idx_clients_status ON clients(status);
CREATE INDEX IF NOT EXISTS idx_clients_archived ON clients(archived_at) WHERE archived_at IS NULL;

-- ============================================
-- AFFILIATES
-- ============================================
CREATE TABLE IF NOT EXISTS affiliates (
    id UUID PRIMARY KEY,
    name CITEXT NOT NULL,
    client_id UUID NOT NULL,
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
    FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE,
    CONSTRAINT unique_affiliate_name_per_client UNIQUE (client_id, name)
);

CREATE INDEX IF NOT EXISTS idx_affiliates_client_id ON affiliates(client_id);
CREATE INDEX IF NOT EXISTS idx_affiliates_name ON affiliates(name);
CREATE INDEX IF NOT EXISTS idx_affiliates_status ON affiliates(status);
