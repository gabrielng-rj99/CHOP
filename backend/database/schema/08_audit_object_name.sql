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
-- AUDIT LOGS ENHANCEMENT - Add object_name column
-- ============================================
-- Este arquivo adiciona a coluna object_name à tabela audit_logs
-- para armazenar o nome do objeto auditado (nome do cliente, categoria, etc)

-- Adicionar coluna object_name se ela não existir
ALTER TABLE IF EXISTS audit_logs
ADD COLUMN IF NOT EXISTS object_name VARCHAR(255);

-- Criar índice para melhor performance nas buscas por object_name
CREATE INDEX IF NOT EXISTS idx_audit_logs_object_name ON audit_logs(object_name);
