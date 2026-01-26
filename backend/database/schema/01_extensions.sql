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
-- POSTGRESQL EXTENSIONS
-- ============================================
-- Este arquivo deve ser executado primeiro.
-- Habilita extensões necessárias para o funcionamento do sistema.

-- CITEXT: Case-insensitive text type
-- Usado para usernames, emails, nomes de entidades, etc.
-- Permite buscas case-insensitive sem funções LOWER() em queries
CREATE EXTENSION IF NOT EXISTS citext;
