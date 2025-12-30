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
-- Client Hub - DATABASE INITIALIZATION
-- ============================================
-- Este arquivo orquestra a execução de todos os módulos do schema.
--
-- Uso:
--   psql -d client_hub -f init.sql
--
-- Ou diretamente de dentro do diretório schema/:
--   psql -d client_hub -f init.sql
--
-- Ordem de execução:
--   01_extensions.sql  - Extensões PostgreSQL (citext)
--   02_core.sql        - Tabelas core: settings, roles, permissions + dados
--   03_security.sql    - Segurança: políticas de senha/sessão + dados
--   04_users.sql       - Usuários e preferências de tema
--   05_clients.sql     - Clientes e filiais
--   06_contracts.sql   - Categorias, subcategorias e contratos
--   07_audit.sql       - Logs de auditoria
--
-- Cada módulo é auto-contido: inclui DDL (CREATE TABLE) e DML (INSERT)
-- para os dados essenciais daquele módulo.

\echo '============================================'
\echo 'Client Hub - Database Initialization'
\echo '============================================'
\echo ''

\echo '[1/7] Loading extensions...'
\i 01_extensions.sql

\echo '[2/7] Loading core module (settings, roles, permissions)...'
\i 02_core.sql

\echo '[3/7] Loading security module (password/session policies)...'
\i 03_security.sql

\echo '[4/7] Loading users module...'
\i 04_users.sql

\echo '[5/7] Loading clients module...'
\i 05_clients.sql

\echo '[6/7] Loading contracts module...'
\i 06_contracts.sql

\echo '[7/7] Loading audit module...'
\i 07_audit.sql

\echo ''
\echo '============================================'
\echo 'Database initialization complete!'
\echo '============================================'
\echo ''
\echo 'Tables created:'
\echo '  - system_settings'
\echo '  - roles'
\echo '  - permissions'
\echo '  - role_permissions'
\echo '  - role_password_policies'
\echo '  - role_session_policies'
\echo '  - password_history'
\echo '  - login_attempts'
\echo '  - users'
\echo '  - user_theme_settings'
\echo '  - clients'
\echo '  - affiliates'
\echo '  - categories'
\echo '  - subcategories'
\echo '  - contracts'
\echo '  - audit_logs'
\echo ''
\echo 'Default data inserted:'
\echo '  - 4 roles (root, admin, user, viewer)'
\echo '  - All permissions'
\echo '  - Role-permission mappings'
\echo '  - System settings (security, dashboard, notifications, audit)'
\echo '  - Password policies per role'
\echo '  - Session policies per role'
\echo ''
