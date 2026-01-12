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
--   08_audit_object_name.sql - Função para nome de objeto em audit
--   09_financial.sql    - Financeiro e parcelas de contratos
--
-- Cada módulo é auto-contido: inclui DDL (CREATE TABLE) e DML (INSERT)
-- para os dados essenciais daquele módulo.

\echo '============================================'
\echo 'Client Hub - Database Initialization'
\echo '============================================'
\echo ''

\echo '[1/9] Loading extensions...'
\i 01_extensions.sql

\echo '[2/9] Loading core module (settings, roles, permissions)...'
\i 02_core.sql

\echo '[3/9] Loading security module (password/session policies)...'
\i 03_security.sql

\echo '[4/9] Loading users module...'
\i 04_users.sql

\echo '[5/9] Loading clients module...'
\i 05_clients.sql

\echo '[6/9] Loading contracts module...'
\i 06_contracts.sql

\echo '[7/9] Loading audit module...'
\i 07_audit.sql

\echo '[8/9] Loading audit object name function...'
\i 08_audit_object_name.sql

\echo '[9/9] Loading financial module...'
\i 09_financial.sql

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
\echo '  - contract_financial'
\echo '  - financial_installments'
\echo '  - audit_logs'
\echo ''
\echo 'Default data inserted:'
\echo '  - 4 roles (root, admin, user, viewer)'
\echo '  - All permissions (including financial)'
\echo '  - Role-permission mappings'
\echo '  - System settings (security, dashboard, notifications, audit)'
\echo '  - Password policies per role'
\echo '  - Session policies per role'
\echo ''
\echo 'Financial features:'
\echo '  - Support for unique, recurring, and custom financial types'
\echo '  - Installment tracking with due dates and status'
\echo '  - Dashboard views for upcoming and overdue financial'
\echo ''
