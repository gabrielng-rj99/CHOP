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
-- Uso (execute de dentro do diretório schema/):
--   psql -d client_hub -f init.sql
--
-- Ou de qualquer lugar apontando para o arquivo:
--   psql -d client_hub -f backend/database/init.sql
--
-- Ordem de execução automática (arquivos 01-08):
--   01_extensions.sql  - Extensões PostgreSQL (citext)
--   02_core.sql        - Tabelas core: settings, roles, permissions + dados
--   03_security.sql    - Segurança: políticas de senha/sessão + dados
--   04_users.sql       - Usuários e preferências de tema
--   05_clients.sql     - Clientes e filiais
--   06_contracts.sql   - Categorias, subcategorias e contratos
--   07_audit.sql       - Logs de auditoria + permissões
--   08_financial.sql   - Financeiro e parcelas de contratos
--
-- Cada módulo é auto-contido: inclui DDL (CREATE TABLE) e DML (INSERT)
-- para os dados essenciais daquele módulo.

\echo '============================================'
\echo 'Client Hub - Database Initialization'
\echo '============================================'
\echo ''

\echo '[1/8] Loading extensions...'
\i schema/01_extensions.sql

\echo '[2/8] Loading core module (settings, roles, permissions)...'
\i schema/02_core.sql

\echo '[3/8] Loading security module (password/session policies)...'
\i schema/03_security.sql

\echo '[4/8] Loading users module...'
\i schema/04_users.sql

\echo '[5/8] Loading clients module...'
\i schema/05_clients.sql

\echo '[6/8] Loading contracts module...'
\i schema/06_contracts.sql

\echo '[7/8] Loading audit module...'
\i schema/07_audit.sql

\echo '[8/8] Loading financial module...'
\i schema/08_financial.sql

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
\echo '  - 77 permissions (distributed across 12 categories)'
\echo '  - 168 role-permission mappings'
\echo '  - System settings (security, dashboard, notifications, audit)'
\echo '  - Password policies per role'
\echo '  - Session policies per role'
\echo ''
\echo 'Financial features:'
\echo '  - Support for unique, recurring, and custom financial types'
\echo '  - Installment tracking with due dates and status'
\echo '  - Dashboard views for upcoming and overdue financial'
\echo ''
