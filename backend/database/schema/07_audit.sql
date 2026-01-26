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
-- AUDIT MODULE
-- ============================================
-- Este arquivo contém tabelas de auditoria:
-- - audit_logs: Registro de todas as ações do sistema
--
-- Deve ser executado após 06_contracts.sql

-- ============================================
-- AUDIT LOGS
-- ============================================
CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY,
    timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    operation VARCHAR(50) NOT NULL,
    resource VARCHAR(50) NOT NULL,
    resource_id VARCHAR(255) NOT NULL,
    object_name VARCHAR(255),
    admin_id UUID,
    admin_username CITEXT,
    old_value TEXT,
    new_value TEXT,
    status VARCHAR(20) NOT NULL DEFAULT 'success',
    error_message TEXT,
    ip_address VARCHAR(45),
    user_agent TEXT,
    request_method VARCHAR(10),
    request_path VARCHAR(512),
    request_id VARCHAR(100),
    response_code INTEGER,
    execution_time_ms INTEGER,
    FOREIGN KEY (admin_id) REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_resource ON audit_logs(resource, resource_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_admin_id ON audit_logs(admin_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_operation ON audit_logs(operation);
CREATE INDEX IF NOT EXISTS idx_audit_logs_request_id ON audit_logs(request_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_status ON audit_logs(status);
CREATE INDEX IF NOT EXISTS idx_audit_logs_ip ON audit_logs(ip_address);
CREATE INDEX IF NOT EXISTS idx_audit_logs_object_name ON audit_logs(object_name);

-- ============================================
-- PERMISSIONS - Auditoria
-- ============================================
INSERT INTO permissions (id, resource, action, display_name, description, category) VALUES
('b0000000-0000-0000-0000-000000000061', 'audit_logs', 'read', 'Visualizar Logs de Auditoria', 'Permite visualizar histórico de ações do sistema', 'Auditoria'),
('b0000000-0000-0000-0000-000000000062', 'audit_logs', 'export', 'Exportar Logs de Auditoria', 'Permite exportar logs de auditoria em diferentes formatos', 'Auditoria'),
('b0000000-0000-0000-0000-000000000131', 'audit_logs', 'read_all', 'Ver Todos os Logs', 'Permite visualizar logs de auditoria de todo o sistema', 'Auditoria'),
('b0000000-0000-0000-0000-000000000132', 'audit_logs', 'read_own', 'Ver Logs Próprios', 'Permite visualizar apenas logs das próprias ações', 'Auditoria'),
('b0000000-0000-0000-0000-000000000133', 'audit_logs', 'delete', 'Deletar Logs', 'Permite remover logs de auditoria (uso crítico)', 'Auditoria'),
('b0000000-0000-0000-0000-000000000134', 'audit_logs', 'configure', 'Configurar Auditoria', 'Permite configurar retenção e tipos de log', 'Auditoria')
ON CONFLICT (resource, action) DO UPDATE SET
    display_name = EXCLUDED.display_name,
    description = EXCLUDED.description,
    category = EXCLUDED.category;

-- ============================================
-- ROLE PERMISSIONS - Audit Logs
-- ============================================

-- ROOT: Todas as permissões de audit_logs
INSERT INTO role_permissions (role_id, permission_id)
SELECT 'a0000000-0000-0000-0000-000000000001', id FROM permissions
WHERE resource = 'audit_logs'
ON CONFLICT DO NOTHING;

-- ADMIN: Audit logs exceto delete
INSERT INTO role_permissions (role_id, permission_id)
SELECT 'a0000000-0000-0000-0000-000000000002', id FROM permissions
WHERE resource = 'audit_logs' AND action != 'delete'
ON CONFLICT DO NOTHING;

-- USER: Apenas read_own
INSERT INTO role_permissions (role_id, permission_id)
SELECT 'a0000000-0000-0000-0000-000000000003', id FROM permissions
WHERE resource = 'audit_logs' AND action = 'read_own'
ON CONFLICT DO NOTHING;
