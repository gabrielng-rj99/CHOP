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
-- FINANCIAL MODULE
-- ============================================
-- Deve ser executado após 06_contracts.sql
-- ============================================

ALTER TABLE contracts DROP CONSTRAINT IF EXISTS contracts_item_key_key;
DROP INDEX IF EXISTS contracts_item_key_unique_not_null;
CREATE UNIQUE INDEX contracts_item_key_unique_not_null
ON contracts(item_key)
WHERE item_key IS NOT NULL AND item_key != '';

-- ============================================
-- CONTRACT FINANCIAL
-- ============================================
-- Modelo de financeiro associado a um contrato
-- Tipos:
--   'unico'       - Financeiro único (uma vez)
--   'recorrente'  - Financeiro recorrente (mensalidade, trimestral, etc)
--   'personalizado' - Financeiro com parcelas customizadas (entrada + N parcelas)

CREATE TABLE IF NOT EXISTS contract_financial (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    contract_id UUID NOT NULL REFERENCES contracts(id) ON DELETE CASCADE,

    -- Tipo de financeiro
    financial_type VARCHAR(20) NOT NULL DEFAULT 'unico'
        CHECK (financial_type IN ('unico', 'recorrente', 'personalizado')),

    -- Para financeiro recorrentes
    recurrence_type VARCHAR(20) DEFAULT NULL
        CHECK (recurrence_type IS NULL OR recurrence_type IN ('mensal', 'trimestral', 'semestral', 'anual')),
    due_day INTEGER DEFAULT NULL CHECK (due_day IS NULL OR (due_day >= 1 AND due_day <= 31)),

    -- Valores base (para tipo único ou recorrente)
    -- Para tipo personalizado, os valores estão em financial_installments
    client_value NUMERIC(12,2) DEFAULT NULL,   -- Quanto o cliente paga
    received_value NUMERIC(12,2) DEFAULT NULL, -- Quanto você recebe

    -- Descrição opcional
    description TEXT,

    -- Status
    is_active BOOLEAN NOT NULL DEFAULT TRUE,

    -- Metadados
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    -- Um contrato pode ter apenas um modelo de financeiro ativo
    CONSTRAINT unique_active_financial_per_contract UNIQUE (contract_id)
);

CREATE INDEX IF NOT EXISTS idx_contract_financial_contract ON contract_financial(contract_id);
CREATE INDEX IF NOT EXISTS idx_contract_financial_type ON contract_financial(financial_type);
CREATE INDEX IF NOT EXISTS idx_contract_financial_active ON contract_financial(is_active) WHERE is_active = TRUE;

-- ============================================
-- FINANCIAL INSTALLMENTS
-- ============================================
-- Parcelas customizadas para financeiro do tipo 'personalizado'
-- Exemplo: Entrada R$1000, 1ª Parcela R$1000, 2ª Parcela R$800, 3ª Parcela R$600

CREATE TABLE IF NOT EXISTS financial_installments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    contract_financial_id UUID NOT NULL REFERENCES contract_financial(id) ON DELETE CASCADE,

    -- Identificação da parcela
    installment_number INTEGER NOT NULL DEFAULT 0, -- 0 = Entrada, 1 = 1ª Parcela, etc.
    installment_label VARCHAR(100), -- Ex: "Entrada", "1ª Parcela", "Bônus 3º mês"

    -- Valores
    client_value NUMERIC(12,2) DEFAULT 0,   -- Quanto o cliente paga nesta parcela
    received_value NUMERIC(12,2) DEFAULT 0, -- Quanto você recebe nesta parcela

    -- Datas
    due_date DATE DEFAULT NULL,     -- Data de vencimento (opcional)
    paid_at TIMESTAMP DEFAULT NULL, -- Quando foi pago (NULL = não pago)

    -- Status
    status VARCHAR(20) NOT NULL DEFAULT 'pendente'
        CHECK (status IN ('pendente', 'pago', 'atrasado', 'cancelado')),

    -- Metadados
    notes TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    -- Garantir ordem única das parcelas por financeiro
    CONSTRAINT unique_installment_number UNIQUE (contract_financial_id, installment_number)
);

CREATE INDEX IF NOT EXISTS idx_financial_installments_financial ON financial_installments(contract_financial_id);
CREATE INDEX IF NOT EXISTS idx_financial_installments_status ON financial_installments(status);
CREATE INDEX IF NOT EXISTS idx_financial_installments_due_date ON financial_installments(due_date);
CREATE INDEX IF NOT EXISTS idx_financial_installments_paid_at ON financial_installments(paid_at) WHERE paid_at IS NOT NULL;

-- Composite covering indexes for performance optimization
-- Enables Index-Only Scan on period summary queries (getPeriodSummariesBatch)
-- Replaces BitmapAnd of two separate indexes with a single direct scan
CREATE INDEX IF NOT EXISTS idx_fi_cfid_duedate_covering
ON financial_installments (contract_financial_id, due_date)
INCLUDE (status, received_value, client_value);

-- Optimizes grouped monthly queries (GROUP BY DATE_TRUNC('month', due_date))
-- Used by GetFinancialDetailedSummary for the monthly breakdown
CREATE INDEX IF NOT EXISTS idx_fi_duedate_cfid_covering
ON financial_installments (due_date, contract_financial_id)
INCLUDE (status, received_value, client_value);

-- ============================================
-- PERMISSIONS - Financeiro
-- ============================================
INSERT INTO permissions (id, resource, action, display_name, description, category) VALUES
('b0000000-0000-0000-0000-000000000201', 'financial', 'create', 'Criar Financeiro', 'Permite criar configurações de financeiro para contratos', 'Financeiro'),
('b0000000-0000-0000-0000-000000000202', 'financial', 'read', 'Visualizar Financeiro', 'Permite visualizar financeiro e parcelas', 'Financeiro'),
('b0000000-0000-0000-0000-000000000203', 'financial', 'update', 'Editar Financeiro', 'Permite editar financeiro existentes', 'Financeiro'),
('b0000000-0000-0000-0000-000000000204', 'financial', 'delete', 'Deletar Financeiro', 'Permite deletar financeiro permanentemente', 'Financeiro'),
('b0000000-0000-0000-0000-000000000205', 'financial', 'read_values', 'Ver Valores de Financeiro', 'Permite visualizar os valores monetários (cliente paga / você recebe)', 'Financeiro'),
('b0000000-0000-0000-0000-000000000206', 'financial', 'update_values', 'Editar Valores de Financeiro', 'Permite editar os valores monetários dos financeiro', 'Financeiro'),
('b0000000-0000-0000-0000-000000000207', 'financial', 'mark_paid', 'Marcar como Pago', 'Permite marcar parcelas como pagas', 'Financeiro'),
('b0000000-0000-0000-0000-000000000208', 'financial', 'export', 'Exportar Financeiro', 'Permite exportar relatórios de financeiro', 'Financeiro')
ON CONFLICT (resource, action) DO UPDATE SET
    display_name = EXCLUDED.display_name,
    description = EXCLUDED.description,
    category = EXCLUDED.category;

-- ============================================
-- ROLE PERMISSIONS - Financeiro
-- ============================================

-- ROOT: Todas as permissões de financeiro
INSERT INTO role_permissions (role_id, permission_id)
SELECT 'a0000000-0000-0000-0000-000000000001', id FROM permissions
WHERE resource = 'financial'
ON CONFLICT DO NOTHING;

-- ADMIN: Todas as permissões de financeiro
INSERT INTO role_permissions (role_id, permission_id)
SELECT 'a0000000-0000-0000-0000-000000000002', id FROM permissions
WHERE resource = 'financial'
ON CONFLICT DO NOTHING;

-- USER: Criar, ler, editar, marcar como pago (não deletar, não ver/editar valores por padrão)
INSERT INTO role_permissions (role_id, permission_id)
SELECT 'a0000000-0000-0000-0000-000000000003', id FROM permissions
WHERE resource = 'financial'
AND action IN ('create', 'read', 'update', 'mark_paid')
ON CONFLICT DO NOTHING;

-- VIEWER: Apenas leitura (sem ver valores)
INSERT INTO role_permissions (role_id, permission_id)
SELECT 'a0000000-0000-0000-0000-000000000004', id FROM permissions
WHERE resource = 'financial' AND action = 'read'
ON CONFLICT DO NOTHING;

-- ============================================
-- VIEWS ÚTEIS
-- ============================================

-- View para resumo de financeiro por contrato
CREATE OR REPLACE VIEW v_contract_financial_summary AS
SELECT
    c.id AS contract_id,
    c.client_id,
    c.model AS contract_model,
    cp.id AS financial_id,
    cp.financial_type,
    cp.recurrence_type,
    cp.client_value AS base_client_value,
    cp.received_value AS base_received_value,
    cp.is_active,
    -- Para financeiro personalizados, soma das parcelas
    COALESCE(
        (SELECT SUM(pi.client_value) FROM financial_installments pi WHERE pi.contract_financial_id = cp.id),
        cp.client_value
    ) AS total_client_value,
    COALESCE(
        (SELECT SUM(pi.received_value) FROM financial_installments pi WHERE pi.contract_financial_id = cp.id),
        cp.received_value
    ) AS total_received_value,
    -- Contagem de parcelas
    (SELECT COUNT(*) FROM financial_installments pi WHERE pi.contract_financial_id = cp.id) AS total_installments,
    (SELECT COUNT(*) FROM financial_installments pi WHERE pi.contract_financial_id = cp.id AND pi.status = 'pago') AS paid_installments,
    (SELECT COUNT(*) FROM financial_installments pi WHERE pi.contract_financial_id = cp.id AND pi.status = 'pendente') AS pending_installments
FROM contracts c
LEFT JOIN contract_financial cp ON cp.contract_id = c.id
WHERE c.archived_at IS NULL;

-- View para próximos vencimentos (parcelas pendentes)
CREATE OR REPLACE VIEW v_upcoming_financial AS
SELECT
    pi.id AS installment_id,
    pi.contract_financial_id,
    pi.installment_number,
    pi.installment_label,
    pi.client_value,
    pi.received_value,
    pi.due_date,
    pi.status,
    cp.contract_id,
    c.client_id,
    cl.name AS client_name,
    c.model AS contract_model
FROM financial_installments pi
JOIN contract_financial cp ON cp.id = pi.contract_financial_id
JOIN contracts c ON c.id = cp.contract_id
JOIN clients cl ON cl.id = c.client_id
WHERE pi.status = 'pendente'
AND pi.due_date IS NOT NULL
AND c.archived_at IS NULL
ORDER BY pi.due_date ASC;

-- View para valores a receber por mês (com dados de atrasados e pendentes)
CREATE OR REPLACE VIEW v_monthly_financial AS
SELECT
    DATE_TRUNC('month', pi.due_date) AS month,
    TO_CHAR(DATE_TRUNC('month', pi.due_date), 'YYYY-MM') AS period,
    TO_CHAR(DATE_TRUNC('month', pi.due_date), 'TMMonth YYYY') AS period_label,
    COALESCE(SUM(pi.received_value), 0) AS total_to_receive,
    COALESCE(SUM(pi.client_value), 0) AS total_client_pays,
    COALESCE(SUM(CASE WHEN pi.status = 'pago' THEN pi.received_value ELSE 0 END), 0) AS already_received,
    COALESCE(SUM(CASE WHEN pi.status = 'pendente' THEN pi.received_value ELSE 0 END), 0) AS pending_amount,
    COUNT(CASE WHEN pi.status = 'pendente' THEN 1 END) AS pending_count,
    COUNT(CASE WHEN pi.status = 'pago' THEN 1 END) AS paid_count,
    COUNT(CASE WHEN pi.status = 'atrasado' THEN 1 END) AS overdue_count,
    COALESCE(SUM(CASE WHEN pi.status = 'atrasado' THEN pi.received_value ELSE 0 END), 0) AS overdue_amount,
    COUNT(*) AS installment_count
FROM financial_installments pi
JOIN contract_financial cp ON cp.id = pi.contract_financial_id
JOIN contracts c ON c.id = cp.contract_id
WHERE c.archived_at IS NULL
AND pi.due_date IS NOT NULL
GROUP BY DATE_TRUNC('month', pi.due_date)
ORDER BY month;

-- View para resumo rápido: mês atual, passado e próximo
CREATE OR REPLACE VIEW v_financial_period_summary AS
WITH current_periods AS (
    SELECT
        DATE_TRUNC('month', CURRENT_DATE - INTERVAL '1 month') AS last_month,
        DATE_TRUNC('month', CURRENT_DATE) AS current_month,
        DATE_TRUNC('month', CURRENT_DATE + INTERVAL '1 month') AS next_month
)
SELECT
    'last_month' AS period_type,
    mr.*
FROM v_monthly_financial mr, current_periods cp
WHERE mr.month = cp.last_month
UNION ALL
SELECT
    'current_month' AS period_type,
    mr.*
FROM v_monthly_financial mr, current_periods cp
WHERE mr.month = cp.current_month
UNION ALL
SELECT
    'next_month' AS period_type,
    mr.*
FROM v_monthly_financial mr, current_periods cp
WHERE mr.month = cp.next_month;
