/*
 * Client Hub Open Project
 * Copyright (C) 2026 Client Hub Contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

-- ============================================
-- MIGRATION: Add composite index on financial_installments
-- ============================================
-- Purpose: Optimize queries that filter by (contract_financial_id, due_date)
--          and project status, received_value, client_value.
--
-- This covers the critical N+1 query in getPeriodSummary() which does:
--   SELECT status FROM financial_installments
--   WHERE contract_financial_id = $1 AND due_date >= $2 AND due_date < $3
--
-- And the batch replacement query:
--   SELECT contract_financial_id, status
--   FROM financial_installments
--   WHERE contract_financial_id = ANY($1) AND due_date >= $2 AND due_date < $3
--
-- The INCLUDE columns allow Index-Only Scans, avoiding heap fetches entirely.
-- ============================================

-- Composite covering index: enables Index-Only Scan for period summary queries
-- Note: Cannot use CONCURRENTLY inside migration transactions
CREATE INDEX IF NOT EXISTS idx_fi_cfid_duedate_covering
ON financial_installments (contract_financial_id, due_date)
INCLUDE (status, received_value, client_value);

-- Composite index for the grouped monthly query used by GetFinancialDetailedSummary
-- Optimizes: GROUP BY DATE_TRUNC('month', due_date) with status/value aggregations
CREATE INDEX IF NOT EXISTS idx_fi_duedate_cfid_covering
ON financial_installments (due_date, contract_financial_id)
INCLUDE (status, received_value, client_value);
