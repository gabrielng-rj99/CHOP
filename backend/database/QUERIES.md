# Database Queries Reference Guide

## Quick Lookup

### Find User Information
```sql
-- Get user with all details
SELECT u.id, u.username, u.display_name, r.name as role, u.created_at
FROM users u
LEFT JOIN roles r ON u.role_id = r.id
WHERE u.username = 'john.doe';

-- Get user's permissions
SELECT p.resource, p.action, p.display_name
FROM users u
JOIN roles r ON u.role_id = r.id
JOIN role_permissions rp ON r.id = rp.role_id
JOIN permissions p ON rp.permission_id = p.id
WHERE u.username = 'john.doe'
ORDER BY p.resource, p.action;

-- Check if user is locked
SELECT id, username, lock_level, locked_until, 
       CASE WHEN locked_until > NOW() THEN 'LOCKED' ELSE 'ACTIVE' END as status
FROM users
WHERE locked_until > NOW();
```

### Find Client Information
```sql
-- Get client with contract count
SELECT c.id, c.name, c.status, c.registration_id,
       COUNT(ct.id) as contract_count,
       COUNT(af.id) as affiliate_count
FROM clients c
LEFT JOIN contracts ct ON c.id = ct.client_id AND ct.archived_at IS NULL
LEFT JOIN affiliates af ON c.id = af.client_id
WHERE c.archived_at IS NULL
GROUP BY c.id, c.name, c.status, c.registration_id
ORDER BY c.name;

-- Get client with all affiliates
SELECT c.id, c.name, af.id as affiliate_id, af.name as affiliate_name
FROM clients c
LEFT JOIN affiliates af ON c.id = af.client_id
WHERE c.id = 'client-uuid-here'
ORDER BY af.name;

-- Search clients by name (case-insensitive)
SELECT id, name, registration_id, status, created_at
FROM clients
WHERE name ILIKE '%search-term%' AND archived_at IS NULL
ORDER BY name;
```

### Find Contract Information
```sql
-- Get contracts for a client
SELECT c.id, c.model, c.item_key, cat.name as category, 
       sc.name as subcategory, c.start_date, c.end_date
FROM contracts c
JOIN subcategories sc ON c.subcategory_id = sc.id
JOIN categories cat ON sc.category_id = cat.id
WHERE c.client_id = 'client-uuid-here' AND c.archived_at IS NULL
ORDER BY c.created_at DESC;

-- Get contracts expiring soon
SELECT c.id, c.model, c.end_date, cl.name as client_name
FROM contracts c
JOIN clients cl ON c.client_id = cl.id
WHERE c.end_date BETWEEN NOW() AND NOW() + INTERVAL '30 days'
AND c.archived_at IS NULL
ORDER BY c.end_date ASC;

-- Get expired contracts
SELECT c.id, c.model, c.end_date, cl.name as client_name
FROM contracts c
JOIN clients cl ON c.client_id = cl.id
WHERE c.end_date < NOW() AND c.archived_at IS NULL
ORDER BY c.end_date DESC;
```

## Financial Queries

### Outstanding Payments
```sql
-- Get upcoming payments (next 30 days)
SELECT pi.id, pi.installment_number, pi.installment_label,
       pi.client_value, pi.received_value, pi.due_date,
       c.model, cl.name as client_name,
       cf.financial_type
FROM financial_installments pi
JOIN contract_financial cf ON pi.contract_financial_id = cf.id
JOIN contracts c ON cf.contract_id = c.id
JOIN clients cl ON c.client_id = cl.id
WHERE pi.status = 'pendente'
AND pi.due_date BETWEEN NOW() AND NOW() + INTERVAL '30 days'
AND c.archived_at IS NULL
ORDER BY pi.due_date ASC;

-- Get overdue payments
SELECT pi.id, pi.installment_number, pi.installment_label,
       pi.client_value, pi.received_value, pi.due_date,
       CURRENT_DATE - pi.due_date as days_overdue,
       cl.name as client_name
FROM financial_installments pi
JOIN contract_financial cf ON pi.contract_financial_id = cf.id
JOIN contracts c ON cf.contract_id = c.id
JOIN clients cl ON c.client_id = cl.id
WHERE pi.status = 'atrasado'
AND c.archived_at IS NULL
ORDER BY pi.due_date ASC;

-- Monthly cash flow summary
SELECT DATE_TRUNC('month', pi.due_date) as month,
       COUNT(*) as installment_count,
       SUM(pi.received_value) FILTER (WHERE pi.status = 'pago') as received,
       SUM(pi.received_value) FILTER (WHERE pi.status = 'pendente') as pending,
       SUM(pi.received_value) FILTER (WHERE pi.status = 'atrasado') as overdue,
       SUM(pi.received_value) as total_due
FROM financial_installments pi
JOIN contract_financial cf ON pi.contract_financial_id = cf.id
JOIN contracts c ON cf.contract_id = c.id
WHERE c.archived_at IS NULL
GROUP BY DATE_TRUNC('month', pi.due_date)
ORDER BY month DESC;

-- Total financial by contract
SELECT c.id, c.model, cl.name as client_name,
       cf.financial_type, cf.recurrence_type,
       SUM(pi.client_value) as total_client_pays,
       SUM(pi.received_value) as total_received,
       COUNT(*) as total_installments,
       COUNT(*) FILTER (WHERE pi.status = 'pago') as paid_count,
       COUNT(*) FILTER (WHERE pi.status = 'pendente') as pending_count
FROM contract_financial cf
JOIN contracts c ON cf.contract_id = c.id
JOIN clients cl ON c.client_id = cl.id
LEFT JOIN financial_installments pi ON cf.id = pi.contract_financial_id
WHERE c.archived_at IS NULL
GROUP BY c.id, c.model, cl.name, cf.financial_type, cf.recurrence_type
ORDER BY cl.name, c.model;
```

## Audit & Compliance Queries

### Recent Activity
```sql
-- Last 100 actions in system
SELECT timestamp, operation, resource, object_name, 
       admin_username, status, response_code
FROM audit_logs
ORDER BY timestamp DESC
LIMIT 100;

-- All changes to a specific client
SELECT timestamp, operation, object_name, admin_username,
       old_value, new_value, ip_address
FROM audit_logs
WHERE resource = 'clients' AND resource_id = 'client-uuid-here'
ORDER BY timestamp DESC;

-- Activity by user in last 7 days
SELECT DATE(timestamp), COUNT(*) as action_count,
       COUNT(*) FILTER (WHERE status = 'error') as errors
FROM audit_logs
WHERE admin_id = 'user-uuid-here'
AND timestamp > NOW() - INTERVAL '7 days'
GROUP BY DATE(timestamp)
ORDER BY DATE DESC;

-- Failed operations
SELECT timestamp, operation, resource, resource_id,
       admin_username, status, error_message, ip_address
FROM audit_logs
WHERE status = 'error'
ORDER BY timestamp DESC
LIMIT 50;

-- Most active users (last 30 days)
SELECT admin_username, COUNT(*) as action_count,
       COUNT(DISTINCT resource) as resources_touched,
       MIN(timestamp) as first_action,
       MAX(timestamp) as last_action
FROM audit_logs
WHERE timestamp > NOW() - INTERVAL '30 days'
GROUP BY admin_username
ORDER BY action_count DESC;
```

### Compliance Reports
```sql
-- Who changed what on a specific date
SELECT timestamp, admin_username, operation, resource, object_name,
       old_value, new_value, ip_address
FROM audit_logs
WHERE DATE(timestamp) = '2025-01-23'
ORDER BY timestamp ASC;

-- Track sensitive changes (user creation, role changes)
SELECT timestamp, admin_username, operation, resource, resource_id,
       object_name, new_value, ip_address
FROM audit_logs
WHERE resource IN ('users', 'roles', 'role_permissions')
AND timestamp > NOW() - INTERVAL '7 days'
ORDER BY timestamp DESC;

-- Suspicious activity (multiple IPs for same user)
SELECT admin_username, COUNT(DISTINCT ip_address) as ip_count,
       STRING_AGG(DISTINCT ip_address, ', ') as ips,
       COUNT(*) as total_actions
FROM audit_logs
WHERE timestamp > NOW() - INTERVAL '24 hours'
GROUP BY admin_username
HAVING COUNT(DISTINCT ip_address) > 1
ORDER BY ip_count DESC;
```

## Permission & Role Queries

### Check Role Permissions
```sql
-- What can a role do?
SELECT r.name as role, p.resource, p.action, p.display_name, p.category
FROM roles r
JOIN role_permissions rp ON r.id = rp.role_id
JOIN permissions p ON rp.permission_id = p.id
WHERE r.name = 'user'
ORDER BY p.category, p.resource, p.action;

-- Compare two roles
SELECT p.resource, p.action,
       MAX(CASE WHEN r.name = 'admin' THEN 1 ELSE 0 END) as admin_has,
       MAX(CASE WHEN r.name = 'user' THEN 1 ELSE 0 END) as user_has
FROM role_permissions rp
JOIN roles r ON rp.role_id = r.id
JOIN permissions p ON rp.permission_id = p.id
WHERE r.name IN ('admin', 'user')
GROUP BY p.resource, p.action
ORDER BY p.resource, p.action;

-- Permissions by category
SELECT p.category, COUNT(*) as permission_count,
       STRING_AGG(DISTINCT p.resource, ', ') as resources
FROM permissions p
GROUP BY p.category
ORDER BY p.category;

-- Who has a specific permission?
SELECT r.name as role
FROM role_permissions rp
JOIN roles r ON rp.role_id = r.id
JOIN permissions p ON rp.permission_id = p.id
WHERE p.resource = 'clients' AND p.action = 'delete'
ORDER BY r.priority DESC;
```

## Statistics & Analytics

### System Overview
```sql
-- Database statistics
SELECT 
  (SELECT COUNT(*) FROM users) as total_users,
  (SELECT COUNT(*) FROM clients WHERE archived_at IS NULL) as active_clients,
  (SELECT COUNT(*) FROM contracts WHERE archived_at IS NULL) as active_contracts,
  (SELECT COUNT(*) FROM roles WHERE is_system = true) as system_roles,
  (SELECT COUNT(*) FROM permissions) as total_permissions,
  (SELECT COUNT(*) FROM audit_logs) as total_audit_logs,
  (SELECT COUNT(*) FROM financial_installments WHERE status = 'pendente') as pending_payments;

-- User statistics
SELECT r.name as role, COUNT(u.id) as user_count,
       COUNT(*) FILTER (WHERE u.deleted_at IS NULL) as active
FROM users u
LEFT JOIN roles r ON u.role_id = r.id
GROUP BY r.name, r.priority
ORDER BY r.priority DESC;

-- Client by status
SELECT status, COUNT(*) as count
FROM clients
WHERE archived_at IS NULL
GROUP BY status
ORDER BY count DESC;

-- Contract distribution
SELECT cat.name as category, COUNT(ct.id) as count
FROM contracts ct
JOIN subcategories sc ON ct.subcategory_id = sc.id
JOIN categories cat ON sc.category_id = cat.id
WHERE ct.archived_at IS NULL
GROUP BY cat.name
ORDER BY count DESC;

-- Financial overview
SELECT 
  (SELECT COUNT(*) FROM contract_financial WHERE is_active = true) as active_financials,
  (SELECT SUM(received_value) FROM financial_installments WHERE status = 'pago') as total_received,
  (SELECT SUM(received_value) FROM financial_installments WHERE status = 'pendente') as total_pending,
  (SELECT SUM(received_value) FROM financial_installments WHERE status = 'atrasado') as total_overdue;
```

## Maintenance Queries

### Database Cleanup (Use with Caution)
```sql
-- Find orphaned records (contracts without clients)
SELECT c.id, c.model, c.item_key
FROM contracts c
LEFT JOIN clients cl ON c.client_id = cl.id
WHERE cl.id IS NULL;

-- Find unused categories
SELECT cat.id, cat.name, COUNT(sc.id) as subcategory_count
FROM categories cat
LEFT JOIN subcategories sc ON cat.id = sc.category_id
WHERE cat.archived_at IS NULL
GROUP BY cat.id, cat.name
HAVING COUNT(sc.id) = 0;

-- Find stale sessions (no activity in X days)
SELECT id, username, last_login_at,
       NOW() - last_login_at as inactive_duration
FROM users
WHERE last_login_at < NOW() - INTERVAL '90 days'
AND deleted_at IS NULL
ORDER BY last_login_at DESC;
```

### Table Statistics
```sql
-- Table sizes
SELECT schemaname, tablename,
       pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) as size
FROM pg_tables
WHERE schemaname = 'public'
ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC;

-- Index efficiency
SELECT schemaname, tablename, indexname,
       pg_size_pretty(pg_relation_size(indexrelid)) as index_size
FROM pg_indexes
WHERE schemaname = 'public'
ORDER BY pg_relation_size(indexrelid) DESC;

-- Row counts
SELECT tablename, 
       (SELECT COUNT(*) FROM pg_class WHERE relname = tablename) as row_count
FROM pg_tables
WHERE schemaname = 'public'
ORDER BY tablename;
```

## Common Updates

### Update User Role
```sql
UPDATE users
SET role_id = (SELECT id FROM roles WHERE name = 'admin'),
    updated_at = NOW()
WHERE id = 'user-uuid-here';
```

### Mark Payment as Paid
```sql
UPDATE financial_installments
SET status = 'pago',
    paid_at = NOW(),
    updated_at = NOW()
WHERE id = 'installment-uuid-here';
```

### Archive Client (Soft Delete)
```sql
UPDATE clients
SET archived_at = NOW()
WHERE id = 'client-uuid-here' AND archived_at IS NULL;
```

### Unarchive Client
```sql
UPDATE clients
SET archived_at = NULL
WHERE id = 'client-uuid-here';
```

### Lock User Account
```sql
UPDATE users
SET lock_level = 3,
    locked_until = NOW() + INTERVAL '1 hour'
WHERE id = 'user-uuid-here';
```

### Unlock User Account
```sql
UPDATE users
SET lock_level = 0,
    locked_until = NULL,
    failed_attempts = 0
WHERE id = 'user-uuid-here';
```

## Useful Views (Pre-built Queries)

These views are automatically created by the schema:

```sql
-- Financial summary per contract
SELECT * FROM v_contract_financial_summary;

-- Upcoming payments
SELECT * FROM v_upcoming_financial
LIMIT 20;

-- Monthly revenue analysis
SELECT * FROM v_monthly_financial;

-- Quick period summary
SELECT * FROM v_financial_period_summary;
```

## Performance Tips

### Use These Conditions
```sql
-- Always filter archived records
WHERE archived_at IS NULL

-- Use indexed columns first
WHERE status = 'pendente' AND due_date > NOW()

-- Prefer exact match over LIKE
WHERE name = 'exact name'  -- Better than ILIKE '%name%'

-- Date comparisons with functions
WHERE DATE(timestamp) = '2025-01-23'  -- OK for small queries
WHERE timestamp >= '2025-01-23'::DATE AND timestamp < '2025-01-24'::DATE  -- Better
```

### Avoid These
```sql
-- Expensive LIKE operations
WHERE name LIKE '%middle%'  -- Scans entire column

-- Functions on indexed columns
WHERE LOWER(name) = 'value'  -- Use CITEXT instead

-- Date math on indexed columns
WHERE DATE(timestamp) = NOW()  -- Use range instead

-- OR with different columns
WHERE id = 'x' OR name = 'y'  -- Use IN or UNION
```

## Common Errors & Solutions

### "violates foreign key constraint"
```
Solution: Ensure referenced record exists in parent table first
Example: Insert parent client before creating contracts
```

### "duplicate key value violates unique constraint"
```
Solution: Check for ON CONFLICT in schema files
Most inserts use: ON CONFLICT DO UPDATE SET ...
Safe to re-run if interrupted
```

### "relation does not exist"
```
Solution: Ensure schema was initialized
Run: make db-reset  (dev mode) or InitDB() (app startup)
```

### "permission denied"
```
Solution: Check user role and permissions
SELECT * FROM role_permissions WHERE role_id = user_role_id
```
