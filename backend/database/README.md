# Database Documentation

## Overview

The Client Hub database is organized using a **modular schema architecture** where each business domain has its own migration file. This ensures:
- **Maintainability**: Each module is self-contained with DDL and DML
- **Scalability**: New modules can be added without affecting existing ones
- **Consistency**: Permissions are defined per-module, preventing inconsistencies

---

## Architecture

### File Structure

```
backend/database/
├── README.md              # This file
├── init.sql               # Manual initialization script (for psql CLI)
└── schema/
    ├── 01_extensions.sql  # PostgreSQL extensions (citext)
    ├── 02_core.sql        # Core: settings, roles, permissions
    ├── 03_security.sql    # Security: policies for password/session
    ├── 04_users.sql       # Users & theme preferences
    ├── 05_clients.sql     # Clients & affiliates
    ├── 06_contracts.sql   # Contracts, categories, subcategories
    ├── 07_audit.sql       # Audit logs & permissions
    └── 08_financial.sql   # Financial tracking & installments
```

### Execution Order

Files are executed **alphabetically** by PostgreSQL and the Go backend:

1. **01_extensions.sql** → PostgreSQL extensions
2. **02_core.sql** → Foundation tables (roles, permissions)
3. **03_security.sql** → Password/session policies + security permissions
4. **04_users.sql** → User accounts + theme settings
5. **05_clients.sql** → Clients & affiliates + their permissions
6. **06_contracts.sql** → Contracts & categories + their permissions
7. **07_audit.sql** → Audit logs + audit permissions
8. **08_financial.sql** → Financial data + financial permissions

---

## Module Details

### 01_extensions.sql
**Purpose**: Load required PostgreSQL extensions

**Creates**:
- `citext` extension (case-insensitive text type)

---

### 02_core.sql
**Purpose**: Core infrastructure for roles, permissions, and system settings

**Creates Tables**:
- `system_settings` - Global system configuration
- `roles` - User roles (root, admin, user, viewer)
- `permissions` - Available permissions
- `role_permissions` - Role-permission mappings

**Inserts**:
- 4 system roles with priority levels
- 13 system permissions (settings, roles, theme, dashboard)
- Role-permission mappings for core resources
- System settings for UI/theme defaults

**Key Features**:
- Roles have priority levels (100=root, 50=admin, 10=user, 1=viewer)
- System roles (`is_system=true`) cannot be deleted
- Permissions use UNIQUE(resource, action) constraint

---

### 03_security.sql
**Purpose**: Password policies, session management, and security permissions

**Creates Tables**:
- `role_password_policies` - Password rules per role
- `role_session_policies` - Session duration per role
- `password_history` - Prevent password reuse
- `login_attempts` - IP-based brute force protection

**Inserts**:
- 5 security permissions (password policy, session policy, lock policy, rate limit, security logs)
- Password policies per role (root=strictest, viewer=lenient)
- Session policies (root: 60min, admin: 60min, user: 60min, viewer: 60min)
- Role-permission mappings for security

**Key Features**:
- ROOT: 24 character min, requires uppercase/lowercase/numbers/special + history
- Password expiration configurable per role
- Session timeout and max concurrent sessions

---

### 04_users.sql
**Purpose**: User accounts and personalization

**Creates Tables**:
- `users` - User accounts with auth tracking
- `user_theme_settings` - Per-user theme customization

**Inserts**:
- 13 user permissions (create, read, update, delete, block, manage_roles, etc.)
- Role-permission mappings (ROOT=all, ADMIN=all except manage_roles, etc.)

**Key Features**:
- Users track last login, failed attempts, lock status
- Theme settings support 60+ color presets
- Accessibility modes (high contrast, color blind, dyslexic font)

---

### 05_clients.sql
**Purpose**: Client management and their sub-organizations

**Creates Tables**:
- `clients` - Primary clients
- `affiliates` - Sub-organizations linked to clients

**Inserts**:
- 6 permissions for clients (create, read, update, delete, archive, export)
- 4 permissions for affiliates
- Role-permission mappings:
  - ROOT/ADMIN: full access
  - USER: create, read, update, archive (no delete)
  - VIEWER: read-only

**Key Features**:
- Clients can have multiple affiliates
- Unique index on name when no registration_id exists
- Status tracking (ativo, inativo)
- Soft-delete via `archived_at`

---

### 06_contracts.sql
**Purpose**: Contract management with hierarchical categorization

**Creates Tables**:
- `categories` - Contract categories
- `subcategories` - Subcategories within categories
- `contracts` - Actual contracts linked to clients

**Inserts**:
- 5 permissions for categories
- 4 permissions for subcategories
- 6 permissions for contracts (create, read, update, delete, archive, export)
- Role-permission mappings (same pattern as clients)

**Key Features**:
- Contracts link to clients and subcategories
- Unique item_key per contract (with custom index handling nulls)
- Soft-delete via `archived_at`
- End-date tracking for expiration notifications

---

### 07_audit.sql
**Purpose**: Comprehensive audit logging and compliance

**Creates Tables**:
- `audit_logs` - Complete action history with request context

**Inserts**:
- 6 permissions (read, read_all, read_own, export, delete, configure)
- Role-permission mappings:
  - ROOT: all
  - ADMIN: all except delete
  - USER: read_own only
  - VIEWER: none

**Key Features**:
- Tracks operation, resource, admin, old/new values
- IP address and user agent logging
- HTTP request metadata (method, path, status, duration)
- `object_name` column for human-readable audit (e.g., client name)
- Indexed by timestamp, resource, admin_id, status

---

### 08_financial.sql
**Purpose**: Financial tracking, payment terms, and installments

**Creates Tables**:
- `contract_financial` - Payment models (unique, recurring, custom)
- `financial_installments` - Individual payment parcels

**Inserts**:
- 8 permissions (create, read, update, delete, mark_paid, read_values, update_values, export)
- Role-permission mappings:
  - ROOT/ADMIN: all
  - USER: create, read, update, mark_paid (no delete, no values)
  - VIEWER: read only

**Views**:
- `v_contract_financial_summary` - Financial overview per contract
- `v_upcoming_financial` - Upcoming payment deadlines
- `v_monthly_financial` - Monthly cash flow analysis
- `v_financial_period_summary` - Last/current/next month

**Key Features**:
- Three financial types:
  - `unico` - One-time payment
  - `recorrente` - Recurring (monthly, quarterly, annual)
  - `personalizado` - Custom with multiple installments
- Installment status: pendente, pago, atrasado, cancelado
- Separate values for client_value vs received_value

---

## Permissions Overview

### Distribution

| Category | Count | Modules |
|----------|-------|---------|
| Sistema | 13 | core, roles, settings |
| Usuários | 13 | users |
| Clientes | 6 | clients |
| Filiais | 4 | affiliates |
| Contratos | 6 | contracts |
| Categorias | 9 | categories, subcategories |
| Auditoria | 6 | audit_logs |
| Segurança | 5 | security policies |
| Aparência | 4 | theme |
| Dashboard | 3 | dashboard |
| Financeiro | 8 | financial |
| **Total** | **77** | **All modules** |

### Role Mappings

| Role | Permissions | Use Case |
|------|-------------|----------|
| **root** | 77 (100%) | System administrator - full access |
| **admin** | 62 (81%) | Manager - no system/security config |
| **user** | 21 (27%) | Operator - create/edit, no delete |
| **viewer** | 8 (10%) | Read-only - view contracts, clients, financials |

---

## Initialization

### Automatic (Recommended)

**Docker Compose**:
```bash
cd deploy/docker
docker compose up postgres
# PostgreSQL automatically executes schema files in /docker-entrypoint-initdb.d
```

**Backend App**:
```bash
# Backend automatically calls InitDB() on startup
# Skips init if database is already initialized
go run ./main.go
```

### Manual (Local Development)

**One-command initialization**:
```bash
cd backend/database
psql -d your_db_name -f init.sql
```

**Step-by-step**:
```bash
cd backend/database/schema
psql -d your_db_name -f 01_extensions.sql
psql -d your_db_name -f 02_core.sql
psql -d your_db_name -f 03_security.sql
# ... continue with remaining files
```

### Reset Database

**Dev environment**:
```bash
cd deploy/dev
make db-reset  # Prompts for confirmation
```

This will:
1. Terminate all connections
2. Drop the database
3. Create empty database
4. Backend will re-initialize on next start

---

## Key Tables Reference

### users
```sql
id UUID PRIMARY KEY
username CITEXT UNIQUE
password_hash VARCHAR(255)
role_id UUID REFERENCES roles(id)
failed_attempts INTEGER
lock_level INTEGER
locked_until TIMESTAMP
created_at TIMESTAMP
```

### clients
```sql
id UUID PRIMARY KEY
name CITEXT UNIQUE (when registration_id IS NULL)
registration_id CITEXT UNIQUE
email CITEXT
status VARCHAR(50) -- 'ativo', 'inativo'
archived_at TIMESTAMP -- soft-delete
```

### contracts
```sql
id UUID PRIMARY KEY
model CITEXT
item_key CITEXT UNIQUE
client_id UUID REFERENCES clients(id)
subcategory_id UUID REFERENCES subcategories(id)
start_date TIMESTAMP
end_date TIMESTAMP
archived_at TIMESTAMP -- soft-delete
```

### permissions
```sql
id UUID PRIMARY KEY
resource VARCHAR(100) -- 'clients', 'contracts', 'users', etc
action VARCHAR(50) -- 'create', 'read', 'update', 'delete', etc
display_name VARCHAR(255)
category VARCHAR(100) -- 'Clientes', 'Contratos', etc
UNIQUE(resource, action)
```

### role_permissions
```sql
role_id UUID REFERENCES roles(id)
permission_id UUID REFERENCES permissions(id)
PRIMARY KEY (role_id, permission_id)
```

### audit_logs
```sql
id UUID PRIMARY KEY
timestamp TIMESTAMP
operation VARCHAR(50) -- 'CREATE', 'UPDATE', 'DELETE'
resource VARCHAR(50) -- 'contracts', 'clients', etc
resource_id VARCHAR(255)
object_name VARCHAR(255) -- Human-readable name
admin_id UUID REFERENCES users(id)
old_value TEXT
new_value TEXT
status VARCHAR(20) -- 'success', 'error'
ip_address VARCHAR(45)
```

---

## Security Considerations

### Password Policies
- **Root**: 24 char min, require uppercase/lowercase/numbers/special, expires 90 days, history of 5
- **Admin**: 16 char min, require all 4 types, expires 180 days, history of 3
- **User**: 12 char min, require all 4 types, no expiration, history of 0
- **Viewer**: 12 char min, require all 4 types, no expiration

### Brute Force Protection
- IP-based rate limiting on login attempts
- Account lock escalates through 3 levels
- Logs all failed attempts with IP address

### Audit Trail
- Every action logged with user, IP, request details
- Soft-delete via `archived_at` (not removed)
- Immutable audit logs

---

## Performance Notes

### Indexes
- Timestamp descending on `audit_logs` for recent activity queries
- Composite index on (resource, resource_id) for audit searches
- Unique indexes with WHERE clauses for nullable columns
- Foreign key indexes automatically created

### Connection Pool
- Configured via environment variables
- Default: max_open_conns=25, max_idle_conns=5
- Connection max lifetime: 5 minutes

### Queries
- Use CITEXT for case-insensitive name searches
- Soft-deletes (archived_at IS NULL) in WHERE clauses
- Views provided for common reports (financials, audit)

---

## Common Tasks

### Create a new module (e.g., `09_invoices.sql`)

1. **Create file**: `backend/database/schema/09_invoices.sql`
2. **Add DDL**: Create tables with proper foreign keys
3. **Add permissions**: Insert rows into `permissions` table
4. **Add role mappings**: Insert rows into `role_permissions`
5. **Use ON CONFLICT**: Ensure idempotency
6. **Test**: Run `make db-reset` and verify

### Add a permission to existing role

```sql
INSERT INTO role_permissions (role_id, permission_id)
SELECT 'a0000000-0000-0000-0000-000000000003', id FROM permissions
WHERE resource = 'clients' AND action = 'export'
ON CONFLICT DO NOTHING;
```

### Check what a role can do

```sql
SELECT p.resource, p.action, p.display_name
FROM role_permissions rp
JOIN permissions p ON p.id = rp.permission_id
WHERE rp.role_id = 'a0000000-0000-0000-0000-000000000003' -- user role
ORDER BY p.resource, p.action;
```

### View recent audit activity

```sql
SELECT timestamp, operation, resource, object_name, admin_username, status
FROM audit_logs
WHERE timestamp > now() - interval '1 day'
ORDER BY timestamp DESC
LIMIT 100;
```

---

## Troubleshooting

### "Relation does not exist"
- Ensure `InitDB()` was called or schema files were executed
- Check file execution order (must be alphabetical)

### Duplicate key violations
- Schema files use `ON CONFLICT DO UPDATE` for idempotency
- Safe to re-run if interrupted

### Permission denied
- Verify user has `CONNECT` on database
- Check role-based access (different from DB roles)

### Foreign key constraint violation
- Check insertion order in script (dependencies first)
- Verify parent records exist

---

## Further Reading

- PostgreSQL documentation: https://www.postgresql.org/docs/16/
- CITEXT extension: https://www.postgresql.org/docs/16/citext.html
- Connection pooling best practices: https://wiki.postgresql.org/wiki/Number_Of_Database_Connections
