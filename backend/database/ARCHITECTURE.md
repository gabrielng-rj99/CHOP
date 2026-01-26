# Database Architecture

## Entity Relationship Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           CORE INFRASTRUCTURE                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                               │
│  ┌──────────────────┐      ┌──────────────────┐      ┌──────────────────┐  │
│  │   system_        │      │     roles        │      │   permissions    │  │
│  │  settings        │      │                  │      │                  │  │
│  │                  │      │  id (UUID)       │      │  id (UUID)       │  │
│  │  key (PK)        │      │  name (CITEXT)   │      │  resource (50)   │  │
│  │  value (TEXT)    │      │  priority (INT)  │      │  action (50)     │  │
│  │  category        │      │  is_system (BOOL)│      │  display_name    │  │
│  │                  │      │                  │      │  category        │  │
│  └──────────────────┘      └──────┬───────────┘      └────────┬─────────┘  │
│                                    │                          │              │
│                            ┌───────┴──────────────────────────┴────────┐    │
│                            │                                          │    │
│                            ▼                                          ▼    │
│                      ┌─────────────────┐                    ┌─────────────────┐
│                      │ role_           │                    │ (UNIQUE         │
│                      │ permissions     │                    │  resource,      │
│                      │                 │                    │  action)        │
│                      │ role_id (FK)    │                    │                 │
│                      │ permission_id   │────────────────────┘                 │
│                      │ (FK)            │                                      │
│                      └─────────────────┘                                      │
│                                                                               │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│                            USERS & SECURITY                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                               │
│  ┌──────────────────────┐        ┌──────────────────────┐                   │
│  │      users           │        │  user_theme_        │                   │
│  │                      │        │  settings            │                   │
│  │  id (UUID, PK)       │        │                      │                   │
│  │  username (CITEXT)   │◄──────►│  user_id (UUID, FK) │                   │
│  │  password_hash       │        │  theme_preset       │                   │
│  │  role_id (FK)──────┐ │        │  primary_color      │                   │
│  │  failed_attempts     │ │        │  secondary_color    │                   │
│  │  lock_level          │ │        │  accessibility_     │                   │
│  │  locked_until        │ │        │  settings           │                   │
│  │  last_login_at       │ │        │                     │                   │
│  │  created_at          │ │        └─────────────────────┘                   │
│  └──────────────────────┘ │                                                   │
│                           │      roles                                       │
│                           └──────(from core)                                 │
│                                                                               │
│  ┌──────────────────────────────────────────────────────────────────┐       │
│  │                      SECURITY POLICIES                          │       │
│  │                                                                  │       │
│  │  ┌──────────────────┐    ┌──────────────────┐                  │       │
│  │  │ role_password_   │    │ role_session_    │                  │       │
│  │  │ policies         │    │ policies         │                  │       │
│  │  │                  │    │                  │                  │       │
│  │  │ role_id (FK)──┐  │    │ role_id (FK)──┐  │                  │       │
│  │  │ min_length     │  │    │ session_       │  │                  │       │
│  │  │ max_age_days   │  │    │ duration_min   │  │                  │       │
│  │  │ history_count  │  │    │ max_concurrent │  │                  │       │
│  │  │                │  │    │ _sessions      │  │                  │       │
│  │  └────────────────┘  │    └────────────────┘  │                  │       │
│  │           │           │           │            │                  │       │
│  │           └───────────┴───────────┘            │                  │       │
│  │                  │                            │                  │       │
│  │                  ▼                            │                  │       │
│  │        ┌──────────────────┐                   │                  │       │
│  │        │ password_        │                   │                  │       │
│  │        │ history          │                   │                  │       │
│  │        │                  │                   │                  │       │
│  │        │ user_id (FK)     │                   │                  │       │
│  │        │ password_hash    │                   │                  │       │
│  │        │ created_at       │                   │                  │       │
│  │        └──────────────────┘                   │                  │       │
│  │                                               │                  │       │
│  │  ┌──────────────────────────┐                 │                  │       │
│  │  │ login_attempts          │                 │                  │       │
│  │  │                          │                 │                  │       │
│  │  │ ip_address (PK)          │                 │                  │       │
│  │  │ failed_attempts          │                 │                  │       │
│  │  │ lock_level               │                 │                  │       │
│  │  │ locked_until             │                 │                  │       │
│  │  └──────────────────────────┘                 │                  │       │
│  └──────────────────────────────────────────────┘                  │       │
│                                                                     │       │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│                          BUSINESS ENTITIES                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                               │
│  ┌──────────────────┐         ┌──────────────────┐                          │
│  │    clients       │         │   affiliates     │                          │
│  │                  │         │                  │                          │
│  │ id (UUID, PK)    │◄────────┤ client_id (FK)   │                          │
│  │ name (CITEXT)    │         │ id (UUID, PK)    │                          │
│  │ registration_id  │         │ name (CITEXT)    │                          │
│  │ email (CITEXT)   │         │ email (CITEXT)   │                          │
│  │ status           │         │ status           │                          │
│  │ archived_at      │         │                  │                          │
│  │ created_at       │         └──────────────────┘                          │
│  └────────┬─────────┘                                                        │
│           │                                                                  │
│           │                                                                  │
│           ▼                                                                  │
│  ┌──────────────────────────────────────────────────────┐                   │
│  │                   contracts                          │                   │
│  │                                                      │                   │
│  │  id (UUID, PK)                                       │                   │
│  │  model (CITEXT)                                      │                   │
│  │  item_key (CITEXT, UNIQUE)                           │                   │
│  │  client_id (FK) ──────────────────┐                 │                   │
│  │  affiliate_id (FK, nullable) ──┐  │                 │                   │
│  │  subcategory_id (FK) ──┐       │  │                 │                   │
│  │  start_date             │       │  │                 │                   │
│  │  end_date               │       │  │                 │                   │
│  │  archived_at            │       │  │                 │                   │
│  └────────────────────────┬───────┼──┼─────────────────┘                   │
│                           │       │  │                                      │
│                ┌──────────┘       │  └─affiliates                           │
│                │                  └─clients                                 │
│                ▼                                                             │
│  ┌─────────────────────────┐                                                │
│  │  subcategories          │                                                │
│  │                         │                                                │
│  │  id (UUID, PK)          │                                                │
│  │  name (CITEXT)          │                                                │
│  │  category_id (FK) ──┐   │                                                │
│  │  archived_at        │   │                                                │
│  └─────────────────────┼───┘                                                │
│                        │                                                     │
│                        ▼                                                     │
│              ┌──────────────────┐                                            │
│              │  categories      │                                            │
│              │                  │                                            │
│              │  id (UUID, PK)   │                                            │
│              │  name (CITEXT)   │                                            │
│              │  status          │                                            │
│              │  archived_at     │                                            │
│              └──────────────────┘                                            │
│                                                                               │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│                       FINANCIAL TRACKING                                    │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                               │
│  ┌──────────────────────────────┐                                            │
│  │  contract_financial          │                                            │
│  │                              │                                            │
│  │  id (UUID, PK)               │                                            │
│  │  contract_id (FK) ──────┐    │                                            │
│  │  financial_type:        │    │                                            │
│  │    - unico              │    │                                            │
│  │    - recorrente         │    │                                            │
│  │    - personalizado      │    │                                            │
│  │  recurrence_type:       │    │                                            │
│  │    - mensal             │    │                                            │
│  │    - trimestral         │    │                                            │
│  │    - semestral          │    │                                            │
│  │    - anual              │    │                                            │
│  │  client_value           │    │                                            │
│  │  received_value         │    │                                            │
│  │  is_active              │    │                                            │
│  │  created_at             │    │                                            │
│  └────────┬─────────────────┼───┘                                            │
│           │                 │                                                │
│           │                 └─contracts                                      │
│           │                                                                  │
│           ▼                                                                  │
│  ┌──────────────────────────────┐                                            │
│  │  financial_installments      │                                            │
│  │                              │                                            │
│  │  id (UUID, PK)               │                                            │
│  │  contract_financial_id (FK)  │                                            │
│  │  installment_number          │                                            │
│  │  installment_label           │                                            │
│  │  client_value                │                                            │
│  │  received_value              │                                            │
│  │  due_date                    │                                            │
│  │  paid_at (nullable)          │                                            │
│  │  status:                      │                                            │
│  │    - pendente                │                                            │
│  │    - pago                    │                                            │
│  │    - atrasado                │                                            │
│  │    - cancelado               │                                            │
│  │  created_at                  │                                            │
│  └──────────────────────────────┘                                            │
│                                                                               │
│  VIEWS:                                                                      │
│  - v_contract_financial_summary                                             │
│  - v_upcoming_financial                                                     │
│  - v_monthly_financial                                                      │
│  - v_financial_period_summary                                               │
│                                                                               │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│                         AUDIT & COMPLIANCE                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                               │
│  ┌──────────────────────────────────────────────────────┐                   │
│  │              audit_logs                             │                   │
│  │                                                      │                   │
│  │  id (UUID, PK)                                       │                   │
│  │  timestamp (DESC indexed)                            │                   │
│  │  operation (CREATE, UPDATE, DELETE)                  │                   │
│  │  resource (clients, contracts, users, etc)           │                   │
│  │  resource_id                                         │                   │
│  │  object_name (human-readable: "Client ABC Ltd")      │                   │
│  │  admin_id (FK) ─────┐                               │                   │
│  │  admin_username     │                               │                   │
│  │  old_value          │                               │                   │
│  │  new_value          │                               │                   │
│  │  status (success/error)                              │                   │
│  │  error_message                                       │                   │
│  │  ip_address                                          │                   │
│  │  user_agent                                          │                   │
│  │  request_method (GET, POST, PUT, DELETE)             │                   │
│  │  request_path                                        │                   │
│  │  request_id                                          │                   │
│  │  response_code                                       │                   │
│  │  execution_time_ms                                   │                   │
│  │                                                      │                   │
│  │  Indexes:                                            │                   │
│  │  - timestamp DESC                                    │                   │
│  │  - (resource, resource_id)                           │                   │
│  │  - admin_id                                          │                   │
│  │  - operation                                         │                   │
│  │  - status                                            │                   │
│  │  - ip_address                                        │                   │
│  │  - object_name                                       │                   │
│  │                                                      │                   │
│  └────────┬───────────────────────────────────────────┘                   │
│           │                                                                  │
│           └─── references users(admin_id)                                   │
│                                                                               │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Data Flow Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    APPLICATION LAYER                             │
│  (Go Backend - main.go)                                         │
└────────────────────────────┬──────────────────────────────────┘
                             │
                             ▼
                    ┌────────────────────┐
                    │  InitDB() called   │
                    │  on startup        │
                    └────────┬───────────┘
                             │
                ┌────────────┴────────────┐
                │                         │
                ▼                         ▼
     ┌────────────────────┐    ┌────────────────────┐
     │ IsDatabaseInit()?  │    │ Already            │
     │ Check for tables   │    │ initialized?       │
     │ Check for roles    │    │ Skip schema init   │
     └────────┬───────────┘    └────────────────────┘
              │
              ├─ NO ──┐
              │       │
              │       ▼
              │  ┌──────────────────────────────────────┐
              │  │ Read schema/ directory               │
              │  │ Filter: *.sql except init.sql        │
              │  │ Sort alphabetically (01_, 02_, ..8_) │
              │  └────────────┬─────────────────────────┘
              │               │
              │               ▼
              │  ┌──────────────────────────────────────┐
              │  │ Execute each file in order:          │
              │  │ 01_extensions.sql                    │
              │  │ 02_core.sql                          │
              │  │ 03_security.sql                      │
              │  │ 04_users.sql                         │
              │  │ 05_clients.sql                       │
              │  │ 06_contracts.sql                     │
              │  │ 07_audit.sql                         │
              │  │ 08_financial.sql                     │
              │  └────────────┬─────────────────────────┘
              │               │
              │               ▼
              │  ┌──────────────────────────────────────┐
              │  │ Verify initialization:               │
              │  │ ✓ All tables created                 │
              │  │ ✓ Default roles inserted             │
              │  │ ✓ Permissions defined                │
              │  │ ✓ Ready for use                      │
              │  └──────────────────────────────────────┘
              │
              └─ YES ──┐
                       │
                       ▼
        ┌──────────────────────────┐
        │ Application running      │
        │ Ready to accept queries  │
        └──────────────────────────┘
```

## Module Dependency Graph

```
01_extensions.sql
        │
        ▼
    ┌─────────────────────┐
    │   02_core.sql       │ ◄─── Foundation (roles, permissions)
    └──────┬──────────────┘
           │
    ┌──────┴──────────────────────────┐
    │                                  │
    ▼                                  ▼
┌─────────────┐              ┌─────────────────┐
│ 03_security │              │  04_users.sql   │ ◄─── Auth & Theme
│ .sql        │              └────────┬────────┘
└──────┬──────┘                       │
       │                              │
       └──────────────┬───────────────┘
                      │
                      ▼
            ┌──────────────────┐
            │  05_clients.sql  │ ◄─── CRM (clients, affiliates)
            └────────┬─────────┘
                     │
                     ▼
            ┌──────────────────┐
            │  06_contracts    │ ◄─── Contracts & categorization
            │  .sql            │
            └────────┬─────────┘
                     │
          ┌──────────┴───────────┐
          │                      │
          ▼                      ▼
   ┌──────────────┐      ┌──────────────┐
   │ 07_audit.sql │      │08_financial  │ ◄─── Financial & audit
   └──────────────┘      └──────────────┘

All modules depend on: 01_extensions + 02_core
Module execution is idempotent (ON CONFLICT DO UPDATE)
```

## Permission Hierarchy

```
ROOT (Priority: 100)
├─ Can manage everything
├─ Cannot be deleted
├─ 77 permissions total
└─ Examples: system settings, security policies, user roles

    ADMIN (Priority: 50)
    ├─ Cannot access: roles, security config, delete audit logs
    ├─ 62 permissions (81%)
    └─ Examples: create users, manage clients, export reports

        USER (Priority: 10)
        ├─ Cannot delete permanently, cannot see/edit sensitive values
        ├─ 21 permissions (27%)
        └─ Examples: create contracts, mark payments, view own activity

            VIEWER (Priority: 1)
            ├─ Read-only access to core entities
            ├─ 8 permissions (10%)
            └─ Examples: view clients, view contracts, view financials
```

## Key Design Patterns

### 1. Soft Deletes
- Uses `archived_at TIMESTAMP` instead of hard DELETE
- Query with `WHERE archived_at IS NULL`
- Preserves audit trail and referential integrity

### 2. Idempotent Schema
- All INSERT statements use `ON CONFLICT DO UPDATE`
- Safe to re-run multiple times
- Useful for migrations and rollbacks

### 3. Role-Based Access Control (RBAC)
- Three-table pattern: roles → role_permissions → permissions
- Flexible permission assignment
- Easy to add new permissions and grant selectively

### 4. Immutable Audit Logs
- All changes logged in `audit_logs`
- Includes before/after values in `old_value`/`new_value`
- Cannot be deleted (only root can via manual query)

### 5. Case-Insensitive Text
- Uses PostgreSQL `CITEXT` type for names/emails
- Case-insensitive comparisons without LOWER()
- Better UX for user-facing fields

### 6. Modular Schema Evolution
- Each file is a self-contained business domain
- Adding new modules doesn't affect existing ones
- Clear separation of concerns

## Foreign Key Relationships

```
STRONG REFERENCES (ON DELETE CASCADE):
- affiliates → clients
- contracts → clients
- contracts → subcategories
- contracts → affiliates
- contract_financial → contracts
- financial_installments → contract_financial
- password_history → users (via FK setup)
- role_permissions → roles
- role_permissions → permissions
- role_password_policies → roles
- role_session_policies → roles

WEAK REFERENCES (ON DELETE SET NULL):
- users → roles (role_id can be NULL)
- audit_logs → users (admin_id can be NULL for system actions)
```

## Scaling Considerations

### Current Capacity
- Designed for ~10K users
- Audit logs can grow to millions of rows (indexed appropriately)
- Soft deletes mean archived records stay in database

### Future Optimization
- Consider partitioning `audit_logs` by date
- Archive old financial data to separate schema
- Add read replicas for reporting queries
- Implement connection pooling via PgBouncer

### Backup Strategy
- Full backups recommended daily
- Incremental WAL backups recommended hourly
- Test restore procedures regularly
- Soft deletes prevent accidental data loss
