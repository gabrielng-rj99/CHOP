# Architecture — Entity Hub Open Project

Technical overview of the system, design patterns, and development guidelines.

## System Overview

Entity Hub is a flexible entity management system with a Go backend API and React frontend. The architecture follows a layered approach with clear separation of concerns.

```
┌─────────────────────────────────────────────────────────────┐
│                      Frontend (React)                        │
│                  TypeScript + Vite + TailwindCSS             │
├─────────────────────────────────────────────────────────────┤
│                       API Gateway                            │
│                    (NGINX / Direct)                          │
├─────────────────────────────────────────────────────────────┤
│                      Backend (Go)                            │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │   Handlers  │  │ Middleware  │  │   JWT Auth          │  │
│  │   (HTTP)    │  │ (CORS/Auth) │  │   (Token Mgmt)      │  │
│  └──────┬──────┘  └──────┬──────┘  └──────────┬──────────┘  │
│         │                │                     │             │
│  ┌──────┴────────────────┴─────────────────────┴──────────┐ │
│  │                     Store Layer                         │ │
│  │  (Business Logic + Data Access + Validations)          │ │
│  └────────────────────────┬────────────────────────────────┘ │
│                           │                                   │
│  ┌────────────────────────┴────────────────────────────────┐ │
│  │                  Domain Models                           │ │
│  │            (User, Client, Contract, etc.)               │ │
│  └─────────────────────────────────────────────────────────┘ │
├─────────────────────────────────────────────────────────────┤
│                    PostgreSQL Database                       │
└─────────────────────────────────────────────────────────────┘
```

## Directory Structure

```
Entity-Hub-Open-Project/
├── backend/
│   ├── cmd/
│   │   ├── server/           # HTTP server entry point
│   │   ├── cli/              # CLI tools entry point
│   │   └── tools/            # Utility tools
│   ├── server/
│   │   ├── server.go         # Server initialization
│   │   ├── routes.go         # Route registration
│   │   ├── auth_handlers.go  # Login, refresh token
│   │   ├── users_handlers.go # User CRUD
│   │   ├── jwt_utils.go      # JWT creation/validation
│   │   └── *_handlers.go     # Entity handlers
│   ├── store/
│   │   ├── user_store.go     # User business logic
│   │   ├── client_store.go   # Client business logic
│   │   ├── contract_store.go # Contract business logic
│   │   └── *_store.go        # Other entity stores
│   ├── domain/
│   │   └── models.go         # Domain entities
│   ├── database/
│   │   ├── database.go       # Connection management
│   │   └── schema.sql        # Database schema
│   └── config/
│       └── config.go         # Configuration loading
├── frontend/
│   └── src/
│       ├── components/       # React components
│       ├── pages/            # Page components
│       ├── services/         # API client
│       └── hooks/            # Custom hooks
├── deploy/
│   ├── docker/               # Docker configurations
│   ├── scripts/              # Deployment scripts
│   └── docs/                 # Deployment documentation
└── tests/
    ├── conftest.py           # Pytest fixtures
    ├── test_*.py             # Test modules
    └── docker-compose.test.yml
```

## Core Components

### Authentication & Authorization

#### JWT Implementation

```go
// Token structure with user-specific signing
type JWTClaims struct {
    UserID   string `json:"user_id"`
    Username string `json:"username"`
    Role     string `json:"role"`
    jwt.RegisteredClaims
}

// Signing key = GlobalSecret + UserAuthSecret
// This allows per-user token invalidation
```

#### Middleware Stack

```
Request
   │
   ▼
┌─────────────────┐
│  CORS Middleware │ ─→ Handles cross-origin requests
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Auth Middleware │ ─→ Validates JWT token
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Admin Middleware │ ─→ Checks admin/root role (for /api/users)
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│     Handler     │ ─→ Processes request
└─────────────────┘
```

#### Role-Based Access Control

| Role | Access Level |
|------|--------------|
| `root` | Full access, can create/manage all users, view audit logs |
| `admin` | Can manage users (except root), full entity access |
| `user` | Limited access (configurable per deployment) |

### Store Layer Pattern

Each entity has a dedicated store that handles:

1. **Business Logic**: Validation, authorization checks
2. **Data Access**: SQL queries with prepared statements
3. **Audit Integration**: Logging operations

```go
type UserStore struct {
    db *sql.DB
}

func (s *UserStore) CreateUser(username, displayName, password, role string) (string, error) {
    // 1. Validate inputs
    if err := ValidateUsername(username); err != nil {
        return "", err
    }
    
    // 2. Validate password strength
    if err := ValidateStrongPassword(password); err != nil {
        return "", err
    }
    
    // 3. Check role validity
    if role != "user" && role != "admin" && role != "root" {
        return "", errors.New("invalid role")
    }
    
    // 4. Hash password and create user
    // ... database operations ...
}
```

### Security Implementations

#### Password Validation

```go
func ValidateStrongPassword(password string) error {
    if len(password) < 16 {
        return errors.New("password must be at least 16 characters")
    }
    if strings.Contains(password, " ") {
        return errors.New("password cannot contain spaces")
    }
    // Must have: uppercase, lowercase, number, special char
    // ...
}
```

#### Brute Force Protection

```go
type User struct {
    // ...
    FailedAttempts int        // Counter for failed logins
    LockLevel      int        // 0, 1, 2 - progressive lockout
    LockedUntil    *time.Time // When the lock expires
}

// Lock durations increase with each level:
// Level 1: 5 minutes
// Level 2: 15 minutes
// Level 3: 60 minutes
```

#### SQL Injection Prevention

- All queries use prepared statements
- No string concatenation for SQL
- Input validation at multiple layers

```go
// ✓ Correct - parameterized query
query := "SELECT * FROM users WHERE username = $1"
row := db.QueryRow(query, username)

// ✗ Wrong - never do this
query := "SELECT * FROM users WHERE username = '" + username + "'"
```

## Data Model

### Entity Relationships

```
┌──────────────┐
│   Users      │ ─── Authentication & Authorization
└──────────────┘

┌──────────────┐       ┌──────────────┐
│  Categories  │──1:N──│    Lines     │
└──────────────┘       └──────┬───────┘
                              │
                              │ 1:N
                              ▼
┌──────────────┐       ┌──────────────┐
│   Clients    │──1:N──│  Contracts   │
└──────┬───────┘       └──────────────┘
       │
       │ 1:N
       ▼
┌──────────────┐
│  Dependents  │ ─── Optional client subsidiaries
└──────────────┘

┌──────────────┐
│  Audit Logs  │ ─── All operations logged (root only access)
└──────────────┘
```

### Key Constraints

- `username` is unique per user (case-insensitive via CITEXT)
- `registration_id` (CNPJ) is unique per client
- Contracts cannot overlap for the same client/line combination
- Soft delete via `archived_at` / `deleted_at` timestamps

## API Design

### Request/Response Format

All responses follow a consistent structure:

```json
// Success response
{
    "message": "User created successfully",
    "data": {
        "id": "uuid-here"
    }
}

// Error response
{
    "error": "Validation failed",
    "details": ["Username is required", "Password too weak"]
}
```

### Authentication Flow

```
1. POST /api/login
   ├── Validate credentials
   ├── Check account lock status
   ├── Generate JWT with user's auth_secret
   └── Return token + refresh token

2. Authenticated Request
   ├── Extract token from Authorization header
   ├── Validate signature using user's current auth_secret
   ├── Check token expiration
   └── Process request

3. POST /api/refresh-token
   ├── Validate refresh token
   ├── Generate new access token
   └── Return new tokens
```

### Endpoint Security Matrix

| Endpoint | Public | User | Admin | Root |
|----------|--------|------|-------|------|
| `/health` | ✓ | ✓ | ✓ | ✓ |
| `/api/login` | ✓ | ✓ | ✓ | ✓ |
| `/api/initialize/*` | ✓ | - | - | - |
| `/api/users` | - | - | ✓ | ✓ |
| `/api/clients` | - | ✓ | ✓ | ✓ |
| `/api/audit-logs` | - | - | - | ✓ |

## Testing Strategy

### Test Categories

1. **Unit Tests** (Go): Store layer, validation functions
2. **Security Tests** (Python/pytest): OWASP Top 10 coverage
3. **Integration Tests**: API endpoint testing
4. **E2E Tests**: Full stack testing

### Security Test Suite

```
tests/
├── test_jwt_security.py      # Token manipulation attacks
├── test_sql_injection.py     # SQLi payloads
├── test_xss_security.py      # XSS prevention
├── test_authorization.py     # RBAC enforcement
├── test_password_validation.py
├── test_input_validation.py
├── test_login_blocking.py    # Brute force protection
└── test_data_leakage.py      # Sensitive data exposure
```

### Test Environment

```yaml
# docker-compose.test.yml
services:
  test_db:
    port: 65432
  test_backend:
    port: 63000
  test_frontend:
    port: 65080
```

## Deployment

### Docker Architecture

```
┌─────────────────────────────────────────────┐
│               Docker Network                 │
│                                             │
│  ┌─────────┐  ┌──────────┐  ┌───────────┐  │
│  │ NGINX   │──│ Backend  │──│ PostgreSQL│  │
│  │ :8081   │  │ :3000    │  │ :5432     │  │
│  └─────────┘  └──────────┘  └───────────┘  │
│       │                                     │
│  ┌────┴────┐                               │
│  │Frontend │                               │
│  │(static) │                               │
│  └─────────┘                               │
└─────────────────────────────────────────────┘
```

### Configuration Hierarchy

1. Environment variables (highest priority)
2. Config file (config.ini)
3. Default values (code)

## Development Guidelines

### Adding a New Entity

1. Define model in `domain/models.go`
2. Create store in `store/new_entity_store.go`
3. Write tests in `store/new_entity_test.go`
4. Add handlers in `server/new_entity_handlers.go`
5. Register routes in `server/routes.go`
6. Update database schema

### Code Style

- **Go**: Follow standard Go formatting (`go fmt`)
- **Naming**: PascalCase for exports, camelCase for internal
- **Errors**: Descriptive messages, no generic "error" responses
- **Comments**: Explain "why", not "what"

### Security Checklist

- [ ] All inputs validated
- [ ] SQL uses prepared statements
- [ ] Sensitive data excluded from JSON (`json:"-"`)
- [ ] Authorization checks in handlers
- [ ] Audit logging for mutations
- [ ] Rate limiting considered

## References

- [Go Code Review Comments](https://github.com/golang/go/wiki/CodeReviewComments)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [PostgreSQL Documentation](https://www.postgresql.org/docs/)
- [JWT Best Practices](https://auth0.com/blog/jwt-security-best-practices/)