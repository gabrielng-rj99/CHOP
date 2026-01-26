# Backend Architecture Documentation

## Project Structure

```
backend/
├── main.go                   # Application entry point
├── config/
│   └── config.go             # Configuration management (INI + env vars)
├── database/
│   ├── connection.go         # PostgreSQL connection
│   ├── init.go               # Schema initialization
│   └── migrations/           # SQL migrations
├── domain/
│   └── models.go             # Business domain models and validation
├── http/
│   ├── server.go             # HTTP server struct and initialization
│   ├── routes.go             # Route registration and middlewares
│   ├── helpers.go            # Response helpers (respondJSON, respondError)
│   ├── jwt_utils.go          # JWT generation and validation
│   ├── middleware_logging.go # Request logging middleware
│   ├── middleware_security.go# Security headers, rate limiting, brute force
│   ├── *_handlers.go         # HTTP handlers organized by domain
│   └── *_test.go             # Handler and middleware tests
├── repository/
│   ├── store_interfaces.go   # Common interfaces (DBInterface)
│   ├── validation_helpers.go # Shared validation functions
│   ├── database_helpers.go   # Test setup/teardown helpers
│   ├── errors.go             # Common repository errors
│   ├── affiliate/            # Affiliate data access
│   ├── audit/                # Audit log data access
│   ├── category/             # Category & subcategory data access
│   ├── client/               # Client data access
│   ├── contract/             # Contract data access
│   ├── financial/            # Financial data access
│   ├── role/                 # Role data access
│   ├── settings/             # Settings & theme data access
│   ├── upload/               # Upload data access
│   └── user/                 # User data access
├── store/
│   └── store.go              # Compatibility layer re-exporting repository types
├── utils/
│   └── *.go                  # Shared utilities
├── uploads/                  # File upload directory
├── go.mod
├── go.sum
└── Makefile
```

## Architecture Principles

### 1. Package Organization

The codebase follows a layered architecture:

- **`http/`**: All HTTP-related code (handlers, middleware, routing, server)
- **`repository/`**: Domain-specific data access packages
- **`store/`**: Compatibility layer that re-exports repository types
- **`domain/`**: Business models and validation rules
- **`config/`**: Application configuration
- **`database/`**: Database connection and schema management

### 2. Repository Pattern

Each domain has its own package under `repository/`:

```
repository/
├── user/
│   ├── user_store.go         # UserStore implementation
│   └── user_test.go          # User store tests
├── client/
│   ├── client_store.go       # ClientStore implementation
│   └── client_test.go        # Client store tests
└── ...
```

Common interfaces and helpers are in the root `repository/` package:
- `DBInterface` - Database abstraction for testing
- `ValidateName`, `ValidateUsername` - Shared validation
- `NormalizeOptionalString`, `FormatCPFOrCNPJ` - Data normalization

### 3. Compatibility Layer

The `store/` package provides backward compatibility:

```go
import "Open-Generic-Hub/backend/store"

// These work:
store.NewUserStore(db)
store.AuditLogRequest{}
store.ValidateStrongPassword()
```

This allows existing code to continue working while the actual implementation lives in domain-specific packages.

### 4. Dependency Flow

```
main.go
    ↓
http.NewServer(db)
    ↓
http.SetupRoutes()
    ↓
net/http.ListenAndServe()
```

Dependencies flow one direction: `main.go` → `http` → `store` → `repository/*` → `database`

### 5. Layer Responsibilities

| Layer | Package | Responsibility |
|-------|---------|---------------|
| Entry | `main.go` | Load config, connect DB, start server |
| HTTP | `http` | Routing, middleware, handlers, JWT |
| Compatibility | `store` | Re-export types from repository |
| Data Access | `repository/*` | SQL queries, repository pattern |
| Domain | `domain` | Business models and validation |
| Config | `config` | Configuration from INI and environment |
| Database | `database` | Connection pooling, schema management |

## Key Files

### `main.go`
- Loads configuration
- Validates required secrets (JWT_SECRET, DB_PASSWORD)
- Connects to PostgreSQL
- Creates server instance with `httpserver.NewServer(db)`
- Starts HTTP server

### `http/server.go`
- Defines `Server` struct with all store dependencies
- `NewServer(db)` constructor
- `InitializeStores(db)` for hot-reload scenarios
- Global DB accessor for health checks

### `http/routes.go`
- `SetupRoutes()` - main entry point
- `registerRoutes()` - all route definitions
- Middleware chain: `corsMiddleware` → `standardMiddleware` → `authMiddleware` → handler

### `http/*_handlers.go`
Files organized by domain:
- `auth_handlers.go` - Login, refresh token
- `users_handlers.go` - User CRUD
- `clients_handlers.go` - Client management
- `contracts_handlers.go` - Contract management
- `affiliates_handlers.go` - Affiliate management
- `categories_handlers.go` - Category management
- `subcategories_handlers.go` - Subcategory management
- `financial_handlers.go` - Financial operations
- `audit_handlers.go` - Audit log viewing
- `role_handlers.go` - Role management
- `role_password_handlers.go` - Role password policies
- `role_session_handlers.go` - Role session policies
- `settings_handlers.go` - System settings
- `security_config_handlers.go` - Security configuration
- `dashboard_config_handlers.go` - Dashboard configuration
- `user_theme_handlers.go` - User theme preferences
- `upload_handlers.go` - File uploads
- `deploy_config.go` - Deployment panel
- `initialize_admin.go` - First-run admin setup

### `store/store.go`
Compatibility layer that re-exports:
- All store types (`UserStore`, `ClientStore`, etc.)
- Request/response types (`AuditLogRequest`, `AuditLogFilter`, etc.)
- Constructor functions (`NewUserStore`, `NewClientStore`, etc.)
- Validation functions (`ValidateStrongPassword`, `ValidateUsername`, etc.)
- Test helpers (`SetupTestDB`, `ClearTables`, `CloseDB`, etc.)

## Request Flow Example

```
GET /api/users/123

1. Request arrives at mux
2. corsMiddleware() - Set CORS headers
3. standardMiddleware() - Logging, rate limiting, security headers
4. authMiddleware() - Validate JWT, set user context
5. adminOnlyMiddleware() - Check admin role
6. handleUserByUsername() - Process request
7. respondJSON() - Send response
```

## Testing

### Run all tests
```bash
cd backend
go test ./...
```

### Run specific package tests
```bash
go test ./http/...
go test ./repository/user/...
go test ./repository/client/...
```

### Build check (no tests)
```bash
go build ./...
```

### Test files location
Tests are in the same package as the code they test:
- `http/handlers_test.go`
- `http/middleware_test.go`
- `http/security_test.go`
- `repository/user/user_test.go`
- `repository/client/client_test.go`

## Configuration

### Environment Variables (Required)
```bash
JWT_SECRET=<random-32-char-string>  # Required always
DB_PASSWORD=<database-password>      # Required in production
```

### config.ini (Optional overrides)
```ini
[app]
name = Client Hub
env = development

[server]
port = 8080
host = localhost

[database]
host = localhost
port = 5432
name = ehopdb_dev
user = postgres
```

## Building

### Development
```bash
cd backend
go run main.go
```

### Production binary
```bash
cd backend
go build -o bin/server main.go
./bin/server
```

### Docker
```bash
docker-compose up backend
```

## Adding a New Feature

### 1. Create repository package (if new entity)
```go
// repository/invoice/invoice_store.go
package invoicestore

import (
    "Open-Generic-Hub/backend/repository"
)

type DBInterface = repository.DBInterface

type InvoiceStore struct { db DBInterface }

func NewInvoiceStore(db DBInterface) *InvoiceStore {
    return &InvoiceStore{db: db}
}

func (s *InvoiceStore) GetByID(id string) (*domain.Invoice, error) {
    // SQL query
}
```

### 2. Add to store compatibility layer
```go
// store/store.go
import invoicestore "Open-Generic-Hub/backend/repository/invoice"

type InvoiceStore = invoicestore.InvoiceStore

func NewInvoiceStore(db *sql.DB) *InvoiceStore {
    return invoicestore.NewInvoiceStore(db)
}
```

### 3. Add store to server
```go
// http/server.go
type Server struct {
    // ... existing stores
    invoiceStore *invoicestore.InvoiceStore
}
```

### 4. Create handlers
```go
// http/invoice_handlers.go
package http

func (s *Server) handleInvoices(w http.ResponseWriter, r *http.Request) {
    // Handler logic
}
```

### 5. Register routes
```go
// http/routes.go in registerRoutes()
mux.HandleFunc("/api/invoices", s.standardMiddleware(s.authMiddleware(s.handleInvoices)))
```

### 6. Add tests
```go
// repository/invoice/invoice_test.go
package invoicestore

func TestGetByID(t *testing.T) {
    // Test logic
}
```

## Security

### Authentication
- JWT tokens with configurable expiration
- Refresh token support
- Token stored client-side (localStorage/cookie)

### Authorization
- Role-based: root, admin, user, viewer
- Middleware checks: `authMiddleware`, `adminOnlyMiddleware`, `rootOnlyMiddleware`
- Permission system with granular controls

### Rate Limiting
- IP-based rate limiting with progressive lockout
- Brute force protection with escalating timeouts
- Configurable limits in config.ini

### Headers
- Security headers via `securityHeadersMiddleware`
- CORS configuration per environment
- Content-Type validation

## Troubleshooting

### "JWT_SECRET not set"
```bash
export JWT_SECRET=$(openssl rand -base64 32)
```

### "Database connection failed"
```bash
# Check PostgreSQL is running
docker-compose ps

# Check connection params
echo $DB_HOST $DB_PORT $DB_USER $DB_NAME
```

### Build errors
```bash
# Clear module cache
go clean -modcache
go mod download
go build ./...
```

### Test failures
```bash
# Run with verbose output
go test -v ./http/...

# Skip DB-dependent tests
go test -short ./...
```

### Import cycle errors
When adding new code, ensure dependencies flow in one direction:
```
main.go → http → store → repository/* → domain
                                      → database
```
Never import `http` from `repository` or `store`.