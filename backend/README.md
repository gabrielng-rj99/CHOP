# Client Hub Open Project - Backend

**Language:** Go 1.21+  
**Database:** PostgreSQL 13+

## Quick Start

### Prerequisites
- Go 1.21+
- PostgreSQL 13+
- Docker & Docker Compose (recommended)

### Development Setup

```bash
# Clone the repository
git clone <repo-url>
cd Client-Hub-Open-Project/backend

# Set required environment variables
export JWT_SECRET=$(openssl rand -base64 32)
export DB_PASSWORD=postgres

# Start PostgreSQL (Docker)
docker-compose up -d postgres

# Build and run
go build -o chop-backend main.go
./chop-backend

# Or run directly
go run main.go
```

### Health Check
```bash
curl http://localhost:8080/health
```

## Project Structure

```
backend/
├── main.go               # Application entry point
├── config/               # Configuration management
├── database/             # PostgreSQL connection & schema
├── domain/               # Business models
├── repository/           # Domain-organized data access layer
│   ├── audit/
│   ├── category/
│   ├── client/
│   ├── contract/
│   ├── role/
│   ├── settings/
│   └── user/
├── server/               # HTTP server, routes, handlers, middleware
├── utils/                # Shared utilities
├── uploads/              # File upload directory
├── go.mod
├── go.sum
└── Makefile
```

## Architecture

See [BACKEND_ARCHITECTURE.md](./BACKEND_ARCHITECTURE.md) for detailed documentation.

### Key Packages

| Package | Responsibility |
|---------|---------------|
| `main.go` | Entry point - load config, connect DB, start server |
| `server` | HTTP routing, middleware, handlers, JWT |
| `repository/*` | Domain-organized data access layer |
| `domain` | Business models and validation |
| `config` | Configuration from INI files and environment |
| `database` | Connection pooling, schema management |

### Request Flow

```
HTTP Request → CORS → Logging → Rate Limit → Auth → Handler → Store → Database
```

## Configuration

### Required Environment Variables

```bash
JWT_SECRET=<random-32-char-string>   # Required always
DB_PASSWORD=<database-password>       # Required in production
```

### Optional Environment Variables

```bash
DB_HOST=localhost
DB_PORT=5432
DB_USER=postgres
DB_NAME=chopdb_dev
PORT=8080
```

## Development

### Build
```bash
go build -o chop-backend main.go
```

### Run Tests
```bash
go test ./...
```

### Run with Verbose Output
```bash
go test -v ./server/...
```

### Format Code
```bash
go fmt ./...
```

### Lint
```bash
go vet ./...
```

## Docker

### Start Services
```bash
docker-compose up -d
```

### View Logs
```bash
docker-compose logs -f backend
```

### Stop Services
```bash
docker-compose down
```

## API Endpoints

### Authentication
- `POST /api/login` - User login
- `POST /api/refresh-token` - Refresh JWT token

### Users (Admin+)
- `GET /api/users` - List users
- `POST /api/users` - Create user
- `GET /api/users/{id}` - Get user
- `PUT /api/users/{id}` - Update user
- `DELETE /api/users/{id}` - Delete user

### Clients
- `GET /api/clients` - List clients
- `POST /api/clients` - Create client
- `GET /api/clients/{id}` - Get client
- `PUT /api/clients/{id}` - Update client
- `DELETE /api/clients/{id}` - Delete client

### Contracts
- `GET /api/contracts` - List contracts
- `POST /api/contracts` - Create contract
- `GET /api/contracts/{id}` - Get contract
- `PUT /api/contracts/{id}` - Update contract
- `DELETE /api/contracts/{id}` - Delete contract

### Settings (Root only)
- `GET /api/settings` - Get settings
- `PUT /api/settings` - Update settings

### Health
- `GET /health` - Health check

## Security

- **Authentication:** JWT tokens (HS256)
- **Authorization:** Role-based (root, admin, user)
- **Rate Limiting:** IP-based with progressive lockout
- **Security Headers:** X-Frame-Options, HSTS, CSP, etc.
- **Input Validation:** Parameterized queries, HTML sanitization

## Troubleshooting

### "JWT_SECRET not set"
```bash
export JWT_SECRET=$(openssl rand -base64 32)
```

### "Database connection failed"
```bash
# Check PostgreSQL is running
docker-compose ps

# Verify connection parameters
echo $DB_HOST $DB_PORT $DB_USER $DB_NAME
```

### Build errors
```bash
go clean -modcache
go mod download
go build ./...
```

## License

GNU Affero General Public License v3.0 (AGPL-3.0)

See `COPYING` and `LICENSE` in project root.