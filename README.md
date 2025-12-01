# Entity Hub Open Project

A flexible entity management system with robust authentication, authorization, and audit logging.

## Overview

Entity Hub is a modern web application for managing abstract entities (clients, contracts, categories, etc.) with a focus on security and extensibility. Built with Go backend and React frontend.

## Features

- **Entity Management**: CRUD operations for clients, contracts, categories, lines, and dependents
- **Role-Based Access Control**: Three-tier system (root, admin, user)
- **Security**: JWT authentication, password policies, brute-force protection
- **Audit Logging**: Complete operation history for compliance
- **Modern UI**: React + TypeScript frontend with responsive design

## Quick Start

### Using Docker (Recommended)

```bash
cd deploy
make build
./bin/deploy-manager
# Select option 10 for Docker deployment
```

Access: http://localhost:8081

### Development Mode

```bash
cd deploy
make build
./bin/deploy-manager
# Select option 1 for Monolith (local development)
```

Access: http://localhost:5173

## Architecture

```
Entity-Hub-Open-Project/
├── backend/          # Go API server
│   ├── cmd/          # Entry points (server, CLI)
│   ├── server/       # HTTP handlers and middleware
│   ├── store/        # Data access layer
│   ├── domain/       # Domain models
│   └── database/     # Database connection and schema
├── frontend/         # React application
│   └── src/
├── deploy/           # Deployment configurations
│   ├── docker/       # Docker Compose files
│   └── scripts/      # Deployment scripts
├── tests/            # Security and integration tests
└── docs/             # Documentation
```

## Tech Stack

| Layer | Technology |
|-------|------------|
| Backend | Go 1.21+, Gin framework |
| Frontend | React 18, TypeScript, Vite |
| Database | PostgreSQL 14+ |
| Auth | JWT with rotating secrets |
| Deploy | Docker, Docker Compose |

## Security

### Password Policy

- Minimum 16 characters
- Must contain: uppercase, lowercase, numbers, special characters
- No spaces allowed

### Role Hierarchy

| Role | Permissions |
|------|-------------|
| `root` | Full system access, audit logs, user management |
| `admin` | User management (except root), entity management |
| `user` | Read-only access (configurable) |

### Brute Force Protection

- Progressive lockout after failed attempts
- IP-based rate limiting
- Account lock levels with increasing duration

## Testing

### Running Tests

```bash
cd tests

# Start test environment
docker compose -f docker-compose.test.yml up -d

# Install Python dependencies
pip install -r requirements.txt

# Run security tests
python run_tests.py
```

### Test Coverage

| Category | Tests | Description |
|----------|-------|-------------|
| JWT Security | 16 | Token validation, tampering, expiration |
| SQL Injection | 15 | Union, boolean, time-based attacks |
| Authorization | 19 | RBAC, privilege escalation |
| Input Validation | 37 | Type, format, length checks |
| Data Leakage | 24 | Sensitive data exposure |
| Password | 25 | Policy enforcement |
| Login Blocking | 18 | Brute force protection |

### Test Environment Ports

- Database: `65432`
- Backend: `63000`
- Frontend: `65080`

## API Endpoints

### Authentication

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/login` | Authenticate user |
| POST | `/api/refresh-token` | Refresh JWT token |
| POST | `/api/initialize/admin` | Create root admin (empty DB only) |
| GET | `/api/initialize/status` | Check initialization status |

### Users (Admin/Root only)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/users` | List all users |
| POST | `/api/users` | Create user |
| GET | `/api/users/{username}` | Get user details |
| PUT | `/api/users/{username}` | Update user |
| DELETE | `/api/users/{username}` | Delete user |
| PUT | `/api/users/{username}/block` | Block user |
| PUT | `/api/users/{username}/unlock` | Unlock user |

### Entities

| Resource | Endpoints |
|----------|-----------|
| Clients | `/api/clients`, `/api/clients/{id}` |
| Contracts | `/api/contracts`, `/api/contracts/{id}` |
| Categories | `/api/categories`, `/api/categories/{id}` |
| Lines | `/api/lines`, `/api/lines/{id}` |
| Dependents | `/api/dependents`, `/api/dependents/{id}` |
| Audit Logs | `/api/audit-logs` (root only) |

## Configuration

### Environment Variables

```bash
# Database
DB_HOST=localhost
DB_PORT=5432
DB_NAME=entity_hub
DB_USER=postgres
DB_PASSWORD=secret

# JWT
JWT_SECRET=your-secret-key
JWT_EXPIRATION_TIME=60  # minutes
JWT_REFRESH_EXPIRATION_TIME=10080  # minutes

# Security
PASSWORD_MIN_LENGTH=16
MAX_FAILED_ATTEMPTS=5
LOCKOUT_DURATION=15m
```

## Documentation

- [Architecture](docs/ARCHITECTURE.md) - Technical architecture details
- [Contributing](docs/CONTRIBUTING.md) - Contribution guidelines

## Development

### Prerequisites

- Go 1.21+
- Node.js 18+
- PostgreSQL 14+
- Docker (optional)

### Backend Development

```bash
cd backend
go mod download
go run cmd/server/main.go
```

### Frontend Development

```bash
cd frontend
npm install
npm run dev
```

## Roadmap

### Current Focus

- [ ] Complete entity name customization
- [ ] Database entity renaming
- [ ] Enhanced filtering and search

### Future Plans

- [ ] Dashboard analytics
- [ ] Export to CSV/PDF
- [ ] Email notifications
- [ ] External integrations

## License

This project is open source. See LICENSE for details.

## Contributing

Contributions welcome! Please read [CONTRIBUTING.md](docs/CONTRIBUTING.md) before submitting PRs.