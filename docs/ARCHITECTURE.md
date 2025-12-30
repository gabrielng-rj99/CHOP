# Architecture — Client Hub Open Project

Technical overview of the system, design patterns, and development guidelines.

## System Overview

Client Hub is a flexible client management system with a Go backend API and React frontend. The architecture follows a layered approach with clear separation of concerns.

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
│  │            (User, Client, Contract, etc.)                │ │
│  └─────────────────────────────────────────────────────────┘ │
│ ├─────────────────────────────────────────────────────────────┤
│ │                    PostgreSQL Database                       │
│ └─────────────────────────────────────────────────────────────┘
```

## Directory Structure

```
Client-Hub-Open-Project/
├── backend/
│   ├── cmd/
│   │   ├── server/           # HTTP server entry point
│   │   ├── cli/              # CLI tools entry point
│   │   └── tools/            # Utility tools
│   ├── server/
│   │   ├── server.go         # Server initialization
│   │   ├── routes.go         # Route registration
│   │   └── *_handlers.go     # HTTP Handlers
│   ├── store/
│   │   └── *_store.go        # Business Logic & DB Access
│   ├── domain/
│   │   └── models.go         # Domain entities
│   ├── database/
│   │   ├── database.go       # Connection management
│   │   └── schema/           # Database schema (modular)
│   └── config/
├── frontend/
│   └── src/
├── deploy/
└── docs/                     # Project Documentation
```

## Core Components

### Authentication & Security

#### JWT Implementation

- **Per-User Signing**: Signing key = GlobalSecret + UserAuthSecret. Allows invalidating tokens for a specific user (e.g., on password change) without affecting others.
- **Rotation**: Refresh tokens allow long-term sessions with short-lived access tokens.

#### Rate Limiting

The backend implements a **Token Bucket** algorithm to protect against abuse and brute-force attacks.

- **Configuration**: Managed via `/api/settings/security`.
- **Logic**: Tracks request counts per IP address within a configurable time window.
- **Response**: Returns `429 Too Many Requests` with a `Retry-After` header when the limit is exceeded.

#### Password Policy & Entropy

The system enforces strict password policies validated at two levels:

1. **Global Policy**: Applies to all users (min length, complexity).
2. **Role-Based Policy**: Specific roles (e.g., Root) can have stricter requirements.

**Entropy Calculation**:
$$E = L \times \log_2(R)$$
Where $L$ is length and $R$ is the character pool size. High privilege roles enforce a higher minimum entropy to prevent weak passwords that might technically pass length checks.

### Frontend Architecture

#### Caching System

To optimize performance and reduce backend load, the frontend utilizes a persistent cache layer.

- **Persistence**: Cached data is stored in browser storage.
- **Smart Invalidation**: Mutations (POST, PUT, DELETE) automatically invalidate relevant cache keys.
- **TTL**: Data has a configurable Time-To-Live to ensure eventual consistency.

### Store Layer Pattern

Each entity has a dedicated store that handles:

1. **Business Logic**: Validation, authorization checks.
2. **Data Access**: SQL queries with prepared statements (protecting against SQL Injection).
3. **Audit Integration**: Automatically logging all create/update/delete operations to the `audit_logs` table.

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
│  Affiliates  │ ─── Branches or Affiliates
└──────────────┘
```

## Deployment

### Docker Architecture

The project is designed to run in a containerized environment using Docker Compose:

- **Nginx**: Reverse proxy and static file server.
- **Backend**: Go API server.
- **PostgreSQL**: Primary data store.

Configuration is handled via environment variables and the `config.ini` file, with a clear hierarchy where environment variables take precedence.

## Development Guidelines

- **Code Style**: Follow standard Go formatting guidelines.
- **Security**: Always use prepared statements. Validate all inputs. Never log sensitive data.
- **Testing**: Unit tests for stores, Integration tests for APIs, and Property-based tests for security critical components.
