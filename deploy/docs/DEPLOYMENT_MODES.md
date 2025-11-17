# Deployment Modes

This document explains the two deployment modes available in the Contract Manager: **Docker Mode** and **Monolith Mode**.

## Quick Overview

| Aspect | Docker Mode | Monolith Mode |
|--------|-------------|---------------|
| **Environment** | Containerized (production-like) | Host machine (development) |
| **PostgreSQL** | Container (isolated) | Host service (native) |
| **Backend** | Container (Go API) | Direct process (go run) |
| **Frontend** | Container (Nginx) | Dev server (npm run dev) |
| **Port: Frontend** | 8081 | 5173 |
| **Port: Backend** | 3000 | 3000 |
| **Port: Database** | 5432 | 5432 |
| **Best For** | CI/CD, Production-like testing, Clean isolation | Development, Debugging, Fast iteration |
| **Data Persistence** | Volumes (semi-persistent) | Host filesystem (persistent) |

---

## 🐳 Docker Mode

### What is Docker Mode?

Docker Mode runs all services inside containers using Docker Compose. This creates an isolated, production-like environment on your machine.

### Architecture

```
┌─────────────────────────────────────────┐
│       Docker Host (Your Machine)        │
├─────────────────────────────────────────┤
│  ┌─────────────────────────────────┐    │
│  │  Docker Container: Frontend      │    │
│  │  - Nginx on port 8081            │    │
│  └─────────────────────────────────┘    │
│                                         │
│  ┌─────────────────────────────────┐    │
│  │  Docker Container: Backend       │    │
│  │  - Go API on port 3000           │    │
│  └─────────────────────────────────┘    │
│                                         │
│  ┌─────────────────────────────────┐    │
│  │  Docker Container: PostgreSQL    │    │
│  │  - Database on port 5432         │    │
│  └─────────────────────────────────┘    │
│                                         │
│  Docker Compose Orchestration           │
└─────────────────────────────────────────┘
```

### Quick Start

1. **Open the Deploy Manager:**
   ```bash
   cd deploy
   ./bin/deploy-manager
   ```

2. **Select Docker Mode:**
   - Choose option `1` from the main menu

3. **Start All Services:**
   - Choose option `11` to start all containers

4. **Access the Application:**
   - Frontend: http://localhost:8081
   - Backend API: http://localhost:3000
   - Database: localhost:5432

### Common Operations

#### Start Everything
```
Menu → 1 (Docker) → 11 (Start all)
```

#### Stop Everything
```
Menu → 1 (Docker) → 12 (Stop all)
```

#### Restart a Single Service
Example: Restart Backend
```
Menu → 1 (Docker) → 27 (Restart backend)
```

#### View Logs
```
Menu → 1 (Docker) → 31 (View all logs)
Menu → 1 (Docker) → 33 (View backend logs only)
```

#### Clean Everything (Fresh Start)
```
Menu → 1 (Docker) → 50 (Stop & clean all)
Then: Menu → 1 (Docker) → 11 (Start fresh)
```

### Advantages
✅ Production-like environment  
✅ Complete isolation between services  
✅ Easy to clean up and start fresh  
✅ Reproducible across different machines  
✅ Suitable for CI/CD pipelines  
✅ No conflicts with other services on your machine

### Disadvantages
❌ Slower startup time  
❌ Requires Docker to be installed  
❌ Uses more system resources  
❌ Harder to debug (inside containers)

---

## 🖥️ Monolith Mode

### What is Monolith Mode?

Monolith Mode runs all services directly on your host machine without containers. This is ideal for development where you want fast iteration and easier debugging.

### Architecture

```
┌──────────────────────────────────────────┐
│      Your Host Machine (Linux/macOS)     │
├──────────────────────────────────────────┤
│  ┌────────────────────────────────────┐  │
│  │  npm run dev                       │  │
│  │  - React/Vite on port 5173        │  │
│  │  - Hot reload enabled             │  │
│  └────────────────────────────────────┘  │
│                                          │
│  ┌────────────────────────────────────┐  │
│  │  go run ./cmd/api                  │  │
│  │  - Backend API on port 3000        │  │
│  │  - Native process                  │  │
│  └────────────────────────────────────┘  │
│                                          │
│  ┌────────────────────────────────────┐  │
│  │  PostgreSQL Service                │  │
│  │  - Native on port 5432            │  │
│  │  - System service                 │  │
│  └────────────────────────────────────┘  │
└──────────────────────────────────────────┘
```

### Prerequisites

Before using Monolith Mode, ensure you have:

```bash
# PostgreSQL installed and running
psql --version

# Go 1.21+ installed
go version

# Node.js and npm installed
npm --version

# Backend dependencies
cd backend
go mod tidy

# Frontend dependencies
cd ../frontend
npm install
```

### Quick Start

1. **Start PostgreSQL** (if not running):
   ```bash
   # Linux
   sudo systemctl start postgresql
   
   # macOS
   brew services start postgresql
   
   # or use your preferred PostgreSQL manager
   ```

2. **Open the Deploy Manager:**
   ```bash
   cd deploy
   ./bin/deploy-manager
   ```

3. **Select Monolith Mode:**
   - Choose option `2` from the main menu

4. **Start All Services:**
   - Choose option `11` to start all services

5. **Access the Application:**
   - Frontend: http://localhost:5173
   - Backend API: http://localhost:3000
   - Database: localhost:5432

### Common Operations

#### Start Everything
```
Menu → 2 (Monolith) → 11 (Start all)
```

#### Start Only Backend
```
Menu → 2 (Monolith) → 25 (Start backend)
```

#### Stop Frontend (while keeping backend running)
```
Menu → 2 (Monolith) → 29 (Stop frontend)
```

#### Restart Backend After Code Changes
```
Menu → 2 (Monolith) → 27 (Restart backend)
```

#### View Backend Logs
```
Menu → 2 (Monolith) → 33 (View backend logs)
```

### Development Workflow

#### Making Backend Changes
1. Edit code in `backend/`
2. Menu → 2 → 27 (Restart backend)
3. Test in browser or API client
4. Check logs: Menu → 2 → 33

#### Making Frontend Changes
1. Edit code in `frontend/`
2. Frontend auto-reloads (npm run dev watches files)
3. Refresh browser to see changes
4. Or restart: Menu → 2 → 30 (Restart frontend)

#### Working with Database
1. Access PostgreSQL directly:
   ```bash
   psql -U postgres -d contract_manager_db
   ```
2. Or use the menu:
   Menu → 2 → 24 (Check database status)

### Advantages
✅ Fast startup  
✅ No Docker required  
✅ Native performance  
✅ Hot reload for frontend (with npm)  
✅ Easy debugging with native tools  
✅ Direct access to logs  
✅ Lower resource usage  
✅ Great for active development

### Disadvantages
❌ Requires all dependencies installed on host  
❌ Port conflicts if services are already running  
❌ Harder to replicate exact environment  
❌ Not suitable for production  
❌ Database state persists between runs

---

## 🔧 Utilities Menu

Both Docker and Monolith modes can use the Utilities menu for testing, diagnostics, and reporting.

### Health Checks
- **Database Health**: Verify PostgreSQL connectivity
- **Backend Health**: Test API health endpoint
- **Frontend Health**: Check frontend availability
- **Full System Check**: Run all health checks

### Diagnostics
- **DB Separation**: Validate test vs production databases
- **Configuration**: Check all config files
- **Full System Diagnostics**: Comprehensive system check

### Testing [PLACEHOLDERS - Under Development]
- **Unit Tests**: Backend and frontend unit tests
- **Integration Tests**: Cross-component testing
- **Security Tests**: Vulnerability scanning
- **Full Test Suite**: All tests combined

### Reports [PLACEHOLDERS - Under Development]
- **Code Coverage Report**: Test coverage analysis
- **Performance Report**: Load and response time metrics
- **Database Schema Report**: ER diagram and documentation
- **System Requirements Report**: Compatibility check

---

## Choosing the Right Mode

### Use **Docker Mode** if:
- You want a production-like environment
- You need complete isolation
- You're testing Docker deployment
- You want to ensure consistency across machines
- You're running CI/CD pipelines
- You prefer containers over host services

### Use **Monolith Mode** if:
- You're actively developing features
- You want fast iteration cycles
- You need to debug code easily
- You prefer native debugging tools
- You have limited system resources
- You don't have Docker installed

---

## Troubleshooting

### Docker Mode Issues

**Containers won't start:**
```bash
cd deploy/scripts
docker-compose logs
docker-compose down -v
docker-compose up -d
```

**Port already in use:**
```bash
# Find process using port 3000
lsof -i :3000
kill -9 <PID>

# Then restart
Menu → 1 (Docker) → 13 (Restart all)
```

### Monolith Mode Issues

**PostgreSQL not running:**
```bash
# Linux
sudo systemctl status postgresql

# macOS
brew services list
brew services start postgresql
```

**Backend won't start:**
```bash
cd backend
go run ./cmd/api
# Check for dependency or port issues
```

**Frontend won't start:**
```bash
cd frontend
npm install
npm run dev
```

**Port conflicts:**
```bash
# Find and kill processes
lsof -i :5173  # Frontend
lsof -i :3000  # Backend
kill -9 <PID>
```

---

## Switching Between Modes

You can switch between modes anytime:

1. If in Docker Mode:
   - Menu → 1 (Docker) → 12 (Stop all)
   - Menu → Main → 2 (Switch to Monolith)

2. If in Monolith Mode:
   - Menu → 2 (Monolith) → 12 (Stop all)
   - Menu → Main → 1 (Switch to Docker)

---

## Environment Variables

### Docker Mode
Environment variables are loaded from `deploy/config/monolith.ini` and passed to containers.

### Monolith Mode
Environment variables should be set before starting services:

```bash
export DB_HOST=localhost
export DB_PORT=5432
export DB_USER=postgres
export DB_PASSWORD=postgres
export DB_NAME=contract_manager_db
export API_PORT=3000

# Then start services
./bin/deploy-manager
```

---

## Performance Comparison

| Operation | Docker | Monolith |
|-----------|--------|----------|
| Start all services | 15-30s | 5-10s |
| Restart backend | 5-10s | 1-2s |
| Memory usage | 1-2GB | 200-500MB |
| CPU usage | Medium | Low |
| Disk I/O | Medium | Low |
| Database operations | Normal | Slightly faster |

---

## Next Steps

- Read [QUICK_START.md](./QUICK_START.md) for initial setup
- Check [TROUBLESHOOTING.md](./TROUBLESHOOTING.md) for common issues
- Review configuration in `deploy/config/monolith.ini`
