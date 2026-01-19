# Client Hub - Development Environment

Fast development environment with hot reload for Client Hub.

## 📋 Overview

**Development mode** runs:
- ✅ Backend API (compiled Go binary)
- ✅ Frontend (Vite dev server with hot reload)
- ✅ PostgreSQL (native installation)
- ✅ Separate development database (`ehopdb_dev`)

This mode is optimized for rapid development with instant feedback.

---

## 🚀 Quick Start

### 1. Prerequisites

Ensure you have installed:
- Go 1.21+
- Node.js 20+
- PostgreSQL 14+
- Make

### 2. Start Development Environment

```bash
cd deploy/dev
make start
```

That's it! The Makefile handles everything:
- Checks for port conflicts
- Detects stale processes
- Builds the backend
- Starts all services

### 3. Access

- **Frontend (Vite)**: http://localhost:5173 ⚡ Hot reload!
- **Backend API**: http://localhost:3000
- **API Health**: http://localhost:3000/health

---

## 📝 Commands Reference

All commands are run from `deploy/dev/`:

### Main Commands

| Command | Description |
|---------|-------------|
| `make start` | Start development environment |
| `make stop` | Stop all services |
| `make restart` | Rebuild and restart all services |
| `make status` | Show status of all services |
| `make logs` | View backend logs (live) |
| `make build` | Build the backend binary |

### Database Commands

| Command | Description |
|---------|-------------|
| `make db-status` | Check database status and list users |
| `make db-connect` | Open psql shell to dev database |
| `make db-reset` | Reset database (⚠️ deletes all data) |

### Maintenance Commands

| Command | Description |
|---------|-------------|
| `make clean` | Kill all dev processes and free ports |
| `make reset` | Clean and restart fresh |
| `make destroy` | Completely destroy dev environment |
| `make check-ports` | Check if required ports are available |
| `make check-processes` | Check for running backend processes |
| `make health` | Check health of all services |
| `make install-deps` | Install Go and npm dependencies |

### Log Commands

| Command | Description |
|---------|-------------|
| `make logs` | View backend logs (live) |
| `make logs-frontend` | View Vite logs (live) |
| `make logs-all` | View all logs (live) |

---

## ⚡ Hot Reload

Development mode uses Vite dev server, which means:

- 🔥 **Instant updates**: Edit React components and see changes immediately
- 🐛 **Better debugging**: React DevTools, detailed error messages
- 🎨 **CSS hot reload**: Style changes apply without page refresh
- 📦 **Fast builds**: Vite only bundles what changed

### Development Workflow

```bash
# 1. Start dev environment
make start

# 2. Edit frontend code - changes appear instantly!
#    (no restart needed)

# 3. Edit backend code - rebuild and restart
make restart-backend

# Or restart everything
make restart
```

---

## 🛡️ Conflict Detection

The Makefile automatically detects and warns about:

### Stale Backend Processes

If an old backend process is running (common cause of "code not updating"):

```
╔══════════════════════════════════════════════════════════════════════════════╗
║  ⚠️   WARNING: OLD BACKEND PROCESS DETECTED                                  ║
╚══════════════════════════════════════════════════════════════════════════════╝

  A stale backend process is running (PID: 12345)
  This may be using an outdated version of the code!

Options:
  1. Run 'make clean' to kill all processes and start fresh
  2. Run 'kill 12345' to kill just this process
```

### Port Conflicts

If ports 3000 or 5173 are already in use:

```
╔══════════════════════════════════════════════════════════════════════════════╗
║  ⚠️   WARNING: PORT 3000 IS ALREADY IN USE                                   ║
╚══════════════════════════════════════════════════════════════════════════════╝

  Process: node (PID: 67890)

Options:
  1. Run 'make clean' to kill all dev processes
  2. Run 'kill 67890' to kill this specific process
  3. Change API_PORT in dev.ini
```

---

## 🗄️ Database

### Separate Development Database

Development mode uses `ehopdb_dev` (separate from production `ehopdb`).

This means:
- ✅ You can test destructive operations safely
- ✅ Production data is never affected
- ✅ You can reset dev database anytime

### Check Database Status

```bash
make db-status
```

Shows tables, users, and lock status.

### Connect Directly

```bash
make db-connect
```

Opens a psql shell to the dev database.

### Reset Database

```bash
make db-reset
```

⚠️ This deletes all data and recreates the database.

---

## 🔧 Configuration

Edit `dev.ini` to customize:

```ini
# Ports
API_PORT=3000
VITE_PORT=5173

# Database
DB_HOST=localhost
DB_PORT=5432
DB_NAME=ehopdb_dev
DB_USER=ehopuser
DB_PASSWORD=your_password

# Security
JWT_SECRET=your_jwt_secret
```

---

## 🔧 Troubleshooting

### Code Changes Not Reflected

**Most common cause**: A stale backend process is running.

```bash
# Check for stale processes
make check-processes

# Kill all and start fresh
make clean
make start
```

### Port Already in Use

```bash
# Check what's using ports
make check-ports

# Free all ports
make clean
```

### Backend Not Starting

```bash
# Check logs
make logs

# Or check status
make status

# Try clean rebuild
make clean
make build
make start
```

### Database Connection Failed

```bash
# Check PostgreSQL is running
sudo systemctl status postgresql

# Start if needed
sudo systemctl start postgresql

# Check database status
make db-status
```

### Module Not Found

```bash
# Reinstall dependencies
make install-deps
```

---

## 📁 File Structure

```
deploy/dev/
├── Makefile              # Single entry point for all commands
├── dev.ini               # Configuration file
├── README.md             # This file
└── INICIO-RAPIDO.md      # Quick start (Portuguese)

Generated during runtime:
├── .dev-pids/            # PID files for process tracking
│   ├── backend.pid
│   └── vite.pid
└── ../../logs/
    ├── backend_dev/
    │   └── server.log    # Backend logs
    └── vite-dev.log      # Vite logs
```

---

## 🎯 Best Practices

### 1. Always Use `make clean` When Stuck

If something isn't working as expected:

```bash
make clean
make start
```

This kills all stale processes and starts fresh.

### 2. Use `make restart-backend` for Backend Changes

Frontend changes apply instantly, but backend changes need a rebuild:

```bash
make restart-backend
```

### 3. Check Status Regularly

```bash
make status
```

Shows if services are running and their PIDs.

### 4. Use `make health` to Verify Services

```bash
make health
```

Checks HTTP endpoints to verify services are responding.

---

## 🔄 Switching Between Modes

### From Development to Production (Monolith)

```bash
# Stop dev
make stop

# Start monolith
cd ../monolith
./start-monolith.sh
```

### From Development to Docker

```bash
# Stop dev
make stop

# Start docker
cd ../docker
docker-compose up -d
```

**Note**: Each mode uses its own database, so data is not shared.

---

## 📚 See Also

- [Monolith Mode](../monolith/README.md) - Production-like deployment
- [Docker Mode](../docker/README.md) - Containerized deployment
- [Main README](../README.md) - Overview of all modes
- [Backend README](../../backend/README.md) - Backend documentation
- [Frontend README](../../frontend/README.md) - Frontend documentation

---

**Happy coding! ⚡🚀**