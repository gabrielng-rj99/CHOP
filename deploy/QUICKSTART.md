# Makefile Quick Reference Guide

## 🚀 TL;DR - What Changed?

All Makefiles in `/deploy` have been rewritten with:
- ✅ **Clear command names** (no more `reset` confusion)
- ✅ **Better organization** (grouped by function)
- ✅ **Language installation helpers** (Go, Node, Python)
- ✅ **`destroy-all` command** (complete cleanup)
- ✅ **No duplicate commands** (removed redundancy)

---

## 📍 Choose Your Deployment Type

### Development (`/deploy/dev`)
For local development with backend + frontend + database

```bash
cd deploy/dev
make help        # Show all commands
make start       # Start everything
make logs        # View logs
make destroy-all # Complete reset
```

### Monolith (`/deploy/monolith`)
For single-unit production installation

```bash
cd deploy/monolith
make help        # Show all commands
make install     # Install monolith
make start       # Start services
make uninstall   # Remove everything
```

### Docker (`/deploy/docker`)
For containerized deployment

```bash
cd deploy/docker
make help        # Show all commands
make build       # Build images
make up          # Start containers
make down        # Stop containers
```

---

## 🎯 Common Tasks

### Development Setup (First Time)

```bash
cd deploy/dev

# Option 1: Use your existing version managers (recommended)
make install-deps           # Just install project dependencies

# Option 2: No version managers? Let Makefile install them
make install-go             # Install Go 1.25.6
make install-node           # Install Node.js 24.11.1
make install-python         # Install Python 3.13.9
make install-deps           # Install project dependencies

# Start development
make build                   # Build backend
make start                   # Start all services
```

### Daily Development

```bash
cd deploy/dev

# Start your day
make start                   # Backend + Frontend

# While working
make logs                    # View live backend logs
make status                  # Check what's running
make health                  # Test if services respond

# When code changes
make restart                 # Rebuild and restart

# End of day
make stop                    # Stop all services
```

### Debug & Fix Issues

```bash
cd deploy/dev

# Something's broken?
make clean                   # Kill stale processes
make status                  # Check what's running
make check-ports             # See port conflicts
make check-processes         # Find running processes

# Database issues?
make db-status               # See database info
make db-list                 # List users with lock status
make db-reset                # Wipe database (careful!)

# Complete reset
make destroy-all             # Remove everything (keeps source code!)
make start                   # Start fresh
```

### Monolith Installation

```bash
cd deploy/monolith

# First time
make install                 # Complete installation

# Daily usage
make start                   # Start services
make stop                    # Stop services
make restart                 # Restart services
make status                  # Check status
make health                  # Check if services respond

# Backup before changes
make backup                  # Create backup
make restore                 # Restore from backup

# Cleanup
make uninstall               # Remove everything
```

### Cron Auto-Update (Monolith)

```bash
# Example cron (daily at 03:00)
0 3 * * * /path/to/deploy/monolith/auto-update-cron.sh >> /path/to/repo/app/monolith/logs/auto-update-cron.log 2>&1
```

Optional environment variables:

```bash
REPO_DIR=/path/to/repo
BRANCH=main
INI_FILE=/path/to/deploy/monolith/monolith.ini
AUTO_BACKUP=true
LOG_FILE=/path/to/repo/app/monolith/logs/auto-update-cron.log
```

### Docker Workflow

```bash
cd deploy/docker

# First time
make env-check               # Create .env from template
make build                   # Build images
make up                      # Start containers

# Daily usage
make logs                    # View container logs
make status                  # Check container status
make health                  # Check service health
make shell                   # Open bash in backend
make shell-db                # Open PostgreSQL shell

# Maintenance
make clean                   # Remove containers (keep volumes)
make rebuild                 # Full rebuild (no cache)
make down                    # Stop and remove containers
```

### Registry Workflow (CI/CD)

```bash
cd deploy/docker

# Configure .env.registry with BACKEND_IMAGE and FRONTEND_IMAGE
make registry-pull
make registry-migrate
make registry-update
```

Note: `auto-update-registry.sh` performs a health check and rolls back to the previous images if the health check fails.

---

## 📋 Command Reference by Category

### Service Management (All Environments)

```
start      - Start all services
stop       - Stop all services
restart    - Stop and start services
status     - Show what's running
health     - Check if services respond
```

### Building (Dev Only)

```
build      - Build backend (uses existing binary if present)
build-fresh - Clean build (clear cache, rebuild everything)
rebuild    - Full rebuild of everything
```

### Logs (All Environments)

```
logs              - Show main service logs (live)
logs-backend      - Show backend logs
logs-frontend     - Show frontend logs
logs-db           - Show database logs (Docker/Monolith)
```

### Database

```
db-status  - Show connection info and tables
db-list    - List users with lock status (Dev only)
db-connect - Open PostgreSQL shell
db-reset   - Wipe and recreate database
backup     - Backup database (Docker/Monolith)
restore    - Restore from backup (Docker/Monolith)
```

### Cleanup & Maintenance

```
clean      - Kill processes, remove PID files
destroy-all - Complete destruction (except source code)
prune      - Remove unused Docker resources
```

### Installation & Setup

```
install           - Full installation (Monolith)
uninstall         - Complete removal (Monolith)
install-deps      - Install project dependencies
install-go        - Install Go 1.25.6
install-node      - Install Node.js 24.11.1
install-python    - Install Python 3.13.9
env-setup         - Create .env from template (Docker)
validate          - Validate configuration
```

---

## 🚨 Dangerous Commands (Need Confirmation)

These commands ask for confirmation before running:

```bash
make db-reset      # Type "reset" to confirm
make destroy-all   # Type "destroy-all" to confirm
make uninstall     # Type "uninstall" to confirm
make clean         # Type "y" to confirm (Docker/Monolith)
```

---

## ⚠️ Important Notes

### Version Managers Recommended
If you have these installed, **skip** the `install-*` commands:
- **Python**: Use `pyenv` instead of `install-python`
- **Node.js**: Use `nvm` or `fnm` instead of `install-node`
- **Go**: Use `gvm` or system package manager instead of `install-go`

The `install-*` commands are for emergency setups only on clean systems.

### Configuration Files
- **Dev**: `/deploy/dev/dev.ini`
- **Monolith**: `/deploy/monolith/monolith.ini`
- **Docker**: `/deploy/docker/.env`

### Default Ports
- **Frontend**: `http://localhost:5173` (Dev) or `:80` (Monolith) or `:5173` (Docker)
- **Backend**: `http://localhost:3000` (all)
- **Database**: `localhost:5432` (all)

---

## 🔄 Old → New Command Mapping

| Old Command | New Command | Environment |
|-------------|------------|-------------|
| `reset` | `rebuild` | Dev |
| `destroy` | `destroy-all` | Dev |
| `restart-backend` | `restart-backend` | Dev (same) |
| `populate` | *removed* | Dev |
| `health-check` | `health` | All |
| `restart` | `restart` | All (same) |
| `logs-backend` | `logs` or `logs-backend` | All |

---

## 💡 Examples

### Dev: Local Testing
```bash
cd deploy/dev
make start           # Start everything
make logs            # Watch logs
# Make changes to code...
make rebuild         # Rebuild everything
make health          # Test if working
make stop            # Stop when done
```

### Monolith: Production Setup
```bash
cd deploy/monolith
make install         # Install once
make start           # Start services
make backup          # Backup before updates
make upgrade         # Update versions
make restore         # Rollback if needed
```

### Docker: CI/CD Pipeline
```bash
cd deploy/docker
make validate        # Check config
make build           # Build images
make up              # Start containers
make health          # Verify services
# Run tests...
make down            # Stop containers
```

---

## ❓ Troubleshooting

**Services won't start?**
```bash
make clean
make status
make check-ports
make check-processes
make start
```

**Something's weird?**
```bash
make destroy-all    # Complete reset
make start          # Start fresh
```

**Database corrupted?**
```bash
make db-reset       # Reset database
make restart        # Restart with fresh schema
```

**Docker issues?**
```bash
make validate       # Check configuration
make rebuild        # Full rebuild
make health         # Check services
```

---

## 📚 Full Documentation

For complete documentation with all options:

```bash
cd deploy/dev && make help
cd deploy/monolith && make help
cd deploy/docker && make help
```

Each `help` output is organized with:
- Quick start commands
- Service management
- Database operations
- Maintenance commands
- Configuration info

---

## ✨ Summary

The new Makefiles are:
- **Clearer**: Commands do what their names suggest
- **Safer**: Destructive operations require confirmation
- **Faster**: Tab completion with better naming
- **Better**: Organized, documented, consistent
- **Powerful**: New features like language installation

**Just run `make help` to see what's available!**