# Client Hub - Deployment Guide

Deployment configurations for Client Hub.

## 🎯 Deployment Modes

This project offers **3 deployment modes**:

### 1. 🐳 Docker (Recommended for Production)

Everything in isolated containers. Easier, safer, and more portable.

### 2. 🖥️ Monolith (Local Production)

Backend + Frontend (static build via Nginx) on the host. Simulates a production environment.

### 3. 🔧 Development (For Developers)

Backend + Vite dev server with hot reload. Perfect for development.

---

## 📁 Structure

```
deploy/
├── docker/                   # Deploy via Docker Compose
│   ├── docker-compose.yml
│   ├── .env.example
│   ├── Dockerfile.backend
│   ├── Dockerfile.frontend
│   └── nginx.conf
│
├── monolith/                 # Local deploy (production-like)
│   ├── start-monolith.sh
│   ├── stop-monolith.sh
│   ├── install-monolith.sh
│   ├── monolith.ini
│   └── versions.ini
│
├── dev/                      # Development environment
│   ├── start-dev.sh
│   ├── stop-dev.sh
│   └── dev.ini
│
├── certs/                    # SSL Certificates
│   └── ssl/
│
├── generate-ssl.sh           # Script to generate certificates
├── certs-config.ini          # Configuration for certificates
└── README.md                 # This file
```

---

## 🚀 Quick Start

### Docker (Recommended)

```bash
cd deploy/docker

# 1. Configure variables
cp .env.example .env
nano .env  # Edit DB_PASSWORD and JWT_SECRET

# 2. Start containers
docker-compose up -d

# 3. Access
# https://localhost (or your configured port)
```

### Monolith (Local Production)

```bash
cd deploy/monolith

# 1. Install dependencies (first time only)
./install-monolith.sh

# 2. Configure
nano monolith.ini  # Leave DB_PASSWORD and JWT_SECRET empty to auto-generate

# 3. Start
./start-monolith.sh

# 4. Access
# https://localhost
# http://localhost:80
```

### Development (Hot Reload)

```bash
cd deploy/dev

# 1. Configure
nano dev.ini  # Leave DB_PASSWORD and JWT_SECRET empty to auto-generate

# 2. Start
./start-dev.sh

# 3. Access
# http://localhost:5173  (Vite dev server)
```

---

## 🔍 Modes Comparison

| Feature               | Docker          | Monolith         | Development      |
|-----------------------|-----------------|------------------|------------------|
| **Isolation**         | ✅ Containers   | ❌ Host          | ❌ Host          |
| **Ease of Use**       | ⭐⭐⭐⭐⭐       | ⭐⭐⭐⭐          | ⭐⭐⭐           |
| **Production**        | ✅ Yes          | ✅ Yes           | ❌ No            |
| **Hot Reload**        | ❌ No           | ❌ No            | ✅ Yes           |
| **Performance**       | High            | High             | Medium           |
| **Frontend**          | Nginx (build)   | Nginx (build)    | Vite dev server  |
| **SSL**               | ✅ Auto         | ✅ Auto          | ❌ Optional      |
| **Portability**       | ✅ Max          | ⚠️ Requires deps | ⚠️ Requires deps |

---

## 🐳 Docker

### Commands

```bash
cd deploy/docker

# Start (local build)
docker-compose up -d

# View logs
docker-compose logs -f

# Restart
docker-compose restart

# Stop
docker-compose down

# Clean all (removes volumes/data)
docker-compose down -v
```

### Registry-based Deployment (CI/CD)

Use the registry flow when you want updates from published images (no local build on the host).

```bash
cd deploy/docker

# 1. Configure .env.registry
# 2. Pull images from the registry
docker compose -f docker-compose.registry.yml --env-file .env.registry pull

# 3. Run migrations (one-shot)
docker compose -f docker-compose.registry.yml --env-file .env.registry --profile migrations run --rm migrator

# 4. Start services using registry images
docker compose -f docker-compose.registry.yml --env-file .env.registry up -d backend frontend
```

You can also run the automated flow:

```bash
./auto-update-registry.sh
```

This script will:
- pull new images,
- run backups (optional),
- run migrations,
- restart services,
- run a health check,
- rollback to previous images if health check fails (when enabled).

Rollback note:
- Rollback only works if the previous images are still present on the host.
- If you use digest-based tags (image@sha256:...), the script creates a temporary :rollback tag to restore.

### .env File (Local build)

```bash
# Minimal Example
DB_PASSWORD=your_secure_password_here
JWT_SECRET=your_jwt_secret_min_64_chars
SSL_DOMAIN=localhost
```

### .env.registry (Registry-based deployment)

Use this file with `docker-compose.registry.yml` and `auto-update-registry.sh`.

```bash
# Registry images (required)
BACKEND_IMAGE=ghcr.io/owner/client-hub-backend:main
FRONTEND_IMAGE=ghcr.io/owner/client-hub-frontend:main

# Database & app secrets (same as .env)
DB_PASSWORD=your_secure_password_here
JWT_SECRET=your_jwt_secret_min_64_chars
SSL_DOMAIN=localhost

# Optional registry login for private registries
REGISTRY_HOST=ghcr.io
REGISTRY_USERNAME=your_registry_user
REGISTRY_PASSWORD=your_registry_token
```

Generate secure passwords:

```bash
# DB Password (64 chars)
openssl rand -base64 48 | tr -d "=+/" | cut -c1-64

# JWT Secret (64 chars)
openssl rand -base64 48 | tr -d "=+/" | cut -c1-64
```

---

## 🖥️ Monolith

### Requirements

- Go 1.21+
- Node.js 20+
- PostgreSQL 14+
- Nginx
- OpenSSL

### Installation

```bash
cd deploy/monolith
./install-monolith.sh
```

This script automatically installs all dependencies (Go, Node, PostgreSQL, Nginx).

### Configuration

Edit `monolith.ini`:

```ini
# Database
DB_USER=ehopuser
DB_NAME=ehopdb
DB_PASSWORD=          # Leave empty to auto-generate

# Backend
JWT_SECRET=           # Leave empty to auto-generate

# Ports
API_PORT=3000
FRONTEND_PORT=80
FRONTEND_HTTPS_PORT=443
```

### Usage

```bash
# Start
./start-monolith.sh

# Stop
./stop-monolith.sh

# Destroy all (removes data, etc)
./destroy-monolith.sh
```

### Cron Auto-Update (Monolith)

Use the cron wrapper to keep the monolith updated without manual intervention. It performs:

- `git fetch` + `git pull` (only if there are updates)
- backup (optional)
- rebuild + migrations + restart

```bash
# Example cron (daily at 03:00)
0 3 * * * /path/to/deploy/monolith/auto-update-cron.sh >> /var/log/client-hub-monolith-update.log 2>&1
```

Optional environment variables:

```bash
REPO_DIR=/path/to/repo
BRANCH=main
INI_FILE=/path/to/deploy/monolith/monolith.ini
AUTO_BACKUP=true
LOG_FILE=/var/log/client-hub-monolith-update.log
```

### What happens at start

1. ✅ Loads `monolith.ini`
2. ✅ Generates passwords if empty (saves to .ini)
3. ✅ Checks PostgreSQL
4. ✅ Creates database and user
5. ✅ Compiles backend (Go)
6. ✅ Compiles frontend (Vite build → dist/)
7. ✅ Generates SSL certificates
8. ✅ Configures and starts Nginx
9. ✅ Starts backend API

### Logs

- Backend: `logs/backend/server.log`
- Nginx: `/tmp/ehop_access.log`, `/tmp/ehop_error.log`

---

## 🔧 Development

### Requirements

Same as Monolith (Go, Node, PostgreSQL).

### Configuration

Edit `dev.ini`:

```ini
# Database (uses separate DB: ehopdb_dev)
DB_USER=ehopuser
DB_NAME=ehopdb_dev
DB_PASSWORD=          # Leave empty to auto-generate

# Backend
JWT_SECRET=           # Leave empty to auto-generate

# Ports
API_PORT=3000
VITE_PORT=5173
```

### Usage

```bash
cd deploy/dev

# Start
./start-dev.sh

# Stop
./stop-dev.sh
```

### What happens at start

1. ✅ Loads `dev.ini`
2. ✅ Generates passwords if empty (saves to .ini)
3. ✅ Checks PostgreSQL
4. ✅ Creates database and user (separate: `ehopdb_dev`)
5. ✅ Compiles backend (Go)
6. ✅ Starts backend API
7. ✅ Starts Vite dev server (hot reload)

### Advantages

- ⚡ **Hot Reload**: Edit code and see changes instantly
- 🐛 **Debug**: React DevTools, detailed logs
- 🗄️ **Separate DB**: Does not affect production data
- 🔄 **Fast**: No Docker image rebuilds

### Logs

- Backend: `logs/backend_dev/server.log`
- Vite: `logs/vite-dev.log`

---

## 🔐 SSL and Certificates

All modes generate SSL certificates automatically using `generate-ssl.sh`.

### Customize Certificates

Edit `certs-config.ini`:

```ini
[certificate]
country=BR
state=Sao Paulo
locality=Sao Paulo
organization=Client Hub
organizational_unit=IT
common_name=ehop.home.arpa
email=admin@ehop.home.arpa
days_valid=365
key_size=2048
```

### Generate Manually

```bash
./generate-ssl.sh ./certs/ssl
```

### Custom Domain

If using a custom domain (e.g., `ehop.home.arpa`):

1. Configure in .ini file:

   ```ini
   SSL_DOMAIN=ehop.home.arpa
   CORS_ALLOWED_ORIGINS=https://ehop.home.arpa
   VITE_API_URL=/api
   ```

2. Add to `/etc/hosts`:

   ```bash
   127.0.0.1 ehop.home.arpa
   ```

3. Import certificate in browser or use mkcert:

   ```bash
   mkcert -install
   mkcert ehop.home.arpa localhost 127.0.0.1
   ```

---

## 🔧 Troubleshooting

### PostgreSQL is not running

```bash
# Linux
sudo systemctl start postgresql
sudo systemctl status postgresql

# macOS
brew services start postgresql
```

### Port in use

```bash
# See what is using the port
sudo lsof -i :80
sudo lsof -i :443
sudo lsof -i :3000

# Kill process
sudo kill -9 <PID>
```

### Permission error in Nginx

```bash
# Nginx needs sudo for ports 80/443
# If error, clear processes:
sudo pkill -9 nginx
```

### Frontend does not load

1. Check if build was created: `ls frontend/dist/`
2. View Nginx logs: `tail -f /tmp/ehop_error.log`
3. Check permissions: `ls -la frontend/dist/`

### Backend cannot connect to database

1. Verify PostgreSQL is running
2. Test connection:

   ```bash
   psql -h localhost -p 5432 -U ehopuser -d ehopdb
   ```

3. Check exported variables:

   ```bash
   echo $DB_PASSWORD
   echo $DB_NAME
   ```

### CORS Error

If you see CORS error in browser console:

1. Check `CORS_ALLOWED_ORIGINS` in .ini
2. Use `/api` in `VITE_API_URL` (not `http://localhost:3000/api`)
3. If using custom domain, configure correctly

---

## 📊 Default Ports

| Service           | Docker | Monolith | Development |
|-------------------|--------|----------|-------------|
| Frontend          | 443    | 443      | 5173        |
| Frontend (HTTP)   | -      | 80       | -           |
| Backend API       | 3000   | 3000     | 3000        |
| PostgreSQL        | 5432   | 5432     | 5432        |

---

## 🗄️ Database

### Initialization

When the database is empty, the system enters setup mode:

1. Access `/api/initialize/status` to check
2. Use `/api/initialize/admin` to create the first admin user
3. Complete documentation at: `http://localhost:3000/docs`

### Backup (Monolith/Dev)

```bash
# Backup
pg_dump -h localhost -U ehopuser ehopdb > backup.sql

# Restore
psql -h localhost -U ehopuser ehopdb < backup.sql
```

### Backup (Docker)

```bash
# Backup
docker exec ehop_db pg_dump -U ehopuser ehopdb > backup.sql

# Restore
docker exec -i ehop_db psql -U ehopuser ehopdb < backup.sql
```

---

## 🔒 Security

### Checklist

- ✅ Use 64-character passwords (use generation commands)
- ✅ Never commit `.env` or `.ini` files with passwords
- ✅ Change default passwords before production
- ✅ Always use HTTPS (SSL certificates)
- ✅ Configure CORS correctly (do not use `*`)
- ✅ Keep dependencies updated
- ✅ Perform regular backups

### Generate Secure Passwords

```bash
# 64-character password
openssl rand -base64 48 | tr -d "=+/" | cut -c1-64

# Or leave empty in .ini to auto-generate
```

---

## 📚 More Information

- **Backend**: `../backend/README.md`
- **Frontend**: `../frontend/README.md`
- **SQL Schema**: `../backend/database/schema/` (modular)
- **API Docs**: `http://localhost:3000/docs` (when running)

---

## 🤝 Contributing

When adding deploy features:

1. Keep the 3 modes synchronized
2. Document changes in this README
3. Test in all modes
4. Update `versions.ini` if dependencies change

---

**Questions?** Open an issue or check the logs first! 🚀
