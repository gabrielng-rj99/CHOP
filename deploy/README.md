# Deploy & Configuration

Everything you need to run the Contract Manager application.

## 🚀 Quick Start

```bash
cd deploy
make build
./bin/deploy-manager
```

Then select your deployment mode:
- **1** = Docker Mode (containerized, production-like)
- **2** = Monolith Mode (host services, development)
- **3** = Utilities (health checks, diagnostics, tests)
- **0** = Exit

Access the application:
- Docker Mode: http://localhost:8081
- Monolith Mode: http://localhost:5173

## 📂 Directory Structure

```
deploy/
├── cmd/
│   └── main.go              → Deploy Manager CLI (Go)
├── bin/
│   └── deploy-manager       → Compiled binary
├── config/
│   └── monolith.ini         → Configuration file
├── scripts/
│   ├── docker-compose.yml   → Docker Compose configuration
│   └── deploy-monolith.sh   → Monolith startup script
├── tools/
│   ├── 000_utils.go         → Test utilities
│   └── 91_run_tests.go      → Test runner
├── docs/
│   ├── QUICK_START.md           → 2-minute setup guide
│   ├── DEPLOYMENT_MODES.md      → Detailed mode comparison
│   └── TROUBLESHOOTING.md       → Common issues & solutions
├── Makefile                 → Build automation
└── go.mod                   → Go module dependencies
```

## 🐳 Docker Mode

Run all services inside containers (production-like environment).

```bash
./bin/deploy-manager
→ Select 1 (Docker Mode)
→ Select 11 (Start all services)
```

**Ports:**
- Frontend: http://localhost:8081
- Backend: http://localhost:3000
- Database: localhost:5432

**Advantages:**
- Production-like environment
- Complete isolation
- Easy to clean and restart
- Reproducible across machines

**Requirements:**
- Docker Engine 20.10+
- Docker Compose 2.0+

## 🖥️ Monolith Mode

Run all services directly on your host machine (development-friendly).

```bash
./bin/deploy-manager
→ Select 2 (Monolith Mode)
→ Select 11 (Start all services)
```

**Ports:**
- Frontend: http://localhost:5173
- Backend: http://localhost:3000
- Database: localhost:5432

**Advantages:**
- Fast startup (5-10 seconds)
- Native debugging
- Hot reload for frontend
- Low resource usage

**Requirements:**
- PostgreSQL 14+ (running on host)
- Go 1.21+
- Node.js 18+

## 🔧 Utilities Menu

Access testing, diagnostics, and reporting tools:

```bash
./bin/deploy-manager
→ Select 3 (Utilities)
```

### Health Checks
- Database connectivity
- Backend API health
- Frontend availability
- Full system check

### Diagnostics
- Database separation validation (test vs main)
- Configuration validation
- Full system diagnostics report

### Testing [Placeholders]
- Unit tests
- Integration tests
- Security tests
- Full test suite with coverage

### Reports [Placeholders]
- Code coverage report
- Performance metrics
- Database schema
- System requirements

## ⚡ Menu Navigation

### Main Menu
```
1  → Docker Mode
2  → Monolith Mode
3  → Utilities
0  → Exit
```

### Docker/Monolith Mode Menus
```
11-14 → All services (start/stop/restart/status)
21-24 → Database operations
25-27 → Backend operations
28-30 → Frontend operations
31-34 → Logs & monitoring
50    → Stop & clean all
99    → Back to main menu
```

### Utilities Menu
```
11-14 → Health checks
21-23 → Diagnostics
31-34 → Testing [PLACEHOLDERS]
41-44 → Reports [PLACEHOLDERS]
99    → Back to main menu
```

## 🔨 Build

```bash
# Build for current OS (Linux/macOS)
cd deploy && make build

# Build for all platforms
make build-all

# Result: bin/deploy-manager
```

## 📖 Documentation

- **docs/QUICK_START.md** → Get started in 2 minutes
- **docs/DEPLOYMENT_MODES.md** → Detailed comparison of both modes
- **docs/TROUBLESHOOTING.md** → Common problems and solutions

## Direct Commands (Without CLI)

### Monolith Mode
```bash
bash scripts/deploy-monolith.sh start
bash scripts/deploy-monolith.sh stop
bash scripts/deploy-monolith.sh status
bash scripts/deploy-monolith.sh logs
```

### Docker Mode
```bash
cd scripts
docker-compose up -d          # Start all
docker-compose down           # Stop all
docker-compose ps             # Status
docker-compose logs -f        # Follow logs
docker-compose restart backend # Restart service
docker-compose down -v        # Clean (remove volumes)
```

## 🔄 Common Workflows

### Fresh Start (Docker)
```
1. Menu → 1 (Docker)
2. 11 (Start all)
3. Wait 20-30 seconds
4. http://localhost:8081
```

### Fresh Start (Monolith)
```
1. Menu → 2 (Monolith)
2. 11 (Start all)
3. Wait 5-10 seconds
4. http://localhost:5173
```

### Restart Backend After Code Changes
```
Menu → Select Mode → 27 (Restart backend)
```

### View Service Logs
```
Menu → Select Mode → 31 (All logs) or 33 (Backend only)
```

### Health Check
```
Menu → 3 (Utilities) → 14 (Full system health check)
```

### Stop Everything
```
Menu → Select Mode → 12 (Stop all)
```

### Clean Fresh Start
```
Menu → Select Mode → 50 (Stop & clean all)
Then:
Menu → Select Mode → 11 (Start all)
```

## 📊 Comparison Table

| Feature | Docker | Monolith |
|---------|--------|----------|
| Startup Time | 20-30s | 5-10s |
| Environment | Containerized | Host |
| Memory Usage | 1-2GB | 200-500MB |
| Debugging | Harder | Easier |
| Hot Reload | No | Yes (Frontend) |
| Production-like | Yes | No |
| Best For | Testing, CI/CD | Development |
| Data Persistence | Volumes | Host filesystem |

## 🌐 Ports & Services

All services listen on standard ports:

| Service | Port | Mode |
|---------|------|------|
| Frontend | 5173 (Monolith) / 8081 (Docker) | Both |
| Backend API | 3000 | Both |
| PostgreSQL | 5432 | Both |

## 🆘 Troubleshooting

**Port already in use:**
```bash
lsof -i :3000
kill -9 <PID>
```

**PostgreSQL not running (Monolith):**
```bash
sudo systemctl start postgresql  # Linux
brew services start postgresql   # macOS
```

**Docker daemon not running:**
```bash
open /Applications/Docker.app  # macOS
# or start Docker using system launcher
```

**Services won't start:**
```
Menu → Select Mode → 31 (View logs)
Menu → Select Mode → 50 (Clean all) → 11 (Start fresh)
```

For more help, see `docs/TROUBLESHOOTING.md`

## 📋 Requirements

### Docker Mode
- Docker Engine 20.10+
- Docker Compose 2.0+
- Disk space: 2-3GB

### Monolith Mode
- PostgreSQL 14+
- Go 1.21+
- Node.js 18+
- npm or yarn
- Disk space: 500MB

### Both Modes
- Linux, macOS, or Windows with WSL
- Network: Ports 3000, 5173/8081, 5432 available

## 🔧 Configuration

Edit `config/monolith.ini` to customize:
- Database credentials
- API port
- Log levels
- Other deployment settings

## 📝 Next Steps

1. **Start:** `make build && ./bin/deploy-manager`
2. **Read:** `docs/QUICK_START.md`
3. **Learn:** `docs/DEPLOYMENT_MODES.md`
4. **Troubleshoot:** `docs/TROUBLESHOOTING.md`

---

**Status:** ✅ Ready | **Start:** `make build && ./bin/deploy-manager`

For detailed information, see the documentation in the `docs/` directory.