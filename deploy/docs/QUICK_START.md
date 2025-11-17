# Quick Start Guide

Get the Contract Manager up and running in 2 minutes!

## Prerequisites

### For Docker Mode
- Docker Engine 20.10+
- Docker Compose 2.0+

### For Monolith Mode
- PostgreSQL 14+ (running on host)
- Go 1.21+
- Node.js 18+

## Option 1: Docker Mode (Recommended for Testing)

Docker Mode runs everything in containers - production-like and completely isolated.

### Start
```bash
cd deploy
make build
./bin/deploy-manager
```

Then in the menu:
1. Select `1` (Docker Mode)
2. Select `11` (Start all services)
3. Wait 20-30 seconds for containers to start
4. Open: **http://localhost:8081**

### Stop
```
Menu → 1 (Docker) → 12 (Stop all)
```

---

## Option 2: Monolith Mode (Recommended for Development)

Monolith Mode runs services directly on your machine - faster startup and easier debugging.

### Prerequisites
Ensure PostgreSQL is running:
```bash
# Linux
sudo systemctl status postgresql

# macOS
brew services list | grep postgresql
```

### Start
```bash
cd deploy
make build
./bin/deploy-manager
```

Then in the menu:
1. Select `2` (Monolith Mode)
2. Select `11` (Start all services)
3. Wait 5-10 seconds for services to start
4. Open: **http://localhost:5173**

### Stop
```
Menu → 2 (Monolith) → 12 (Stop all)
```

---

## Initial Setup (First Run)

After starting the application (either mode), you'll see an **Initialize** page.

Fill in the required information:

### 1. Database Configuration
- **Host**: `localhost`
- **Port**: `5432`
- **Database**: `contract_manager_db` (or your preferred name)
- **Username**: `postgres`
- **Password**: Your PostgreSQL password

### 2. Admin User
- **Email**: Your email address
- **Password**: Choose a strong password

### 3. JWT Secret
- Click **Generate** button (recommended)
- Or paste your own secret key

### 4. Deploy
- Click **Deploy** button
- Wait for confirmation
- Login with your email and password

---

## Accessing the Application

| Service | Docker Mode | Monolith Mode |
|---------|------------|---------------|
| Frontend | http://localhost:8081 | http://localhost:5173 |
| Backend API | http://localhost:3000 | http://localhost:3000 |
| Database | localhost:5432 | localhost:5432 |

---

## Common Tasks

### View Logs
```
Menu → Select Mode (1 or 2) → 31 (View all logs)
```

### Restart Backend (after code changes)
```
Menu → Select Mode → 27 (Restart backend)
```

### Restart Frontend (after code changes)
```
Menu → Select Mode → 30 (Restart frontend)
```

### Health Check
```
Menu → 3 (Utilities) → 14 (Full system health check)
```

### Stop Everything
```
Menu → Select Mode → 12 (Stop all)
```

### Clean Everything (Fresh Start)
```
Menu → Select Mode → 50 (Stop & clean all)
Menu → Select Mode → 11 (Start all)
```

---

## Switching Modes

You can switch between Docker and Monolith modes anytime:

1. Stop the current mode
2. Return to main menu
3. Select the other mode
4. Start services in new mode

---

## Troubleshooting

### "Port already in use"
```bash
# Find what's using port 3000
lsof -i :3000

# Kill the process
kill -9 <PID>

# Then restart in your menu
```

### "PostgreSQL connection refused" (Monolith Mode)
```bash
# Start PostgreSQL
sudo systemctl start postgresql  # Linux
brew services start postgresql   # macOS
```

### "Docker daemon not running" (Docker Mode)
```bash
# Start Docker
open /Applications/Docker.app  # macOS
# or use your system's Docker launcher
```

### Services won't start
```bash
# Check logs
Menu → Select Mode → 31 (View all logs)

# Clean and restart
Menu → Select Mode → 50 (Stop & clean all)
Menu → Select Mode → 11 (Start all)
```

---

## Next Steps

- **Read More**: See `DEPLOYMENT_MODES.md` for detailed information
- **Advanced Setup**: Check `TROUBLESHOOTING.md` for common issues
- **Configuration**: Review `deploy/config/monolith.ini` for advanced options
- **Run Tests**: Menu → 3 (Utilities) → Testing section

---

## Quick Reference

| Task | Command |
|------|---------|
| Build CLI | `cd deploy && make build` |
| Start CLI | `cd deploy && ./bin/deploy-manager` |
| View all logs | Menu → Select Mode → 31 |
| Restart backend | Menu → Select Mode → 27 |
| Stop everything | Menu → Select Mode → 12 |
| Health check | Menu → 3 → 14 |
| Clean fresh start | Menu → Select Mode → 50, then 11 |

---

**That's it!** You're ready to use Contract Manager. 🎉

For more information, see the [Deployment Modes Guide](./DEPLOYMENT_MODES.md).