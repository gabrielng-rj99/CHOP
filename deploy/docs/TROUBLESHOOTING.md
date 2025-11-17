# Troubleshooting

Common problems and quick solutions.

## Port Already in Use

```bash
# Find process
lsof -i :3000    # Backend
lsof -i :5173    # Frontend (Monolith)
lsof -i :8081    # Frontend (Docker)
lsof -i :5432    # Database

# Kill process
kill -9 <PID>
```

## PostgreSQL Connection Failed

**Monolith:**
```bash
# Check if running
psql -h localhost -U postgres

# Start (macOS)
brew services start postgresql

# Start (Linux)
sudo systemctl start postgresql
```

**Docker:**
```bash
# Check container
docker ps | grep postgres

# Restart
docker-compose -f scripts/docker-compose.yml restart postgres

# Rebuild
docker-compose -f scripts/docker-compose.yml down -v
docker-compose -f scripts/docker-compose.yml up -d postgres
```

## Docker Not Found

```bash
# Check installation
docker --version
docker-compose --version

# Install from https://docker.com

# Start daemon
docker ps
```

## "command not found"

```bash
# Make sure you're in deploy folder
cd deploy

# Check files exist
ls -la scripts/deploy-monolith.sh
ls -la bin/deploy-manager

# Fix permissions
chmod +x scripts/*.sh
chmod +x bin/deploy-manager
```

## Scripts in Wrong Directory

```bash
# From project root
bash deploy/scripts/deploy-monolith.sh start

# Or go to deploy folder
cd deploy
bash scripts/deploy-monolith.sh start
```

## Database Initialization Stuck

```bash
# Stop everything
bash deploy/scripts/deploy-monolith.sh stop

# Clean
bash deploy/scripts/deploy-monolith.sh clean

# Start fresh
bash deploy/scripts/deploy-monolith.sh start

# Reinitialize via Frontend UI
# Open http://localhost:5173 or http://localhost:8081
```

## Frontend Shows Blank Page

```bash
# Check backend running
curl http://localhost:3000/health

# Check logs
bash deploy/scripts/deploy-monolith.sh logs

# Restart
bash deploy/scripts/deploy-monolith.sh stop
bash deploy/scripts/deploy-monolith.sh start

# Refresh browser (Ctrl+Shift+R)
```

## API Calls Fail (503)

```bash
# Check backend
curl http://localhost:3000/health

# View logs
bash deploy/scripts/deploy-monolith.sh logs backend

# Restart
bash deploy/scripts/deploy-monolith.sh stop
bash deploy/scripts/deploy-monolith.sh start
```

## Docker Container Won't Start

```bash
# Check logs
docker logs <container_id>

# Or all logs
docker-compose -f scripts/docker-compose.yml logs

# Rebuild
docker-compose -f scripts/docker-compose.yml down -v
docker-compose -f scripts/docker-compose.yml up -d --build
```

## Docker Daemon Not Running

```bash
# macOS
open /Applications/Docker.app

# Linux
sudo systemctl start docker

# Windows
# Start Docker Desktop app

# Verify
docker ps
```

## Build Failed - "make: command not found"

```bash
# macOS
brew install make

# Linux (Ubuntu/Debian)
sudo apt-get install build-essential

# Linux (Fedora/CentOS)
sudo yum install make
```

## Binary Wrong for Platform

```bash
# Rebuild for your OS
cd deploy
make clean
make build

# Or specific platform
make build-linux
make build-macos
make build-windows
```

## High CPU/Memory Usage

```bash
# Check processes
top

# Restart everything
cd deploy
./bin/deploy-manager
# Press 5 (clean monolith) or 13 (clean docker)

# Then start again
./bin/deploy-manager
# Press 1 (monolith) or 10 (docker)
```

## Cannot Reach Frontend

```bash
# Check if running
lsof -i :5173    # Monolith
lsof -i :8081    # Docker

# Try different address
http://127.0.0.1:5173
http://127.0.0.1:8081

# Check firewall
# Windows: Check Windows Firewall
# macOS: System Preferences → Security & Privacy
# Linux: sudo ufw status
```

## Frontend Can't Connect to Backend

```bash
# Check backend running
curl http://localhost:3000/health

# Check CORS config
cat deploy/config/monolith.ini | grep -i cors

# Restart both
bash deploy/scripts/deploy-monolith.sh stop
bash deploy/scripts/deploy-monolith.sh start
```

## Verbose/Debug Output

```bash
# Run script with verbose output
bash -x deploy/scripts/deploy-monolith.sh start

# Docker verbose
docker-compose -f scripts/docker-compose.yml --verbose up

# View environment
env | grep -i contract
env | grep -i database
```

## Still Not Working?

1. Check logs: `bash deploy/scripts/deploy-monolith.sh logs`
2. Clean everything and restart
3. Read `deploy/docs/QUICK_START.md`
4. Check Docker/PostgreSQL are properly installed

**Include these when reporting issues:**
- Error messages (exact text)
- OS version
- Output of `docker ps` or logs
- Steps to reproduce