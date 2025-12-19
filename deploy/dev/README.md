# Entity Hub - Development Mode

Fast development environment with hot reload for Entity Hub.

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
- OpenSSL

If not, run the monolith installer first:
```bash
cd ../monolith
./install-monolith.sh
```

### 2. Configure

Edit `dev.ini`:

```ini
# Leave passwords empty for auto-generation
DB_PASSWORD=
JWT_SECRET=

# Ports
API_PORT=3000
VITE_PORT=5173

# Database (separate from production)
DB_NAME=ehopdb_dev
DB_USER=ehopuser
```

### 3. Start

```bash
./start-dev.sh
```

### 4. Access

- **Frontend (Vite)**: http://localhost:5173 ⚡ Hot reload!
- **Backend API**: http://localhost:3000
- **API Health**: http://localhost:3000/health

---

## 📝 Commands

```bash
# Start development environment
./start-dev.sh

# Stop all services
./stop-dev.sh

# Destroy dev environment (⚠️ deletes dev database!)
./destroy-dev.sh
```

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
./start-dev.sh

# 2. Edit frontend code
cd ../../frontend/src/
nano components/YourComponent.jsx

# 3. See changes instantly in browser (no restart needed!)

# 4. Edit backend code
cd ../../backend/
nano server/your_handler.go

# 5. Rebuild and restart backend
go build -o ehop-backend-dev ./cmd/server/main.go
./ehop-backend-dev

# Or use the full restart
cd ../../deploy/dev
./stop-dev.sh
./start-dev.sh
```

---

## 🗄️ Database

### Separate Development Database

Development mode uses `ehopdb_dev` (separate from production `ehopdb`).

This means:
- ✅ You can test destructive operations safely
- ✅ Production data is never affected
- ✅ You can reset dev database anytime
- ✅ Both databases can coexist on the same machine

### Initialization

On first run, the database is empty:

1. Access http://localhost:5173
2. Follow the initialization wizard
3. Create your first admin user

Check status:
```bash
curl http://localhost:3000/api/initialize/status
```

### Reset Dev Database

```bash
# Option 1: Use destroy script (removes everything)
./destroy-dev.sh

# Option 2: Manual reset (keeps user)
sudo -u postgres psql -c "DROP DATABASE ehopdb_dev;"
sudo -u postgres psql -c "CREATE DATABASE ehopdb_dev OWNER ehopuser;"
```

### Backup

```bash
# Backup dev database
pg_dump -h localhost -U ehopuser ehopdb_dev > dev_backup.sql

# Restore
psql -h localhost -U ehopuser ehopdb_dev < dev_backup.sql
```

---

## 🔐 Security

### Auto-Generated Passwords

Leave `DB_PASSWORD` and `JWT_SECRET` empty in `dev.ini` to auto-generate:

```ini
DB_PASSWORD=
JWT_SECRET=
```

On first run:
1. Secure passwords are generated
2. Displayed in terminal (save them!)
3. Saved to `dev.ini`
4. Used for all future runs

### Manual Passwords

```bash
# Generate 64-character password
openssl rand -base64 48 | tr -d "=+/" | cut -c1-64
```

Then paste into `dev.ini`:
```ini
DB_PASSWORD=your_password_here
JWT_SECRET=your_jwt_secret_here
```

---

## 📊 Monitoring

### Logs

```bash
# Backend logs
tail -f ../../logs/backend_dev/server.log

# Vite logs
tail -f ../../logs/vite-dev.log

# Follow both
tail -f ../../logs/backend_dev/server.log ../../logs/vite-dev.log
```

### Health Checks

```bash
# Backend health
curl http://localhost:3000/health

# Initialize status
curl http://localhost:3000/api/initialize/status

# Test API endpoint
curl http://localhost:3000/api/users \
  -H "Authorization: Bearer YOUR_TOKEN"
```

### Process Status

```bash
# Check backend
cat /tmp/ehop-backend-dev.pid
ps aux | grep ehop-backend-dev

# Check Vite
cat /tmp/ehop-vite-dev.pid
ps aux | grep vite

# Check PostgreSQL
sudo systemctl status postgresql
```

---

## 🔧 Troubleshooting

### Port 5173 Already in Use

```bash
# Find what's using the port
lsof -i :5173

# Kill the process
kill -9 <PID>

# Or change port in dev.ini
VITE_PORT=5174
```

### Backend Not Starting

```bash
# Check logs
tail -50 ../../logs/backend_dev/server.log

# Verify database connection
psql -h localhost -U ehopuser -d ehopdb_dev

# Check environment variables
echo $DB_PASSWORD
echo $JWT_SECRET
```

### Vite Not Starting

```bash
# Check logs
tail -50 ../../logs/vite-dev.log

# Verify node_modules
cd ../../frontend
npm install

# Try manual start
npm run dev -- --port 5173
```

### Database Connection Failed

```bash
# Start PostgreSQL
sudo systemctl start postgresql

# Check status
sudo systemctl status postgresql

# Test connection
pg_isready -h localhost -p 5432

# Verify database exists
psql -h localhost -U postgres -c "\l" | grep ehopdb_dev
```

### CORS Errors

If you see CORS errors in browser console:

1. Check `CORS_ALLOWED_ORIGINS` in `dev.ini`:
   ```ini
   CORS_ALLOWED_ORIGINS=http://localhost:5173,http://localhost:3000
   ```

2. Ensure `VITE_API_URL` points to backend:
   ```ini
   VITE_API_URL=http://localhost:3000/api
   ```

3. Restart both services:
   ```bash
   ./stop-dev.sh
   ./start-dev.sh
   ```

### Module Not Found

```bash
# Backend
cd ../../backend
go mod tidy
go mod download

# Frontend
cd ../../frontend
rm -rf node_modules package-lock.json
npm install
```

---

## 📁 File Structure

```
dev/
├── start-dev.sh          # Start dev environment
├── stop-dev.sh           # Stop all services
├── destroy-dev.sh        # Destroy dev environment
├── dev.ini               # Configuration file
└── README.md             # This file

Generated during runtime:
├── /tmp/ehop-backend-dev.pid    # Backend PID
├── /tmp/ehop-vite-dev.pid       # Vite PID
├── ../../logs/backend_dev/      # Backend logs
└── ../../logs/vite-dev.log      # Vite logs
```

---

## 🎯 Best Practices

### 1. Use Separate Databases

Always use the dev database (`ehopdb_dev`) for development:
- Never modify production database during development
- Test migrations on dev database first
- Keep production data pristine

### 2. Hot Reload Workflow

Take advantage of Vite's hot reload:
```bash
# Keep dev environment running
./start-dev.sh

# Edit frontend → See changes instantly
# Edit backend → Restart only backend:
cd ../../backend
go build -o ehop-backend-dev ./cmd/server/main.go
pkill ehop-backend-dev
nohup ./ehop-backend-dev > ../logs/backend_dev/server.log 2>&1 &
```

### 3. Debug Mode

Enable verbose logging in `dev.ini`:
```ini
LOG_LEVEL=debug
APP_ENV=development
```

### 4. Test API with curl

```bash
# Health check
curl http://localhost:3000/health

# Login
curl -X POST http://localhost:3000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"password"}'

# Get entities (with token)
curl http://localhost:3000/api/entities \
  -H "Authorization: Bearer YOUR_TOKEN"
```

### 5. Browser DevTools

- React DevTools (Chrome/Firefox extension)
- Network tab for API calls
- Console for errors and logs
- Application tab for localStorage/cookies

---

## 🔄 Switching Between Modes

### From Development to Production (Monolith)

```bash
# 1. Stop dev
./stop-dev.sh

# 2. Start monolith
cd ../monolith
./start-monolith.sh
```

### From Development to Docker

```bash
# 1. Stop dev
./stop-dev.sh

# 2. Start docker
cd ../docker
docker-compose up -d
```

**Note**: Each mode uses its own database, so data is not shared.

---

## 🐛 Debugging Tips

### Backend Debugging

Add print statements:
```go
fmt.Printf("DEBUG: User ID: %d\n", userID)
log.Printf("DEBUG: Query result: %+v\n", result)
```

Check logs:
```bash
tail -f ../../logs/backend_dev/server.log
```

### Frontend Debugging

Use console.log:
```javascript
console.log('Component mounted:', this.props);
console.log('API response:', response.data);
```

Use React DevTools to inspect component state and props.

### Database Debugging

```bash
# Connect to dev database
psql -h localhost -U ehopuser -d ehopdb_dev

# List tables
\dt

# Query data
SELECT * FROM users;

# Check constraints
\d users
```

---

## 🆚 Development vs Monolith vs Docker

| Feature               | Development | Monolith | Docker |
|-----------------------|-------------|----------|--------|
| **Hot Reload**        | ✅ Yes      | ❌ No    | ❌ No  |
| **Build Speed**       | ⚡ Fast     | Medium   | Slow   |
| **Production-like**   | ❌ No       | ✅ Yes   | ✅ Yes |
| **Isolated**          | ❌ No       | ❌ No    | ✅ Yes |
| **Debug Friendly**    | ✅ Yes      | ⚠️ Ok    | ⚠️ Ok  |
| **Database**          | dev only    | prod     | prod   |
| **SSL**               | ❌ No       | ✅ Yes   | ✅ Yes |
| **Best For**          | Coding      | Testing  | Deploy |

---

## 📚 See Also

- [Monolith Mode](../monolith/README.md) - Production-like deployment
- [Docker Mode](../docker/README.md) - Containerized deployment
- [Main README](../README.md) - Overview of all modes
- [Backend README](../../backend/README.md) - Backend documentation
- [Frontend README](../../frontend/README.md) - Frontend documentation

---

## 🤝 Contributing

When developing new features:

1. Start dev environment: `./start-dev.sh`
2. Make changes with hot reload
3. Test on dev database
4. Test on monolith mode before committing
5. Document changes in README files

---

**Happy coding! ⚡🚀**