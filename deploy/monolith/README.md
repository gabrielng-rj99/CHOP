# Entity Hub - Monolith Deployment

Deploy Entity Hub on a single machine with all services running on the host (production-like environment).

## 📋 Overview

**Monolith mode** runs:
- ✅ Backend API (compiled Go binary)
- ✅ Frontend (static build served by Nginx)
- ✅ PostgreSQL (native installation)
- ✅ Nginx (reverse proxy + static files)
- ✅ SSL/TLS (auto-generated certificates)

This mode simulates a production environment without Docker.

---

## 🚀 Quick Start

### 1. Install Dependencies (First Time Only)

```bash
./install-monolith.sh
```

This installs:
- Go (latest)
- Node.js (latest LTS)
- PostgreSQL
- Nginx
- OpenSSL

### 2. Configure

Edit `monolith.ini`:

```ini
# Leave passwords empty for auto-generation
DB_PASSWORD=
JWT_SECRET=

# Ports
API_PORT=3000
FRONTEND_PORT=80
FRONTEND_HTTPS_PORT=443

# Database
DB_NAME=ehopdb
DB_USER=ehopuser
```

### 3. Start

```bash
./start-monolith.sh
```

### 4. Access

- **HTTPS**: https://localhost
- **HTTP**: http://localhost
- **API**: http://localhost:3000

---

## 📝 Commands

```bash
# Install dependencies (first time)
./install-monolith.sh

# Start all services
./start-monolith.sh

# Stop all services
./stop-monolith.sh

# Destroy everything (⚠️ deletes database!)
./destroy-monolith.sh
```

---

## 🔐 Security

### Auto-Generated Passwords

Leave `DB_PASSWORD` and `JWT_SECRET` empty in `monolith.ini` to auto-generate secure 64-character passwords.

When generated, they will be:
1. ✅ Displayed in the terminal (save them!)
2. ✅ Automatically saved back to `monolith.ini`
3. ✅ Used for all subsequent runs

### Manual Passwords

Generate secure passwords:

```bash
# 64-character password
openssl rand -base64 48 | tr -d "=+/" | cut -c1-64
```

Then paste them into `monolith.ini`:

```ini
DB_PASSWORD=your_64_char_password_here
JWT_SECRET=your_64_char_jwt_secret_here
```

---

## 🗄️ Database

### Initialization

On first run with an empty database, the system enters setup mode:

1. Access the app (https://localhost)
2. You'll see the initialization screen
3. Follow the prompts to create the first admin user

Check initialization status:

```bash
curl http://localhost:3000/api/initialize/status
```

### Backup

```bash
# Backup
pg_dump -h localhost -U ehopuser ehopdb > backup.sql

# Restore
psql -h localhost -U ehopuser ehopdb < backup.sql
```

### Reset Database

To start fresh:

```bash
# Option 1: Full destroy (removes everything)
./destroy-monolith.sh

# Option 2: Manual reset
sudo -u postgres psql -c "DROP DATABASE ehopdb;"
sudo -u postgres psql -c "CREATE DATABASE ehopdb OWNER ehopuser;"
```

---

## 🌐 Nginx Configuration

Nginx is automatically configured to:

- ✅ Serve frontend static files from `frontend/dist/`
- ✅ Proxy `/api/*` requests to backend (port 3000)
- ✅ Handle SSL/TLS (ports 80 → HTTP, 443 → HTTPS)
- ✅ Enable gzip compression
- ✅ Set security headers

Configuration is generated at: `nginx-runtime.conf`

### Custom Domain

To use a custom domain (e.g., `ehop.home.arpa`):

1. Edit `monolith.ini`:
   ```ini
   SSL_DOMAIN=ehop.home.arpa
   CORS_ALLOWED_ORIGINS=https://ehop.home.arpa
   ```

2. Add to `/etc/hosts`:
   ```
   127.0.0.1 ehop.home.arpa
   ```

3. Import certificate in browser or use mkcert:
   ```bash
   mkcert -install
   mkcert ehop.home.arpa
   ```

---

## 📊 Monitoring

### Logs

```bash
# Backend logs
tail -f ../../logs/backend/server.log

# Nginx access log
tail -f /tmp/ehop_access.log

# Nginx error log
tail -f /tmp/ehop_error.log
```

### Health Check

```bash
# Backend health
curl http://localhost:3000/health

# Via Nginx proxy
curl http://localhost/api/initialize/status
```

### Process Status

```bash
# Check backend
cat /tmp/ehop-backend.pid
ps aux | grep ehop-backend

# Check Nginx
sudo systemctl status nginx
ps aux | grep nginx

# Check PostgreSQL
sudo systemctl status postgresql
```

---

## 🔧 Troubleshooting

### Port 80/443 Already in Use

```bash
# Find what's using the port
sudo lsof -i :80
sudo lsof -i :443

# Stop conflicting service
sudo systemctl stop apache2  # or other web server
```

### Permission Denied on Nginx

```bash
# Nginx needs sudo for ports 80/443
# If error, stop and restart:
sudo pkill -9 nginx
./start-monolith.sh
```

### Backend Not Starting

```bash
# Check logs
tail -50 ../../logs/backend/server.log

# Check if database is accessible
psql -h localhost -U ehopuser -d ehopdb

# Verify environment variables
echo $DB_PASSWORD
echo $JWT_SECRET
```

### Database Connection Failed

```bash
# Start PostgreSQL
sudo systemctl start postgresql

# Check status
sudo systemctl status postgresql

# Test connection
pg_isready -h localhost -p 5432
```

### Frontend 404 Errors

```bash
# Verify build exists
ls -la ../../frontend/dist/

# Rebuild frontend
cd ../../frontend
npm run build
```

### SSL Certificate Errors

```bash
# Regenerate certificates
rm -rf ../../deploy/certs/ssl
./start-monolith.sh

# Or manually
cd ..
./generate-ssl.sh ./certs/ssl
```

---

## 📁 File Structure

```
monolith/
├── start-monolith.sh        # Start all services
├── stop-monolith.sh         # Stop all services
├── install-monolith.sh      # Install dependencies
├── destroy-monolith.sh      # Destroy everything
├── monolith.ini             # Configuration file
├── versions.ini             # Dependency versions
├── nginx-runtime.conf       # Generated Nginx config
└── README.md                # This file

Generated during runtime:
├── /tmp/ehop-backend.pid    # Backend process ID
├── /tmp/ehop_access.log     # Nginx access log
├── /tmp/ehop_error.log      # Nginx error log
└── ../../logs/backend/      # Backend logs
```

---

## 🔄 Updating

### Update Dependencies

```bash
# Edit versions.ini
nano versions.ini

# Reinstall
./install-monolith.sh
```

### Update Application

```bash
# Pull latest code
cd ../..
git pull

# Restart services
cd deploy/monolith
./stop-monolith.sh
./start-monolith.sh
```

---

## 🚀 Production Checklist

Before deploying to production:

- [ ] Change default passwords (64+ characters)
- [ ] Use a real domain with valid SSL certificate
- [ ] Configure firewall (UFW/iptables)
- [ ] Set up log rotation
- [ ] Configure automatic backups
- [ ] Enable monitoring (Prometheus/Grafana)
- [ ] Restrict CORS to your domain only
- [ ] Set `APP_ENV=production` in config
- [ ] Review and harden Nginx configuration
- [ ] Set up fail2ban for brute force protection
- [ ] Configure PostgreSQL for production workload

### Example: Setup Automatic Backups

```bash
# Create backup script
cat > ~/backup-ehop.sh << 'EOF'
#!/bin/bash
BACKUP_DIR=~/ehop-backups
mkdir -p $BACKUP_DIR
DATE=$(date +%Y%m%d_%H%M%S)
pg_dump -h localhost -U ehopuser ehopdb > $BACKUP_DIR/ehop_$DATE.sql
# Keep only last 7 days
find $BACKUP_DIR -name "ehop_*.sql" -mtime +7 -delete
EOF

chmod +x ~/backup-ehop.sh

# Add to crontab (daily at 2 AM)
crontab -e
# Add: 0 2 * * * /home/youruser/backup-ehop.sh
```

---

## 🆘 Support

- **Documentation**: `../../docs/`
- **API Docs**: http://localhost:3000/docs (when running)
- **Logs**: Check `../../logs/backend/server.log` first
- **Issues**: Open an issue on GitHub

---

## 📚 See Also

- [Development Mode](../dev/README.md) - Hot reload with Vite
- [Docker Mode](../docker/README.md) - Containerized deployment
- [Main README](../README.md) - Overview of all modes

---

**Happy deploying! 🚀**