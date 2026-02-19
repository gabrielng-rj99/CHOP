#!/bin/bash

# Client Hub - Monolith Mode Startup Script
# This script reads monolith.ini, generates secure passwords if needed,
# builds the application (Backend & Frontend), and starts all services.

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Resolve Paths
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
RUNTIME_DIR="$PROJECT_ROOT/app/monolith"
CONFIG_FILE="$SCRIPT_DIR/monolith.ini"

# Function to generate secure 64-character password
generate_password() {
    openssl rand -base64 48 | tr -d "=+/" | cut -c1-64
}

# Function to print highlighted message
print_highlight() {
    echo -e "${BOLD}${YELLOW}================================================================================${NC}"
    echo -e "${BOLD}${YELLOW}$1${NC}"
    echo -e "${BOLD}${YELLOW}================================================================================${NC}"
}

# Function to update ini file with generated password
update_ini_value() {
    local key=$1
    local value=$2
    local file=$3

    # Escape special characters in value for sed
    local escaped_value=$(echo "$value" | sed 's/[&/\]/\\&/g')

    # Update the line with the key
    sed -i "s|^${key}=.*|${key}=${escaped_value}|" "$file"
}

echo -e "${BLUE}🚀 Starting Client Hub (Monolith Mode)${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Check Config
if [ ! -f "$CONFIG_FILE" ]; then
    echo -e "${RED}❌ Error: $CONFIG_FILE not found!${NC}"
    echo "Copy from docker/.env.example and adjust for monolith mode."
    exit 1
fi

# Load configuration from monolith.ini
echo "📄 Loading configuration from $CONFIG_FILE..."

# First pass: read all variables into associative array
declare -A CONFIG
while IFS= read -r line; do
    # Skip comments and empty lines
    [[ "$line" =~ ^[[:space:]]*# ]] && continue
    [[ -z "$line" ]] && continue

    # Extract key=value
    if [[ "$line" =~ ^[[:space:]]*([A-Z_][A-Z0-9_]*)=(.*)$ ]]; then
        key="${BASH_REMATCH[1]}"
        value="${BASH_REMATCH[2]}"

        # Remove quotes if present
        value="${value%\"}"
        value="${value#\"}"

        # Store in array
        CONFIG[$key]="$value"
    fi
done < "$CONFIG_FILE"

# Second pass: handle password generation and expand variables
GENERATED_DB_PASSWORD=""
GENERATED_JWT_SECRET=""

for key in "${!CONFIG[@]}"; do
    value="${CONFIG[$key]}"

    # Generate passwords if empty
    if [[ "$key" == "DB_PASSWORD" && -z "$value" ]]; then
        value=$(generate_password)
        GENERATED_DB_PASSWORD="$value"
        CONFIG[$key]="$value"
        update_ini_value "$key" "$value" "$CONFIG_FILE"
        echo -e "${GREEN}✓ Generated secure DB_PASSWORD${NC}"
    elif [[ "$key" == "JWT_SECRET" && -z "$value" ]]; then
        value=$(generate_password)
        GENERATED_JWT_SECRET="$value"
        CONFIG[$key]="$value"
        update_ini_value "$key" "$value" "$CONFIG_FILE"
        echo -e "${GREEN}✓ Generated secure JWT_SECRET${NC}"
    fi

    # Expand variables in value (e.g., ${API_PORT})
    while [[ "$value" =~ \$\{([A-Z_][A-Z0-9_]*)\} ]]; do
        var_name="${BASH_REMATCH[1]}"
        var_value="${CONFIG[$var_name]}"
        value="${value//\$\{$var_name\}/$var_value}"
    done

    # Update in array and export
    CONFIG[$key]="$value"
    export "$key=$value"
done

echo -e "${GREEN}✓ Configuration loaded${NC}"
echo ""

# Set defaults if not in config
export DB_HOST="${DB_HOST:-localhost}"
export DB_PORT="${DB_PORT:-5432}"
export DB_USER="${DB_USER:-ehopuser}"
export DB_NAME="${DB_NAME:-ehopdb}"
export API_PORT="${API_PORT:-3000}"
export FRONTEND_PORT="${FRONTEND_PORT:-80}"
export FRONTEND_HTTPS_PORT="${FRONTEND_HTTPS_PORT:-443}"

# Check if PostgreSQL is running
echo "🔍 Checking PostgreSQL..."
if ! pg_isready -h "$DB_HOST" -p "$DB_PORT" > /dev/null 2>&1; then
    echo -e "${RED}❌ PostgreSQL is not running on ${DB_HOST}:${DB_PORT}!${NC}"
    echo ""
    echo "Start PostgreSQL:"
    echo "  Linux:   sudo systemctl start postgresql"
    echo "  macOS:   brew services start postgresql"
    exit 1
fi
echo -e "${GREEN}✓ PostgreSQL is running${NC}"

# Check/create database user and database
echo "🗄️  Checking database..."

# Check if user exists, if not create it
USER_EXISTS=$(sudo -u postgres psql -h "$DB_HOST" -p "$DB_PORT" -tAc "SELECT 1 FROM pg_roles WHERE rolname='${DB_USER}'" 2>/dev/null || echo "")
if [[ "$USER_EXISTS" != "1" ]]; then
    echo "Creating database user ${DB_USER}..."
    sudo -u postgres psql -h "$DB_HOST" -p "$DB_PORT" -c "CREATE USER ${DB_USER} WITH PASSWORD '${DB_PASSWORD}';" || {
         echo -e "${RED}❌ Failed to create database user.${NC}"
         exit 1
    }
    echo -e "${GREEN}✓ Database user created${NC}"
else
    echo -e "${GREEN}✓ Database user exists${NC}"
    # Update password in case it changed
    sudo -u postgres psql -h "$DB_HOST" -p "$DB_PORT" -c "ALTER USER ${DB_USER} WITH PASSWORD '${DB_PASSWORD}';" >/dev/null 2>&1 || true
fi

# Check if database exists
DB_EXISTS=$(sudo -u postgres psql -h "$DB_HOST" -p "$DB_PORT" -tAc "SELECT 1 FROM pg_database WHERE datname='${DB_NAME}'" 2>/dev/null || echo "")
if [[ "$DB_EXISTS" != "1" ]]; then
    echo "Creating database ${DB_NAME}..."
    sudo -u postgres psql -h "$DB_HOST" -p "$DB_PORT" -c "CREATE DATABASE ${DB_NAME} OWNER ${DB_USER};" || {
        echo -e "${RED}❌ Failed to create database.${NC}"
        exit 1
    }
    echo -e "${GREEN}✓ Database created${NC}"
else
    echo -e "${GREEN}✓ Database exists${NC}"
fi

# Grant privileges
sudo -u postgres psql -h "$DB_HOST" -p "$DB_PORT" -c "GRANT ALL PRIVILEGES ON DATABASE ${DB_NAME} TO ${DB_USER};" >/dev/null 2>&1 || true

echo -e "${GREEN}✓ Database ready${NC}"
echo ""

# Build Backend
echo "🔧 Building Backend..."
cd "$PROJECT_ROOT/backend"
mkdir -p "$RUNTIME_DIR/bin"
if go build -o "$RUNTIME_DIR/bin/ehop-backend.bin" ./main.go; then
    echo -e "${GREEN}✓ Backend built successfully${NC}"
else
    echo -e "${RED}❌ Backend build failed!${NC}"
    exit 1
fi

# Run Migrations
echo "🧭 Running database migrations..."
MIGRATE_ONLY=true AUTO_MIGRATIONS=true "$RUNTIME_DIR/bin/ehop-backend.bin"
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Database migrations applied${NC}"
else
    echo -e "${RED}❌ Database migrations failed!${NC}"
    exit 1
fi

# Build Frontend
echo "🎨 Building Frontend..."
cd "$PROJECT_ROOT/frontend"

# Clean dist directory to avoid permission issues
if [ -d "dist" ]; then
    echo "Cleaning old build..."
    rm -rf dist 2>/dev/null || {
        echo -e "${YELLOW}⚠️  Need sudo to clean old build (created by previous run)${NC}"
        sudo rm -rf dist || {
            echo -e "${RED}❌ Could not clean dist directory${NC}"
            exit 1
        }
    }
fi

# Set VITE_API_URL to /api for relative path
export VITE_API_URL="/api"

if npm run build >/dev/null 2>&1; then
    echo -e "${GREEN}✓ Frontend built successfully${NC}"
else
    echo -e "${RED}❌ Frontend build failed! Check errors:${NC}"
    npm run build
    exit 1
fi

FRONTEND_BUILD_DIR="$RUNTIME_DIR/frontend"
mkdir -p "$FRONTEND_BUILD_DIR"
rm -rf "$FRONTEND_BUILD_DIR"/*
mv dist/* "$FRONTEND_BUILD_DIR"/

# Setup nginx
echo "🌐 Setting up nginx..."
if ! command -v nginx >/dev/null 2>&1; then
    echo -e "${RED}❌ nginx is not installed!${NC}"
    exit 1
fi

# Generate SSL certificates using centralized script
echo "🔐 Generating SSL certificates..."
SSL_DIR="$RUNTIME_DIR/certs"
mkdir -p "$SSL_DIR"

if [ -f "$PROJECT_ROOT/deploy/generate-ssl.sh" ]; then
    bash "$PROJECT_ROOT/deploy/generate-ssl.sh" "$SSL_DIR" >/dev/null 2>&1 || {
         echo -e "${YELLOW}⚠️  Could not generate certificates using generate-ssl.sh, using fallback${NC}"
         openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
             -keyout "$SSL_DIR/server.key" \
             -out "$SSL_DIR/server.crt" \
             -subj "/C=US/ST=State/L=City/O=ClientHub/CN=localhost" 2>/dev/null
    }
else
    echo "Generating self-signed certificate..."
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout "$SSL_DIR/server.key" \
        -out "$SSL_DIR/server.crt" \
        -subj "/C=US/ST=State/L=City/O=ClientHub/CN=localhost" 2>/dev/null
fi
echo -e "${GREEN}✓ SSL certificates ready${NC}"

# Create nginx config in project directory
NGINX_CONF="$RUNTIME_DIR/nginx-runtime.conf"
cat > "$NGINX_CONF" << 'NGINX_EOF'
# Client Hub Monolith Nginx Config
events {
    worker_connections 1024;
}

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    # Logs
    access_log PROJECT_ROOT_PLACEHOLDER/app/monolith/logs/nginx_access.log;
    error_log PROJECT_ROOT_PLACEHOLDER/app/monolith/logs/nginx_error.log;

    # Gzip compression
    gzip on;
    gzip_vary on;
    gzip_min_length 1024;
    gzip_types text/plain text/css text/xml text/javascript application/javascript application/json application/xml+rss;

    server {
        listen FRONTEND_PORT_PLACEHOLDER;
        server_name localhost;

        # Frontend Static Files
        root "PROJECT_ROOT_PLACEHOLDER/app/monolith/frontend";
        index index.html;

        location / {
            try_files $uri $uri/ /index.html;
        }

        # API proxy
        location /api {
            proxy_pass http://127.0.0.1:API_PORT_PLACEHOLDER;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection 'upgrade';
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_cache_bypass $http_upgrade;
        }
    }

    server {
        listen FRONTEND_HTTPS_PORT_PLACEHOLDER ssl;
        server_name localhost;

        ssl_certificate SSL_DIR_PLACEHOLDER/server.crt;
        ssl_certificate_key SSL_DIR_PLACEHOLDER/server.key;
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers HIGH:!aNULL:!MD5;

        root "PROJECT_ROOT_PLACEHOLDER/app/monolith/frontend";
        index index.html;

        location / {
            try_files $uri $uri/ /index.html;
        }

        location /api {
            proxy_pass http://127.0.0.1:API_PORT_PLACEHOLDER;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection 'upgrade';
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_cache_bypass $http_upgrade;
        }
    }
}
NGINX_EOF

# Replace placeholders
sed -i "s|FRONTEND_PORT_PLACEHOLDER|${FRONTEND_PORT}|g" "$NGINX_CONF"
sed -i "s|FRONTEND_HTTPS_PORT_PLACEHOLDER|${FRONTEND_HTTPS_PORT}|g" "$NGINX_CONF"
sed -i "s|API_PORT_PLACEHOLDER|${API_PORT}|g" "$NGINX_CONF"
sed -i "s|PROJECT_ROOT_PLACEHOLDER|${PROJECT_ROOT}|g" "$NGINX_CONF"
sed -i "s|SSL_DIR_PLACEHOLDER|${SSL_DIR}|g" "$NGINX_CONF"

# Stop any existing nginx
echo "Stopping any existing nginx..."
sudo nginx -s stop 2>/dev/null || true
sudo pkill -9 nginx 2>/dev/null || true
sleep 2

# Test nginx config
echo "Testing nginx configuration..."
if ! sudo nginx -t -c "$NGINX_CONF" 2>/dev/null; then
    echo -e "${RED}❌ Nginx configuration test failed!${NC}"
    sudo nginx -t -c "$NGINX_CONF"
    exit 1
fi

# Start nginx with custom config
echo "Starting Nginx..."
sudo nginx -c "$NGINX_CONF"
echo -e "${GREEN}✓ nginx started${NC}"

# Prepare backend environment
echo "🔧 Starting backend service..."
cd "$PROJECT_ROOT/backend"

# Ensure logs directory exists
LOG_DIR="$RUNTIME_DIR/logs/backend"
mkdir -p "$LOG_DIR" "$RUNTIME_DIR/pids"

# Create a PID file location
PID_FILE="$RUNTIME_DIR/pids/ehop-backend.bin.pid"

# Export all necessary environment variables for the backend
export DB_HOST="$DB_HOST"
export DB_PORT="$DB_PORT"
export DB_USER="$DB_USER"
export DB_PASSWORD="$DB_PASSWORD"
export DB_NAME="$DB_NAME"
export JWT_SECRET="$JWT_SECRET"
export API_PORT="$API_PORT"
export LOG_FILE="$LOG_DIR/backend.log"

# Start backend in background
nohup "$RUNTIME_DIR/bin/ehop-backend.bin" > "$LOG_DIR/backend.log" 2>&1 &
BACKEND_PID=$!
echo $BACKEND_PID > "$PID_FILE"

echo -e "${GREEN}✓ Backend started (PID: $BACKEND_PID)${NC}"

# Wait for backend to initialize
echo "Waiting for backend to be ready..."
for i in {1..30}; do
    if curl -s http://localhost:${API_PORT}/health >/dev/null 2>&1; then
        echo -e "${GREEN}✓ Backend health check passed${NC}"
        break
    fi
    if [ $i -eq 30 ]; then
        echo -e "${YELLOW}⚠️  Backend may not be fully ready yet. Check logs: $LOG_DIR/backend.log${NC}"
        echo ""
        echo "Last 20 lines of backend log:"
        tail -20 "$LOG_DIR/backend.log"
    fi
    sleep 1
done

echo ""
echo -e "${GREEN}🎉 All services started successfully!${NC}"
echo ""
echo -e "${BOLD}Services running:${NC}"
echo "  Application (HTTPS): https://localhost:${FRONTEND_HTTPS_PORT}"
echo "  Application (HTTP):  http://localhost:${FRONTEND_PORT}"
echo "  Backend API:         http://localhost:${API_PORT}"
echo ""
echo -e "${BOLD}Logs:${NC}"
echo "  Backend:  $LOG_DIR/backend.log"
echo "  Nginx:    $RUNTIME_DIR/logs/nginx_access.log, $RUNTIME_DIR/logs/nginx_error.log"
echo ""
echo -e "${BOLD}Process IDs:${NC}"
echo "  Backend PID: $BACKEND_PID (saved to $PID_FILE)"
echo "  Nginx: running via sudo"
echo ""

# Print generated passwords with highlight
if [ -n "$GENERATED_DB_PASSWORD" ] || [ -n "$GENERATED_JWT_SECRET" ]; then
    print_highlight "🔐 IMPORTANT: Save these generated passwords!"
    echo ""

    if [ -n "$GENERATED_DB_PASSWORD" ]; then
        echo -e "${BOLD}${RED}Database Password (DB_PASSWORD):${NC}"
        echo -e "${BOLD}${GREEN}$GENERATED_DB_PASSWORD${NC}"
        echo ""
        echo "Saved to: $CONFIG_FILE"
        echo ""
    fi

    if [ -n "$GENERATED_JWT_SECRET" ]; then
        echo -e "${BOLD}${RED}JWT Secret (JWT_SECRET):${NC}"
        echo -e "${BOLD}${GREEN}$GENERATED_JWT_SECRET${NC}"
        echo ""
        echo "Saved to: $CONFIG_FILE"
        echo ""
    fi

    print_highlight "Passwords have been saved to $CONFIG_FILE"
    echo ""
fi

echo -e "${YELLOW}To stop services, run: ./deploy/monolith/stop-monolith.sh${NC}"
echo ""
echo "Press Ctrl+C to view this message again, or check logs for status."
