#!/bin/bash

# Contract Manager - Monolith Mode Startup Script
# This script reads monolith.ini, generates secure passwords if needed,
# and starts all services for monolith deployment.

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Configuration file
CONFIG_FILE="monolith.ini"

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

# Check if config file exists
if [ ! -f "$CONFIG_FILE" ]; then
    echo -e "${RED}❌ Error: $CONFIG_FILE not found!${NC}"
    echo "Copy from docker/.env.example and adjust for monolith mode."
    exit 1
fi

echo -e "${BLUE}🚀 Starting Contract Manager (Monolith Mode)${NC}"
echo -e "${BLUE}================================================${NC}"
echo ""

# Load configuration from monolith.ini
echo "📄 Loading configuration from $CONFIG_FILE..."
if [ -f "$CONFIG_FILE" ]; then
    # Read and export variables, but handle passwords specially
    while IFS='=' read -r key value; do
        # Skip comments and empty lines
        [[ $key =~ ^[[:space:]]*# ]] && continue
        [[ -z "$key" ]] && continue

        # Remove spaces
        key=$(echo "$key" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        value=$(echo "$value" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')

        # Generate passwords if empty
        if [[ "$key" == "DB_PASSWORD" && -z "$value" ]]; then
            value=$(generate_password)
            GENERATED_DB_PASSWORD="$value"
            echo -e "${GREEN}✓ Generated secure DB_PASSWORD${NC}"
        elif [[ "$key" == "JWT_SECRET" && -z "$value" ]]; then
            value=$(generate_password)
            GENERATED_JWT_SECRET="$value"
            echo -e "${GREEN}✓ Generated secure JWT_SECRET${NC}"
        fi

        # Export the variable
        export "$key=$value"
    done < "$CONFIG_FILE"
fi

echo ""

# Check if PostgreSQL is running
echo "🔍 Checking PostgreSQL..."
if ! pg_isready -h ${DB_HOST:-localhost} -p ${DB_PORT:-5432} > /dev/null 2>&1; then
    echo -e "${RED}❌ PostgreSQL is not running on ${DB_HOST:-localhost}:${DB_PORT:-5432}!${NC}"
    echo ""
    echo "Start PostgreSQL:"
    echo "  Linux:   sudo systemctl start postgresql"
    echo "  macOS:   brew services start postgresql"
    echo "  Docker:  docker run -d --name postgres -e POSTGRES_PASSWORD=yourpass -p 5432:5432 postgres:16"
    exit 1
fi
echo -e "${GREEN}✓ PostgreSQL is running${NC}"

# Check/create database
echo "🗄️  Checking database..."
if ! psql -h ${DB_HOST:-localhost} -p ${DB_PORT:-5432} -U ${DB_USER:-postgres} -lqt 2>/dev/null | cut -d \| -f 1 | grep -qw ${DB_NAME}; then
    echo "Creating database ${DB_NAME}..."
    createdb -h ${DB_HOST:-localhost} -p ${DB_PORT:-5432} -U ${DB_USER:-postgres} ${DB_NAME} 2>/dev/null || {
        echo -e "${YELLOW}⚠️  Could not create database. Make sure user ${DB_USER:-postgres} has permissions.${NC}"
    }

    # Run schema if exists
    if [ -f "../backend/database/schema.sql" ]; then
        echo "Running database schema..."
        PGPASSWORD=${DB_PASSWORD} psql -h ${DB_HOST:-localhost} -p ${DB_PORT:-5432} -U ${DB_USER} -d ${DB_NAME} -f ../backend/database/schema.sql >/dev/null 2>&1 || {
            echo -e "${YELLOW}⚠️  Could not run schema. Check database permissions.${NC}"
        }
    fi
fi
echo -e "${GREEN}✓ Database ready${NC}"
echo ""

# Setup nginx
echo "🌐 Setting up nginx..."
if ! command -v nginx >/dev/null 2>&1; then
    echo -e "${RED}❌ nginx is not installed!${NC}"
    echo "Install nginx:"
    echo "  Ubuntu/Debian: sudo apt install nginx"
    echo "  CentOS/RHEL:   sudo yum install nginx"
    echo "  macOS:         brew install nginx"
    exit 1
fi
echo -e "${GREEN}✓ nginx is installed${NC}"

# Create nginx config
NGINX_CONF="/tmp/entity-hub-monolith.conf"
cat > "$NGINX_CONF" << EOF
# Entity Hub Monolith Nginx Config
server {
    listen ${FRONTEND_PORT:-80};
    server_name localhost;

    # Frontend proxy
    location / {
        proxy_pass http://localhost:5173;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }

    # API proxy
    location /api {
        proxy_pass http://localhost:${API_PORT:-3000};
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}

server {
    listen ${FRONTEND_HTTPS_PORT:-443} ssl;
    server_name localhost;

    ssl_certificate ${SSL_CERTS_PATH:-./certs/ssl}/server.crt;
    ssl_certificate_key ${SSL_CERTS_PATH:-./certs/ssl}/server.key;

    # Frontend proxy
    location / {
        proxy_pass http://localhost:5173;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }

    # API proxy
    location /api {
        proxy_pass http://localhost:${API_PORT:-3000};
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF

# Generate SSL certificates using centralized script
echo "🔐 Generating SSL certificates..."
SSL_DIR="${SSL_CERTS_PATH:-./certs/ssl}"
mkdir -p "$SSL_DIR"

# Call centralized generate-ssl.sh script
if [ -f "../generate-ssl.sh" ]; then
    ../generate-ssl.sh "$SSL_DIR" || {
        echo -e "${YELLOW}⚠️  Could not generate certificates using generate-ssl.sh${NC}"
    }
else
    echo -e "${RED}❌ Error: generate-ssl.sh not found at ../generate-ssl.sh${NC}"
    exit 1
fi
echo -e "${GREEN}✓ SSL certificates ready${NC}"

# Start nginx with custom config
sudo nginx -c "$NGINX_CONF" -p /tmp &
NGINX_PID=$!
echo -e "${GREEN}✓ nginx started (PID: $NGINX_PID)${NC}"

# Start backend
echo "🔧 Starting backend service..."
cd ../backend
go run cmd/server/main.go &
BACKEND_PID=$!
echo -e "${GREEN}✓ Backend started (PID: $BACKEND_PID)${NC}"

# Wait for backend to initialize
sleep 3

# Check if backend is responding
if curl -s http://localhost:${API_PORT:-3000}/health >/dev/null 2>&1; then
    echo -e "${GREEN}✓ Backend health check passed${NC}"
else
    echo -e "${YELLOW}⚠️  Backend may not be fully ready yet${NC}"
fi

# Start frontend
echo "🌐 Starting frontend service..."
cd ../frontend
npm run dev &
FRONTEND_PID=$!
echo -e "${GREEN}✓ Frontend started (PID: $FRONTEND_PID)${NC}"

echo ""
echo -e "${GREEN}🎉 All services started successfully!${NC}"
echo ""
echo -e "${BOLD}Services running:${NC}"
echo "  Application: https://localhost:${FRONTEND_HTTPS_PORT:-443} (nginx proxy with SSL)"
echo "  HTTP Fallback: http://localhost:${FRONTEND_PORT:-80}"
echo "  Direct Backend: http://localhost:${API_PORT:-3000}"
echo "  Direct Frontend: http://localhost:5173"
echo ""
echo "Press Ctrl+C to stop all services"
echo ""

# Print generated passwords with highlight
if [ -n "$GENERATED_DB_PASSWORD" ] || [ -n "$GENERATED_JWT_SECRET" ]; then
    print_highlight "🔐 IMPORTANT: Save these generated passwords!"
    echo ""

    if [ -n "$GENERATED_DB_PASSWORD" ]; then
        echo -e "${BOLD}${RED}Database Password (DB_PASSWORD):${NC}"
        echo -e "${BOLD}${GREEN}$GENERATED_DB_PASSWORD${NC}"
        echo ""
    fi

    if [ -n "$GENERATED_JWT_SECRET" ]; then
        echo -e "${BOLD}${RED}JWT Secret (JWT_SECRET):${NC}"
        echo -e "${BOLD}${GREEN}$GENERATED_JWT_SECRET${NC}"
        echo ""
    fi

    print_highlight "💾 Copy and save these passwords securely!"
    echo -e "${YELLOW}They are required to run the application and cannot be recovered.${NC}"
    echo ""
fi

# Wait for Ctrl+C
trap "echo ''; echo 'Stopping services...'; sudo nginx -s stop 2>/dev/null; kill $BACKEND_PID $FRONTEND_PID $NGINX_PID 2>/dev/null; exit" INT TERM

wait
