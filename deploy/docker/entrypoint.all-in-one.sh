#!/bin/sh
set -eu

# ==============================================================================
# All-in-one container entrypoint:
# - Initializes and starts PostgreSQL
# - Runs backend migrations
# - Starts backend API
# - Starts Nginx serving frontend
# ==============================================================================

# Load .env file if exists (for consistency with docker-compose)
if [ -f /app/.env ]; then
  export $(grep -v '^#' /app/.env | xargs)
fi

log() {
  printf "%s %s\n" "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" "$*"
}

# Defaults
: "${DB_HOST:=127.0.0.1}"
: "${DB_PORT:=5432}"
: "${DB_NAME:=ehopdb}"
: "${DB_USER:=ehopuser}"
: "${DB_PASSWORD:=}"
: "${DB_SSLMODE:=disable}"
: "${API_PORT:=3000}"
: "${APP_ENV:=production}"
: "${JWT_SECRET:=}"
: "${POSTGRES_PASSWORD:=${DB_PASSWORD:-}}"
: "${POSTGRES_INITDB_ARGS:=--auth-local=trust --auth-host=scram-sha-256}"
: "${POSTGRES_DATA_DIR:=/var/lib/postgresql/data}"
: "${POSTGRES_LOG_DIR:=/var/lib/postgresql/logs}"
: "${POSTGRES_SOCKET_DIR:=/var/run/postgresql}"
: "${SSL_DIR:=/etc/nginx/ssl}"
: "${NGINX_CONF:=/etc/nginx/nginx.conf}"
: "${LOG_DIR:=/app/logs}"
: "${BACKEND_BIN:=/app/main}"

generate_secret() {
  openssl rand -base64 48 | tr -d "=+/" | cut -c1-64
}

if [ -z "$DB_PASSWORD" ]; then
  DB_PASSWORD="$(generate_secret)"
fi

if [ -z "$POSTGRES_PASSWORD" ]; then
  POSTGRES_PASSWORD="$DB_PASSWORD"
fi

if [ -z "$JWT_SECRET" ]; then
  JWT_SECRET="$(generate_secret)"
fi

export DB_HOST DB_PORT DB_NAME DB_USER DB_PASSWORD DB_SSLMODE API_PORT APP_ENV JWT_SECRET POSTGRES_PASSWORD POSTGRES_INITDB_ARGS

ensure_dir() {
  mkdir -p "$1"
  chown -R postgres:postgres "$1"
  chmod 700 "$1"
}

wait_for_postgres() {
  for i in $(seq 1 60); do
    if pg_isready -h "$POSTGRES_SOCKET_DIR" -p "$DB_PORT" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  return 1
}

run_as_postgres() {
  su-exec postgres sh -c "$1"
}

init_postgres_if_needed() {
  ensure_dir "$POSTGRES_DATA_DIR"
  ensure_dir "$POSTGRES_LOG_DIR"
  mkdir -p "$POSTGRES_SOCKET_DIR"
  chown -R postgres:postgres "$POSTGRES_SOCKET_DIR"

  if [ ! -s "$POSTGRES_DATA_DIR/PG_VERSION" ]; then
    log "Initializing PostgreSQL data directory..."
    PWFILE="/tmp/pg_pwfile"
    printf "%s" "$POSTGRES_PASSWORD" > "$PWFILE"
    chown postgres:postgres "$PWFILE"
    chmod 600 "$PWFILE"
    run_as_postgres "LC_ALL=C initdb -D '$POSTGRES_DATA_DIR' --encoding=UTF8 --locale=C $POSTGRES_INITDB_ARGS --pwfile='$PWFILE'"
    rm -f "$PWFILE"
  fi
}

start_postgres() {
  log "Starting PostgreSQL..."
  run_as_postgres "pg_ctl -D '$POSTGRES_DATA_DIR' -l '$POSTGRES_LOG_DIR/postgres.log' -o \"-p $DB_PORT -h 0.0.0.0 -k $POSTGRES_SOCKET_DIR\" start"
}

configure_database() {
  if ! wait_for_postgres; then
    log "PostgreSQL did not become ready in time"
    exit 1
  fi

  log "Configuring database and user..."

  USER_EXISTS=$(run_as_postgres "psql -h $POSTGRES_SOCKET_DIR -p $DB_PORT -tAc \"SELECT 1 FROM pg_roles WHERE rolname='${DB_USER}'\"")
  if [ "$USER_EXISTS" != "1" ]; then
    if [ -z "$DB_PASSWORD" ]; then
      log "DB_PASSWORD is required to create the database user"
      exit 1
    fi
    run_as_postgres "psql -h $POSTGRES_SOCKET_DIR -p $DB_PORT -c \"CREATE USER ${DB_USER} WITH PASSWORD '${DB_PASSWORD}';\""
  else
    if [ -n "$DB_PASSWORD" ]; then
      run_as_postgres "psql -h $POSTGRES_SOCKET_DIR -p $DB_PORT -c \"ALTER USER ${DB_USER} WITH PASSWORD '${DB_PASSWORD}';\""
    fi
  fi

  DB_EXISTS=$(run_as_postgres "psql -h $POSTGRES_SOCKET_DIR -p $DB_PORT -tAc \"SELECT 1 FROM pg_database WHERE datname='${DB_NAME}'\"")
  if [ "$DB_EXISTS" != "1" ]; then
    run_as_postgres "psql -h $POSTGRES_SOCKET_DIR -p $DB_PORT -c \"CREATE DATABASE ${DB_NAME} OWNER ${DB_USER};\""
  fi

  run_as_postgres "psql -h $POSTGRES_SOCKET_DIR -p $DB_PORT -c \"GRANT ALL PRIVILEGES ON DATABASE ${DB_NAME} TO ${DB_USER};\""
}

run_migrations() {
  log "Running migrations..."
  cat > /tmp/migrate.sh << 'EOF'
#!/bin/sh
export MIGRATE_ONLY=true
export AUTO_MIGRATIONS=true
exec /app/main
EOF
  chmod +x /tmp/migrate.sh
  /tmp/migrate.sh
  rm /tmp/migrate.sh
  log "Migrations complete."
}

generate_ssl() {
  if [ -x "/usr/local/bin/generate-ssl.sh" ]; then
    log "Generating SSL certificates..."
    /usr/local/bin/generate-ssl.sh "$SSL_DIR"
  else
    log "SSL generator not found; skipping."
  fi
}

start_backend() {
  log "Starting backend on port ${API_PORT}..."
  mkdir -p "$LOG_DIR"
  chown -R appuser:appuser "$LOG_DIR"
  su-exec appuser "$BACKEND_BIN" &
  mkdir -p /app/pids
  chown -R appuser:appuser /app/pids
  echo $! > /app/pids/ehop-backend.pid
}

start_nginx() {
  log "Starting nginx..."
  if [ -f /etc/nginx/conf.d/default.conf ]; then
    sed -i "s|proxy_pass http://127.0.0.1:[0-9]*;|proxy_pass http://127.0.0.1:${API_PORT};|g" /etc/nginx/conf.d/default.conf
  fi
  nginx -t -c "$NGINX_CONF"
  nginx -c "$NGINX_CONF"
}

stop_all() {
  log "Shutting down..."
  if [ -f /app/pids/ehop-backend.pid ]; then
    kill "$(cat /app/pids/ehop-backend.pid)" 2>/dev/null || true
  fi
  nginx -s quit 2>/dev/null || true
  run_as_postgres "pg_ctl -D '$POSTGRES_DATA_DIR' stop -m fast" || true
}

trap stop_all INT TERM

init_postgres_if_needed
start_postgres
configure_database
run_migrations
generate_ssl
start_backend
start_nginx

log "All services started."

# Wait indefinitely while services run
while true; do
  if ! kill -0 "$(cat /app/pids/ehop-backend.pid 2>/dev/null || echo 0)" 2>/dev/null; then
    log "Backend process stopped. Exiting."
    stop_all
    exit 1
  fi
  sleep 5
done
