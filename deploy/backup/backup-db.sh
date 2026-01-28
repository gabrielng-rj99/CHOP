#!/usr/bin/env bash

# Client Hub - Rotating PostgreSQL Backup
# - Daily snapshots (or manual)
# - Retention by max days OR max total size
# - Compatible with Docker or Monolith via env vars

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"

load_env_file() {
  local file="$1"
  if [[ -f "$file" ]]; then
    set -a
    . "$file"
    set +a
  fi
}

load_ini_file() {
  local file="$1"
  if [[ ! -f "$file" ]]; then
    return
  fi

  while IFS= read -r line; do
    line="${line%%#*}"
    line="$(echo "$line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
    if [[ -z "$line" ]]; then
      continue
    fi
    if [[ "$line" =~ ^[A-Za-z_][A-Za-z0-9_]*= ]]; then
      local key="${line%%=*}"
      local value="${line#*=}"
      value="${value%\"}"
      value="${value#\"}"
      export "$key=$value"
    fi
  done < "$file"
}

if [[ -n "${ENV_FILE:-}" ]]; then
  load_env_file "$ENV_FILE"
else
  load_env_file "$PROJECT_ROOT/deploy/docker/.env"
fi

if [[ -n "${INI_FILE:-}" ]]; then
  load_ini_file "$INI_FILE"
else
  if [[ -z "${DB_NAME:-}" || -z "${DB_USER:-}" ]]; then
    load_ini_file "$PROJECT_ROOT/deploy/monolith/monolith.ini"
    load_ini_file "$PROJECT_ROOT/deploy/dev/dev.ini"
  fi
fi

BACKUP_DIR="${BACKUP_DIR:-./backups}"
DAYS_KEEP="${DAYS_KEEP:-90}"
MAX_TOTAL_BYTES="${MAX_TOTAL_BYTES:-524288000}" # 500 MB
COMPRESS="${COMPRESS:-true}"

DB_HOST="${DB_HOST:-localhost}"
DB_PORT="${DB_PORT:-5432}"
DB_USER="${DB_USER:-ehopuser}"
DB_NAME="${DB_NAME:-ehopdb}"
DB_PASSWORD="${DB_PASSWORD:-}"

mkdir -p "$BACKUP_DIR"

TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
EXT="sql"
if [[ "$COMPRESS" == "true" ]]; then
  EXT="sql.gz"
fi
OUT_FILE="$BACKUP_DIR/ehop_${TIMESTAMP}.${EXT}"

echo "Starting backup..."
echo "Database: ${DB_NAME}"
echo "Output:   ${OUT_FILE}"
echo ""

export PGPASSWORD="$DB_PASSWORD"

if [[ "$COMPRESS" == "true" ]]; then
  pg_dump -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" "$DB_NAME" | gzip > "$OUT_FILE"
else
  pg_dump -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" "$DB_NAME" > "$OUT_FILE"
fi

echo "Backup completed."
echo "Size: $(du -h "$OUT_FILE" | cut -f1)"
echo ""

# Retention by days
echo "Applying retention: keep last ${DAYS_KEEP} days"
find "$BACKUP_DIR" -type f -name 'ehop_*.sql*' -mtime +"$DAYS_KEEP" -print -delete || true

# Retention by total size
total_bytes() {
  if command -v du >/dev/null 2>&1; then
    du -sb "$BACKUP_DIR" 2>/dev/null | cut -f1 || echo 0
  else
    find "$BACKUP_DIR" -type f -name 'ehop_*.sql*' -printf '%s\n' | awk '{sum+=$1} END{print sum+0}'
  fi
}

echo "Applying retention: max total size ${MAX_TOTAL_BYTES} bytes"
current_size=$(total_bytes)
while [[ "$current_size" -gt "$MAX_TOTAL_BYTES" ]]; do
  oldest_file=$(ls -1t "$BACKUP_DIR"/ehop_*.sql* 2>/dev/null | tail -n1 || true)
  if [[ -z "$oldest_file" ]]; then
    break
  fi
  echo "Removing oldest backup: $oldest_file"
  rm -f "$oldest_file"
  current_size=$(total_bytes)
done

echo ""
echo "Retention complete."
echo "Current storage used: $(du -h "$BACKUP_DIR" | cut -f1)"
