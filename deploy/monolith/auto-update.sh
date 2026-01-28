#!/usr/bin/env bash

# Client Hub - Monolith Auto Update
# - Optional pre-backup (config + DB snapshot)
# - Build backend + frontend
# - Run migrations
# - Restart services
#
# Usage:
#   ./auto-update.sh
#   AUTO_BACKUP=true ./auto-update.sh
#   INI_FILE=./monolith.ini ./auto-update.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
INI_FILE="${INI_FILE:-$SCRIPT_DIR/monolith.ini}"

AUTO_BACKUP="${AUTO_BACKUP:-true}"
BACKUP_DB_DIR="${BACKUP_DB_DIR:-$SCRIPT_DIR/backups/db}"
BACKUP_DB_DAYS="${BACKUP_DB_DAYS:-90}"
BACKUP_DB_MAX_BYTES="${BACKUP_DB_MAX_BYTES:-524288000}"
BACKUP_DB_COMPRESS="${BACKUP_DB_COMPRESS:-true}"

load_ini_file() {
  local file="$1"
  if [[ ! -f "$file" ]]; then
    echo "❌ Missing config file: $file"
    exit 1
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

echo "🚀 Starting monolith auto-update..."
echo "Project root: $PROJECT_ROOT"
echo "Config file:  $INI_FILE"
echo ""

load_ini_file "$INI_FILE"

export DB_HOST="${DB_HOST:-localhost}"
export DB_PORT="${DB_PORT:-5432}"
export DB_USER="${DB_USER:-ehopuser}"
export DB_NAME="${DB_NAME:-ehopdb}"

echo "🔍 Checking PostgreSQL..."
if ! pg_isready -h "$DB_HOST" -p "$DB_PORT" >/dev/null 2>&1; then
  echo "❌ PostgreSQL is not ready at ${DB_HOST}:${DB_PORT}"
  exit 1
fi
echo "✅ PostgreSQL is ready"
echo ""

if [[ "$AUTO_BACKUP" == "true" ]]; then
  echo "💾 Running configuration backup..."
  (cd "$SCRIPT_DIR" && make backup)
  echo ""

  echo "💾 Running database snapshot (rotating policy)..."
  INI_FILE="$INI_FILE" BACKUP_DIR="$BACKUP_DB_DIR" DAYS_KEEP="$BACKUP_DB_DAYS" MAX_TOTAL_BYTES="$BACKUP_DB_MAX_BYTES" COMPRESS="$BACKUP_DB_COMPRESS" "$PROJECT_ROOT/deploy/backup/backup-db.sh"
  echo ""
fi

echo "🛑 Stopping services..."
"$SCRIPT_DIR/stop-monolith.sh"
echo ""

echo "🚀 Starting services..."
"$SCRIPT_DIR/start-monolith.sh"
echo ""

echo "🏥 Health check..."
HEALTH_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:${API_PORT:-3000}/health || echo "000")
if [[ "$HEALTH_CODE" == "200" ]]; then
  echo "✅ Backend healthy (HTTP $HEALTH_CODE)"
else
  echo "⚠️ Backend not healthy yet (HTTP $HEALTH_CODE)"
  echo "Check logs: tail -f $PROJECT_ROOT/logs/backend/backend.log"
fi

echo ""
echo "✅ Auto-update complete."
