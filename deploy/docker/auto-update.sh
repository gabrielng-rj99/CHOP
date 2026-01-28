#!/usr/bin/env bash

# Client Hub - Docker Auto Update
# - Pull images
# - Optional pre-backup
# - Run migrations
# - Restart services
# - Health check
#
# Requirements:
# - docker compose
# - deploy/docker/.env configured
#
# Usage:
#   ./auto-update.sh
#   AUTO_BACKUP=true ./auto-update.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
DOCKER_DIR="$PROJECT_ROOT/deploy/docker"
ENV_FILE="${ENV_FILE:-$DOCKER_DIR/.env}"

AUTO_BACKUP="${AUTO_BACKUP:-true}"
COMPOSE_FILE="${COMPOSE_FILE:-$DOCKER_DIR/docker-compose.yml}"
PROJECT_NAME="${PROJECT_NAME:-ehop}"

echo "🚀 Starting auto-update..."
echo "Docker dir: $DOCKER_DIR"
echo ""

if [[ ! -f "$ENV_FILE" ]]; then
  echo "❌ Missing env file: $ENV_FILE"
  exit 1
fi

cd "$DOCKER_DIR"

echo "🔨 Building latest images..."
docker compose -f "$COMPOSE_FILE" -p "$PROJECT_NAME" build
echo ""

if [[ "$AUTO_BACKUP" == "true" ]]; then
  echo "💾 Running backup (rotating policy)..."
  docker compose -f "$COMPOSE_FILE" -p "$PROJECT_NAME" up -d backup
  docker compose -f "$COMPOSE_FILE" -p "$PROJECT_NAME" exec -T backup /usr/local/bin/backup-db.sh
  echo ""
fi

echo "🧭 Running migrations..."
docker compose -f "$COMPOSE_FILE" -p "$PROJECT_NAME" --profile migrations run --rm migrator
echo ""

echo "🔄 Restarting services..."
docker compose -f "$COMPOSE_FILE" -p "$PROJECT_NAME" up -d backend frontend
echo ""

echo "🏥 Health check..."
HEALTH_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:3000/health || echo "000")
if [[ "$HEALTH_CODE" == "200" ]]; then
  echo "✅ Backend healthy (HTTP $HEALTH_CODE)"
else
  echo "⚠️ Backend not healthy yet (HTTP $HEALTH_CODE)"
  echo "Check logs: docker compose -f \"$COMPOSE_FILE\" -p \"$PROJECT_NAME\" logs -f backend"
fi

echo ""
echo "✅ Auto-update complete."
