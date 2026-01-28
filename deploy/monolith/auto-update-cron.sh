#!/usr/bin/env bash

# Client Hub - Monolith Cron Update Wrapper
# - Pulls latest code from git (optional)
# - Runs monolith auto-update (backup + rebuild + migrate + restart)
# - Writes logs to a file for cron usage
#
# Usage (cron):
#   0 3 * * * /path/to/deploy/monolith/auto-update-cron.sh >> /var/log/client-hub-monolith-update.log 2>&1
#
# Optional env:
#   REPO_DIR=/path/to/repo
#   BRANCH=main
#   INI_FILE=/path/to/deploy/monolith/monolith.ini
#   AUTO_BACKUP=true|false
#   LOG_FILE=/var/log/client-hub-monolith-update.log
#
# Notes:
# - This script is safe to run on hosts without other container privileges.
# - It does NOT require Docker or docker socket access.

set -euo pipefail

REPO_DIR="${REPO_DIR:-}"
BRANCH="${BRANCH:-main}"
INI_FILE="${INI_FILE:-}"
AUTO_BACKUP="${AUTO_BACKUP:-true}"
LOG_FILE="${LOG_FILE:-}"
LOCK_DIR="${LOCK_DIR:-/tmp/client-hub-monolith-update.lock}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_REPO_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
DEFAULT_INI_FILE="${SCRIPT_DIR}/monolith.ini"

if [[ -z "$REPO_DIR" ]]; then
  REPO_DIR="$DEFAULT_REPO_DIR"
fi

if [[ -z "$INI_FILE" ]]; then
  INI_FILE="$DEFAULT_INI_FILE"
fi

timestamp() {
  date +"%Y-%m-%d %H:%M:%S"
}

log() {
  local msg="$1"
  if [[ -n "$LOG_FILE" ]]; then
    echo "$(timestamp) $msg" | tee -a "$LOG_FILE"
  else
    echo "$(timestamp) $msg"
  fi
}

acquire_lock() {
  mkdir "$LOCK_DIR" 2>/dev/null
}

release_lock() {
  rmdir "$LOCK_DIR" 2>/dev/null || true
}

if ! acquire_lock; then
  log "⚠️ Another update is running. Exiting."
  exit 0
fi

trap release_lock EXIT

log "🚀 Starting monolith cron update"
log "Repo: $REPO_DIR"
log "Branch: $BRANCH"
log "INI: $INI_FILE"

if [[ ! -d "$REPO_DIR/.git" ]]; then
  log "❌ Not a git repository: $REPO_DIR"
  exit 1
fi

cd "$REPO_DIR"

log "🔄 Fetching latest changes..."
git fetch --all --prune

if ! git show-ref --verify --quiet "refs/remotes/origin/${BRANCH}"; then
  log "❌ Remote branch not found: origin/${BRANCH}"
  exit 1
fi

LOCAL_SHA="$(git rev-parse HEAD)"
REMOTE_SHA="$(git rev-parse "origin/${BRANCH}")"

if [[ "$LOCAL_SHA" != "$REMOTE_SHA" ]]; then
  log "⬆️ Updates detected. Pulling latest..."
  git checkout "$BRANCH"
  git pull --ff-only
else
  log "✅ No updates detected. Skipping auto-update."
  exit 0
fi

log "🧭 Running monolith auto-update..."
INI_FILE="$INI_FILE" AUTO_BACKUP="$AUTO_BACKUP" "$SCRIPT_DIR/auto-update.sh"

log "✅ Monolith cron update complete."
