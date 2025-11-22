#!/bin/bash

# Simple database backup script

cd "$(dirname "$0")/../.."

# Load .env if exists
if [ -f deploy/.env ]; then
    export $(grep -v '^#' deploy/.env | xargs)
fi

DB_HOST=${DB_HOST:-localhost}
DB_PORT=${DB_PORT:-5432}
DB_NAME=${DB_NAME:-contract_manager}
DB_USER=${DB_USER:-postgres}

BACKUP_DIR="backups"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
BACKUP_FILE="${BACKUP_DIR}/backup_${TIMESTAMP}.sql"

mkdir -p $BACKUP_DIR

echo "Creating backup..."
echo "Database: $DB_NAME"
echo "Output: $BACKUP_FILE"
echo ""

PGPASSWORD=$DB_PASSWORD pg_dump -h $DB_HOST -p $DB_PORT -U $DB_USER $DB_NAME > $BACKUP_FILE

if [ $? -eq 0 ]; then
    echo "✓ Backup created successfully"
    echo ""
    echo "Size: $(du -h $BACKUP_FILE | cut -f1)"
    echo ""
    echo "To restore:"
    echo "  psql -h $DB_HOST -p $DB_PORT -U $DB_USER -d $DB_NAME < $BACKUP_FILE"
else
    echo "✗ Backup failed"
    exit 1
fi
