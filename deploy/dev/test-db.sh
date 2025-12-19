#!/bin/bash
DB_HOST="localhost"
DB_PORT="5432"
DB_USER="ehopuser"
DB_NAME="ehopdb_dev"

echo "Checking if PostgreSQL is available..."
if command -v psql >/dev/null 2>&1; then
    echo "psql found"
else
    echo "psql not found"
    exit 1
fi

echo "Checking database connection..."
sudo -u postgres psql -h "$DB_HOST" -p "$DB_PORT" -c "SELECT version();" >/dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "PostgreSQL connection OK"
else
    echo "PostgreSQL connection FAILED"
    exit 1
fi

echo "Checking if database $DB_NAME exists..."
DB_EXISTS=$(sudo -u postgres psql -h "$DB_HOST" -p "$DB_PORT" -tAc "SELECT 1 FROM pg_database WHERE datname='${DB_NAME}'" 2>/dev/null | tr -d ' ')
echo "DB_EXISTS result: '$DB_EXISTS'"

if [[ "$DB_EXISTS" == "1" ]]; then
    echo "Database $DB_NAME exists, attempting to drop..."
    
    echo "Terminating active connections..."
    sudo -u postgres psql -h "$DB_HOST" -p "$DB_PORT" -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '${DB_NAME}' AND pid <> pg_backend_pid();" >/dev/null 2>&1 || echo "Warning: Could not terminate connections"
    
    sleep 1
    
    echo "Dropping database..."
    DROP_OUTPUT=$(sudo -u postgres psql -h "$DB_HOST" -p "$DB_PORT" -c "DROP DATABASE ${DB_NAME};" 2>&1)
    DROP_EXIT=$?
    
    echo "Drop exit code: $DROP_EXIT"
    echo "Drop output: $DROP_OUTPUT"
    
    if [ $DROP_EXIT -eq 0 ]; then
        echo "SUCCESS: Database dropped"
    else
        echo "FAILED: Could not drop database"
    fi
else
    echo "Database $DB_NAME does not exist"
fi
