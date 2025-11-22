#!/bin/bash

# Simple health check for Contract Manager

cd "$(dirname "$0")/../.."

# Load .env if exists
if [ -f deploy/.env ]; then
    export $(grep -v '^#' deploy/.env | xargs)
fi

API_PORT=${API_PORT:-3000}

echo "Health Check"
echo "============"
echo ""

# Check database
echo -n "Database: "
if pg_isready -h ${DB_HOST:-localhost} -p ${DB_PORT:-5432} > /dev/null 2>&1; then
    echo "✓ OK"
else
    echo "✗ FAIL"
fi

# Check backend
echo -n "Backend:  "
if curl -s -f http://localhost:$API_PORT/health > /dev/null 2>&1; then
    echo "✓ OK"
else
    echo "✗ FAIL"
fi

echo ""
