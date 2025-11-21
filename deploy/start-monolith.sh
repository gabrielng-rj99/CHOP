#!/bin/bash

# Simple script to run Contract Manager in monolith mode (no Docker)

set -e

# Load .env if exists
if [ -f .env ]; then
    export $(grep -v '^#' .env | xargs)
fi

# Override DB_HOST for local postgres
export DB_HOST=localhost

echo "Starting Contract Manager (Monolith Mode)"
echo "=========================================="
echo ""

# Check if PostgreSQL is running
if ! pg_isready -h localhost -p ${DB_PORT:-5432} > /dev/null 2>&1; then
    echo "❌ PostgreSQL is not running!"
    echo ""
    echo "Start it with:"
    echo "  Linux:   sudo systemctl start postgresql"
    echo "  macOS:   brew services start postgresql"
    exit 1
fi

echo "✓ PostgreSQL is running"

# Check if database exists
if ! psql -h localhost -p ${DB_PORT:-5432} -U ${DB_USER:-postgres} -lqt | cut -d \| -f 1 | grep -qw ${DB_NAME:-contract_manager}; then
    echo "Creating database ${DB_NAME:-contract_manager}..."
    createdb -h localhost -p ${DB_PORT:-5432} -U ${DB_USER:-postgres} ${DB_NAME:-contract_manager}

    # Run schema if exists
    if [ -f ../backend/database/schema.sql ]; then
        psql -h localhost -p ${DB_PORT:-5432} -U ${DB_USER:-postgres} -d ${DB_NAME:-contract_manager} -f ../backend/database/schema.sql
    fi
fi

echo "✓ Database ready"
echo ""

# Start backend
echo "Starting backend..."
cd ../backend
go run cmd/server/main.go &
BACKEND_PID=$!
echo "✓ Backend started (PID: $BACKEND_PID)"

# Wait a bit for backend to start
sleep 2

# Start frontend
echo "Starting frontend..."
cd ../frontend
npm run dev &
FRONTEND_PID=$!
echo "✓ Frontend started (PID: $FRONTEND_PID)"

echo ""
echo "=========================================="
echo "Services running:"
echo "  Backend:  http://localhost:${API_PORT:-3000}"
echo "  Frontend: http://localhost:5173"
echo ""
echo "Press Ctrl+C to stop all services"
echo ""

# Wait for Ctrl+C
trap "kill $BACKEND_PID $FRONTEND_PID 2>/dev/null; exit" INT TERM

wait
