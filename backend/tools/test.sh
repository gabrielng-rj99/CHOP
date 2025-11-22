#!/bin/bash

# Simple test runner for Contract Manager

cd "$(dirname "$0")/.."

echo "Running tests..."
echo ""

go test -v -cover ./...

echo ""
echo "Done!"
