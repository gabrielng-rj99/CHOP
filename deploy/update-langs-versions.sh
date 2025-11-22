#!/bin/bash

# Update Versions Script
# Synchronizes versions from monolith/versions.ini to Dockerfiles and docker-compose.yml

set -e

VERSIONS_FILE="monolith/versions.ini"

# Function to get version
get_version() {
    local key=$1
    grep "^$key=" "$VERSIONS_FILE" | cut -d'=' -f2
}

# Check if versions.ini exists
if [ ! -f "$VERSIONS_FILE" ]; then
    echo "Error: $VERSIONS_FILE not found"
    exit 1
fi

echo "Updating versions from $VERSIONS_FILE..."

# Update Dockerfile.backend
GO_VERSION=$(get_version go)
sed -i "s/FROM golang:.*/FROM golang:$GO_VERSION-alpine AS builder/" docker/Dockerfile.backend
echo "Updated Dockerfile.backend to golang:$GO_VERSION-alpine"

# Update Dockerfile.frontend
NODE_VERSION=$(get_version node)
sed -i "s/FROM node:.*/FROM node:$NODE_VERSION-alpine AS builder/" docker/Dockerfile.frontend
echo "Updated Dockerfile.frontend to node:$NODE_VERSION-alpine"

# Update postgres image in docker-compose.yml
PG_VERSION=$(get_version postgres)
sed -i "s/image: postgres:.*/image: postgres:$PG_VERSION-alpine/" docker/docker-compose.yml
echo "Updated postgres image to $PG_VERSION-alpine"

echo "All versions updated successfully!"
