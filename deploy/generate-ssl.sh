#!/bin/sh
set -e

SSL_DIR="./certs/ssl"
SERVER_CERT="$SSL_DIR/server.crt"
SERVER_KEY="$SSL_DIR/server.key"

SSL_DOMAIN="${SSL_DOMAIN:-ehop.home.arpa}"

mkdir -p "$SSL_DIR"

if [ ! -f "$SERVER_CERT" ] || [ ! -f "$SERVER_KEY" ]; then
    openssl req -x509 -nodes -days 365 \
        -newkey rsa:2048 \
        -keyout "$SERVER_KEY" \
        -out "$SERVER_CERT" \
        -subj "/CN=$SSL_DOMAIN" \
        -addext "subjectAltName=DNS:$SSL_DOMAIN"
fi
