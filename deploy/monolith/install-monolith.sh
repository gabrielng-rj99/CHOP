#!/bin/bash

# Entity Hub Monolith Installer
# One-click installation script for all dependencies and setup.
# Reads compatible versions from deploy/versions.ini
# Run with: curl -f https://your-domain/install-monolith.sh | sh
# Or locally: ./install-monolith.sh

set -e

# Colors
RED='[0;31m'
GREEN='[0;32m'
YELLOW='[1;33m'
BLUE='[0;34m'
NC='[0m'
BOLD='[1m'

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to print step
print_step() {
    echo -e "${BLUE}🔧 $1${NC}"
}

# Function to print success
print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

# Function to print error
print_error() {
    echo -e "${RED}❌ $1${NC}"
}

# Function to get version from versions.ini
get_version() {
    local key=$1
    local versions_file="$(dirname "$0")/../versions.ini"
    grep "^$key=" "$versions_file" | cut -d'=' -f2
}

# Check if versions.ini exists
if [ ! -f "$(dirname "$0")/../versions.ini" ]; then
    print_error "versions.ini not found in deploy/"
    exit 1
fi

# Check if running on supported OS
if [[ "$OSTYPE" != "linux-gnu"* ]]; then
    print_error "This installer is designed for Linux. For other OS, install manually."
    exit 1
fi

echo -e "${BOLD}${BLUE}🚀 Entity Hub Monolith Installer${NC}"
echo -e "${BOLD}${BLUE}=================================${NC}"
echo ""

# Check if running as root
if [[ $EUID -eq 0 ]]; then
    SUDO=""
else
    SUDO="sudo"
    print_step "Will use sudo for system installations"
fi

# Update package list
print_step "Updating package list..."
$SUDO apt update -qq

# Install curl if not present
if ! command_exists curl; then
    print_step "Installing curl..."
    $SUDO apt install -y -qq curl
    print_success "curl installed"
fi

# Install wget if not present
if ! command_exists wget; then
    print_step "Installing wget..."
    $SUDO apt install -y -qq wget
    print_success "wget installed"
fi

# Install Git if not present
if ! command_exists git; then
    print_step "Installing Git..."
    $SUDO apt install -y -qq git
    print_success "Git installed"
fi

# Install Go
if ! command_exists go; then
    print_step "Installing Go..."
    GO_VERSION=$(get_version go)
    wget -q https://golang.org/dl/go${GO_VERSION}.linux-amd64.tar.gz
    $SUDO rm -rf /usr/local/go && $SUDO tar -C /usr/local -xzf go${GO_VERSION}.linux-amd64.tar.gz
    rm go${GO_VERSION}.linux-amd64.tar.gz
    export PATH=$PATH:/usr/local/go/bin
    echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
    print_success "Go installed ($GO_VERSION)"
else
    print_success "Go already installed"
fi

# Install Node.js
if ! command_exists node; then
    print_step "Installing Node.js..."
    NODE_VERSION=$(get_version node)
    curl -fsSL https://deb.nodesource.com/setup_${NODE_VERSION}.x | $SUDO -E bash -
    $SUDO apt-get install -y -qq nodejs
    print_success "Node.js installed ($NODE_VERSION)"
else
    print_success "Node.js already installed"
fi

# Install PostgreSQL
if ! command_exists psql; then
    print_step "Installing PostgreSQL..."
    PG_VERSION=$(get_version postgres)
    $SUDO apt install -y -qq postgresql-${PG_VERSION} postgresql-contrib
    $SUDO systemctl enable postgresql
    $SUDO systemctl start postgresql
    print_success "PostgreSQL installed and started ($PG_VERSION)"
else
    print_success "PostgreSQL already installed"
fi

# Install nginx
if ! command_exists nginx; then
    print_step "Installing nginx..."
    $SUDO apt install -y -qq nginx
    $SUDO systemctl enable nginx
    print_success "nginx installed"
else
    print_success "nginx already installed"
fi

# Install OpenSSL if not present
if ! command_exists openssl; then
    print_step "Installing OpenSSL..."
    $SUDO apt install -y -qq openssl
    print_success "OpenSSL installed"
fi

echo ""
print_success "All system dependencies installed!"
echo ""

# Setup project
print_step "Setting up Entity Hub project..."

# Assume we're in the project root or adjust path
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$PROJECT_ROOT"

# Backend setup
print_step "Setting up backend..."
cd backend
if [ -f go.mod ]; then
    go mod tidy
    print_success "Backend dependencies installed"
else
    print_error "go.mod not found in backend/"
    exit 1
fi

# Frontend setup
cd ../frontend
print_step "Setting up frontend..."
if [ -f package.json ]; then
    npm install
    print_success "Frontend dependencies installed"
else
    print_error "package.json not found in frontend/"
    exit 1
fi

cd ..

# Copy monolith.ini if not exists
if [ ! -f deploy/monolith/monolith.ini ]; then
    print_step "Creating monolith.ini..."
    cp deploy/docker/.env.example deploy/monolith/monolith.ini 2>/dev/null || {
        print_error "Could not copy .env.example to monolith.ini"
        exit 1
    }
    print_success "monolith.ini created"
fi

echo ""
print_success "Entity Hub setup complete!"
echo ""
echo -e "${BOLD}${YELLOW}Next steps:${NC}"
echo "1. Edit deploy/monolith/monolith.ini with your settings"
echo "2. Run: ./deploy/monolith/start-monolith.sh"
echo ""
echo -e "${BOLD}${GREEN}🎉 Installation finished!${NC}"
