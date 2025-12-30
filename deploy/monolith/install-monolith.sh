#!/bin/bash

# Client Hub Monolith Installer
# One-click installation script for all dependencies and setup.
# Reads compatible versions from deploy/versions.ini
# Run with: curl -f https://your-domain/install-monolith.sh | sh
# Or locally: ./install-monolith.sh

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'
BOLD='\033[1m'

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
    local versions_file="$(dirname "$0")/versions.ini"
    grep "^$key=" "$versions_file" | cut -d'=' -f2
}

# Detect Package Manager
detect_package_manager() {
    if command_exists apt-get; then
        PM="apt"
    elif command_exists dnf; then
        PM="dnf"
    elif command_exists yum; then
        PM="yum"
    elif command_exists pacman; then
        PM="pacman"
    else
        print_error "Unsupported package manager. Please install dependencies manually."
        exit 1
    fi
    echo "$PM"
}

# Install Package
install_package() {
    local PACKAGE_NAME=$1
    local ARCH_PACKAGE_NAME=$2  # Optional alternate name for Arch/Pacman
    local RHEL_PACKAGE_NAME=$3  # Optional alternate name for RHEL/Fedora

    if [ -z "$ARCH_PACKAGE_NAME" ]; then ARCH_PACKAGE_NAME=$PACKAGE_NAME; fi
    if [ -z "$RHEL_PACKAGE_NAME" ]; then RHEL_PACKAGE_NAME=$PACKAGE_NAME; fi

    echo "Blocking until lock is released..."

    case $PM in
        apt)
            $SUDO apt-get install -y -qq $PACKAGE_NAME
            ;;
        dnf)
            $SUDO dnf install -y -q $RHEL_PACKAGE_NAME
            ;;
        yum)
            $SUDO yum install -y -q $RHEL_PACKAGE_NAME
            ;;
        pacman)
            $SUDO pacman -S --noconfirm --needed $ARCH_PACKAGE_NAME
            ;;
    esac
}

# Update System
update_system() {
    case $PM in
        apt)
            $SUDO apt-get update -qq
            ;;
        dnf)
            $SUDO dnf check-update || true
            ;;
        yum)
            $SUDO yum check-update || true
            ;;
        pacman)
            $SUDO pacman -Sy
            ;;
    esac
}

# Check if versions.ini exists
SCRIPT_DIR="$(dirname "$0")"
if [ ! -f "$SCRIPT_DIR/versions.ini" ]; then
    print_error "versions.ini not found in $SCRIPT_DIR"
    exit 1
fi

# Check if running on supported OS
if [[ "$OSTYPE" != "linux-gnu"* ]]; then
    print_error "This installer is designed for Linux. For other OS, install manually."
    exit 1
fi

echo -e "${BOLD}${BLUE}🚀 Client Hub Monolith Installer${NC}"
echo -e "${BOLD}${BLUE}=================================${NC}"
echo ""

# Check if running as root
if [[ $EUID -eq 0 ]]; then
    SUDO=""
else
    SUDO="sudo"
    print_step "Will use sudo for system installations"
fi

# Detect Package Manager
PM=$(detect_package_manager)
print_step "Detected package manager: $PM"

# Update package list
print_step "Updating system..."
update_system

# Install curl
if ! command_exists curl; then
    print_step "Installing curl..."
    install_package curl curl curl
    print_success "curl installed"
fi

# Install wget
if ! command_exists wget; then
    print_step "Installing wget..."
    install_package wget wget wget
    print_success "wget installed"
fi

# Install Git
if ! command_exists git; then
    print_step "Installing Git..."
    install_package git git git
    print_success "Git installed"
fi

# Install Build Essentials
if ! command_exists gcc; then
    print_step "Installing Build Essentials..."
    case $PM in
        apt)
            install_package build-essential
            ;;
        dnf|yum)
            $SUDO $PM groupinstall -y "Development Tools"
            ;;
        pacman)
            install_package base-devel
            ;;
    esac
    print_success "Build Essentials installed"
fi

# Install Go
if ! command_exists go; then
    print_step "Installing Go..."
    # Try package manager first for specific distros (like Arch), else binary
    if [[ "$PM" == "pacman" ]] || [[ "$PM" == "dnf" ]]; then
        install_package go go golang
        print_success "Go installed from package manager"
    else
        GO_VERSION=$(get_version go)
        wget -q https://golang.org/dl/go${GO_VERSION}.linux-amd64.tar.gz
        $SUDO rm -rf /usr/local/go && $SUDO tar -C /usr/local -xzf go${GO_VERSION}.linux-amd64.tar.gz
        rm go${GO_VERSION}.linux-amd64.tar.gz
        export PATH=$PATH:/usr/local/go/bin
        # Assuming bash/zsh
        echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
        print_success "Go installed (${GO_VERSION})"
    fi
else
    print_success "Go already installed"
fi

# Install Node.js
if ! command_exists node; then
    print_step "Installing Node.js..."
    NODE_VERSION=$(get_version node)

    if [[ "$PM" == "pacman" ]]; then
        install_package nodejs nodejs nodejs
        install_package npm npm npm
    else
       # Use NodeSource for Debian/RHEL
       curl -fsSL https://deb.nodesource.com/setup_${NODE_VERSION}.x | $SUDO -E bash -
       install_package nodejs
    fi
    print_success "Node.js installed"
else
    print_success "Node.js already installed"
fi

# Install PostgreSQL
if ! command_exists psql; then
    print_step "Installing PostgreSQL..."
    PG_VERSION=$(get_version postgres)

    case $PM in
        apt)
            install_package postgresql postgresql postgresql
            install_package postgresql-contrib
            SERVICE_NAME="postgresql"
            ;;
        dnf|yum)
            install_package postgresql-server postgresql-server postgresql-server
            install_package postgresql-contrib
            $SUDO postgresql-setup --initdb || true
            SERVICE_NAME="postgresql"
            ;;
        pacman)
            install_package postgresql postgresql postgresql
            # Arch needs initdb
            if [ ! -d "/var/lib/postgres/data" ]; then
                 $SUDO su - postgres -c "initdb --locale en_US.UTF-8 -D /var/lib/postgres/data" || true
            fi
            SERVICE_NAME="postgresql"
            ;;
    esac

    $SUDO systemctl enable $SERVICE_NAME
    $SUDO systemctl start $SERVICE_NAME
    print_success "PostgreSQL installed and started"
else
    print_success "PostgreSQL already installed"
fi

# Install nginx
if ! command_exists nginx; then
    print_step "Installing nginx..."
    install_package nginx nginx nginx
    $SUDO systemctl enable nginx
    print_success "nginx installed"
else
    print_success "nginx already installed"
fi

# Install OpenSSL
if ! command_exists openssl; then
    print_step "Installing OpenSSL..."
    install_package openssl openssl openssl
    print_success "OpenSSL installed"
fi

echo ""
print_success "All system dependencies installed!"
echo ""

# Setup project
print_step "Setting up Client Hub project..."

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
print_success "Client Hub setup complete!"
echo ""
echo -e "${BOLD}${YELLOW}Next steps:${NC}"
echo "1. Edit deploy/monolith/monolith.ini with your settings"
echo "2. Run: ./deploy/monolith/start-monolith.sh"
echo ""
echo -e "${BOLD}${GREEN}🎉 Installation finished!${NC}"
