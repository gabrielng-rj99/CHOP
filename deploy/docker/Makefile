# ==============================================================================
# Client Hub - Docker Deployment Makefile
# ==============================================================================
# Unified environment for Docker Compose-based deployment
#
# Features:
# - Simple container orchestration (build, up, down, restart)
# - Automated environment configuration
# - Health checking and log viewing
# - Cleanup and recovery utilities
# - Language installation helpers
#
# Location: deploy/docker/Makefile
# Usage: cd deploy/docker && make <target>
# ==============================================================================

SHELL := /bin/bash
.SHELLFLAGS := -c

# Configuration files
COMPOSE_FILE := docker-compose.yml
ENV_FILE := .env
BACKUP_DIR := backups
TIMESTAMP := $(shell date +%Y%m%d-%H%M%S)

# Compose project name
COMPOSE_PROJECT := ehop

# Service names
SERVICES := backend frontend postgres

# Colors
RED := $(shell printf '\033[0;31m')
GREEN := $(shell printf '\033[0;32m')
YELLOW := $(shell printf '\033[1;33m')
BLUE := $(shell printf '\033[0;34m')
MAGENTA := $(shell printf '\033[0;35m')
CYAN := $(shell printf '\033[0;36m')
BOLD := $(shell printf '\033[1m')
NC := $(shell printf '\033[0m')

# Docker Compose command
DOCKER_CMD := docker compose -f $(COMPOSE_FILE) -p $(COMPOSE_PROJECT)

# Version requirements
GO_VERSION := 1.21
NODE_VERSION := 20
PYTHON_VERSION := 3.11

# Default target
.DEFAULT_GOAL := help

.PHONY: help info status health build up down restart \
        logs logs-backend logs-frontend logs-db \
        shell shell-backend shell-frontend shell-db \
        validate env-check clean prune backup backup-rotate restore migrate \
        pull ps update upgrade \
        install-go install-node install-python install-deps

# ==============================================================================
# HELP
# ==============================================================================

help: ## Show available commands
	@echo ""
	@echo "$(BLUE)╔══════════════════════════════════════════════════════════════════════════════╗$(NC)"
	@echo "$(BLUE)║$(NC)$(BOLD)              Client Hub - Docker Deployment                                 $(BLUE)║$(NC)"
	@echo "$(BLUE)╚══════════════════════════════════════════════════════════════════════════════╝$(NC)"
	@echo ""
	@echo "$(YELLOW)━━━ QUICK START ━━━$(NC)"
	@echo "  $(GREEN)make env-check$(NC)         Check/create .env configuration"
	@echo "  $(GREEN)make build$(NC)             Build Docker images"
	@echo "  $(GREEN)make up$(NC)                Start all containers"
	@echo "  $(GREEN)make down$(NC)              Stop all containers"
	@echo "  $(GREEN)make status$(NC)            Show container status"
	@echo ""
	@echo "$(YELLOW)━━━ CONTAINER MANAGEMENT ━━━$(NC)"
	@echo "  $(GREEN)up$(NC)                     Start all containers (detached)"
	@echo "  $(GREEN)down$(NC)                   Stop and remove containers"
	@echo "  $(GREEN)restart$(NC)                Stop and start containers"
	@echo "  $(GREEN)build$(NC)                  Build Docker images"
	@echo "  $(GREEN)rebuild$(NC)                Full rebuild (no cache)"
	@echo "  $(GREEN)ps$(NC)                     Show running containers"
	@echo ""
	@echo "$(YELLOW)━━━ MONITORING ━━━$(NC)"
	@echo "  $(GREEN)status$(NC)                 Show container and image status"
	@echo "  $(GREEN)health$(NC)                 Check health of services"
	@echo "  $(GREEN)logs$(NC)                   Show all service logs (live)"
	@echo "  $(GREEN)logs-backend$(NC)           Show backend logs only"
	@echo "  $(GREEN)logs-frontend$(NC)          Show frontend logs only"
	@echo "  $(GREEN)logs-db$(NC)                Show database logs only"
	@echo ""
	@echo "$(YELLOW)━━━ SHELL & DEBUGGING ━━━$(NC)"
	@echo "  $(GREEN)shell$(NC)                  Open shell in backend container"
	@echo "  $(GREEN)shell-backend$(NC)          Alias for shell"
	@echo "  $(GREEN)shell-frontend$(NC)         Open shell in frontend container"
	@echo "  $(GREEN)shell-db$(NC)               Open PostgreSQL shell"
	@echo ""
	@echo "$(YELLOW)━━━ MAINTENANCE ━━━$(NC)"
	@echo "  $(GREEN)clean$(NC)                  Remove containers and volumes (keep images)"
	@echo "  $(GREEN)prune$(NC)                  Remove unused Docker resources"
	@echo "  $(GREEN)validate$(NC)               Validate docker-compose.yml"
	@echo "  $(GREEN)backup$(NC)                 Backup database volume"
	@echo "  $(GREEN)backup-rotate$(NC)          Backup database with retention policy"
	@echo "  $(GREEN)restore$(NC)                Restore database from backup"
	@echo ""
	@echo "$(YELLOW)━━━ UPDATES ━━━$(NC)"
	@echo "  $(GREEN)pull$(NC)                   Pull latest images"
	@echo "  $(GREEN)migrate$(NC)                Run database migrations"
	@echo "  $(GREEN)update$(NC)                 Update and restart"
	@echo "  $(GREEN)upgrade$(NC)                Full rebuild and restart"
	@echo ""
	@echo "$(YELLOW)━━━ LANGUAGE INSTALLATION (for build host) ━━━$(NC)"
	@echo "  $(GREEN)install-go$(NC)             Install Go $(MAGENTA)1.21$(NC) (requires sudo)"
	@echo "  $(GREEN)install-node$(NC)           Install Node.js $(MAGENTA)20$(NC) (requires sudo)"
	@echo "  $(GREEN)install-python$(NC)         Install Python $(MAGENTA)3.11$(NC) (requires sudo)"
	@echo "  $(GREEN)install-deps$(NC)           Install build dependencies"
	@echo ""
	@echo "$(BOLD)$(YELLOW)Configuration:$(NC)"
	@echo "  Compose file: $(CYAN)$(COMPOSE_FILE)$(NC)"
	@echo "  Env file:     $(CYAN)$(ENV_FILE)$(NC)"
	@echo "  Project:      $(CYAN)$(COMPOSE_PROJECT)$(NC)"
	@echo ""

# ==============================================================================
# INFORMATION & STATUS
# ==============================================================================

info: ## Show Docker deployment information
	@echo ""
	@echo "$(BLUE)ℹ️  Docker Deployment Information$(NC)"
	@echo ""
	@echo "$(BOLD)What is Docker?$(NC)"
	@echo "  Containerized deployment using Docker Compose"
	@echo "  Each component runs in its own container:"
	@echo "    • Backend service"
	@echo "    • Frontend service"
	@echo "    • PostgreSQL database"
	@echo "    • All with isolated filesystems and networking"
	@echo ""
	@echo "$(BOLD)Advantages:$(NC)"
	@echo "  ✓ Consistent across development and production"
	@echo "  ✓ Easy to scale and manage"
	@echo "  ✓ Isolated dependencies"
	@echo "  ✓ Simple cleanup (remove all with one command)"
	@echo ""
	@echo "$(BOLD)Default Ports:$(NC)"
	@echo "  Frontend:  http://localhost:5173 (Vite dev server)"
	@echo "  Backend:   http://localhost:3000"
	@echo "  Database:  localhost:5432"
	@echo ""
	@echo "$(BOLD)Next Steps:$(NC)"
	@if [ -f "$(ENV_FILE)" ]; then \
		echo "  • Run '$(GREEN)make build$(NC)' to build images"; \
		echo "  • Run '$(GREEN)make up$(NC)' to start containers"; \
	else \
		echo "  • Run '$(GREEN)make env-check$(NC)' to create .env"; \
		echo "  • Then '$(GREEN)make build$(NC)' and '$(GREEN)make up$(NC)'"; \
	fi
	@echo ""

status: ## Show container and image status
	@echo ""
	@echo "$(BLUE)╔══════════════════════════════════════════════════════════════════════════════╗$(NC)"
	@echo "$(BLUE)║$(NC)$(BOLD)              Docker Status                                                 $(BLUE)║$(NC)"
	@echo "$(BLUE)╚══════════════════════════════════════════════════════════════════════════════╝$(NC)"
	@echo ""
	@echo "$(CYAN)Containers:$(NC)"
	@$(DOCKER_CMD) ps -a --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" || true
	@echo ""
	@echo "$(CYAN)Images:$(NC)"
	@docker images | grep -E "ehop|IMAGE" || echo "  No EHOP images built yet"
	@echo ""
	@echo "$(CYAN)Volumes:$(NC)"
	@docker volume ls | grep -E "ehop|DRIVER" || echo "  No EHOP volumes"
	@echo ""

ps: ## Show running containers (short form)
	@echo "$(BLUE)📦 Running containers$(NC)"
	@echo ""
	@$(DOCKER_CMD) ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
	@echo ""

# ==============================================================================
# ENVIRONMENT & CONFIGURATION
# ==============================================================================

env-check: ## Verify or create .env configuration
	@echo "$(BLUE)⚙️  Checking environment configuration...$(NC)"
	@echo ""
	@if [ -f "$(ENV_FILE)" ]; then \
		echo "$(GREEN)✓ $(ENV_FILE) exists$(NC)"; \
		echo ""; \
		echo "$(CYAN)Configuration:$(NC)"; \
		grep "^[^#]" $(ENV_FILE) | head -10 | sed 's/^/  /'; \
		if [ $$(grep -c "^[^#]" $(ENV_FILE)) -gt 10 ]; then \
			echo "  ... and more"; \
		fi; \
	else \
		echo "$(YELLOW)Creating $(ENV_FILE) from .env.example...$(NC)"; \
		if [ -f ".env.example" ]; then \
			cp .env.example $(ENV_FILE); \
			echo "$(GREEN)✓ $(ENV_FILE) created$(NC)"; \
			echo ""; \
			echo "$(YELLOW)⚠️  Please review and update the values in $(ENV_FILE)$(NC)"; \
			echo "   especially: DB_PASSWORD, JWT_SECRET, API keys, etc."; \
		else \
			echo "$(RED)❌ .env.example not found$(NC)"; \
			exit 1; \
		fi; \
	fi
	@echo ""

validate: ## Validate docker-compose.yml configuration
	@echo "$(BLUE)✓ Validating Docker Compose configuration...$(NC)"
	@echo ""
	@$(DOCKER_CMD) config > /dev/null 2>&1 && \
		echo "$(GREEN)✓ Configuration is valid$(NC)" || \
		(echo "$(RED)❌ Configuration errors found:$(NC)"; $(DOCKER_CMD) config)
	@echo ""

# ==============================================================================
# BUILD
# ==============================================================================

build: env-check validate ## Build Docker images
	@echo "$(BLUE)🐳 Building Docker images...$(NC)"
	@echo ""
	@$(DOCKER_CMD) build
	@echo ""
	@echo "$(GREEN)✅ Build complete$(NC)"
	@echo ""
	@docker images | grep -E "ehop|IMAGE"
	@echo ""

pull: ## Pull latest base images
	@echo "$(BLUE)📥 Pulling latest base images...$(NC)"
	@echo ""
	@$(DOCKER_CMD) pull || true
	@echo ""
	@echo "$(GREEN)✅ Pull complete$(NC)"
	@echo ""

rebuild: ## Full rebuild (no cache, clears build state)
	@echo "$(BLUE)🔨 Full Docker rebuild...$(NC)"
	@echo ""
	@echo "$(YELLOW)Stopping containers...$(NC)"
	@$(DOCKER_CMD) down 2>/dev/null || true
	@echo ""
	@echo "$(YELLOW)Removing volumes...$(NC)"
	@$(DOCKER_CMD) down -v 2>/dev/null || true
	@echo ""
	@echo "$(YELLOW)Building images (no cache)...$(NC)"
	@$(DOCKER_CMD) build --no-cache
	@echo ""
	@echo "$(GREEN)✅ Rebuild complete$(NC)"
	@echo ""

# ==============================================================================
# CONTAINER MANAGEMENT
# ==============================================================================

up: env-check ## Start all containers (detached)
	@echo "$(BLUE)🚀 Starting containers...$(NC)"
	@echo ""
	@$(DOCKER_CMD) up -d
	@sleep 3
	@echo ""
	@echo "$(GREEN)✅ Containers started$(NC)"
	@echo ""
	@echo "$(BOLD)Services:$(NC)"
	@echo "  Frontend (Vite): $(CYAN)http://localhost:5173$(NC)"
	@echo "  Backend API:     $(CYAN)http://localhost:3000$(NC)"
	@echo "  Database:        $(CYAN)localhost:5432$(NC)"
	@echo ""
	@echo "$(BOLD)Useful commands:$(NC)"
	@echo "  make logs        - View live logs"
	@echo "  make shell       - Open shell in backend"
	@echo "  make status      - Check status"
	@echo ""

down: ## Stop and remove all containers
	@echo "$(BLUE)🛑 Stopping containers...$(NC)"
	@echo ""
	@$(DOCKER_CMD) down
	@echo ""
	@echo "$(GREEN)✅ Containers stopped and removed$(NC)"
	@echo ""

restart: down up ## Restart all containers (stop → start)

# ==============================================================================
# MONITORING & LOGS
# ==============================================================================

health: ## Check health of all services
	@echo "$(BLUE)🏥 Service Health Check$(NC)"
	@echo ""
	@echo "$(CYAN)Backend:$(NC)"
	@HEALTH=$$(curl -s -o /dev/null -w "%{http_code}" http://localhost:3000/health 2>/dev/null || echo "000"); \
	if [ "$$HEALTH" = "200" ]; then \
		echo "  $(GREEN)✓ Healthy$(NC) (HTTP $$HEALTH)"; \
	else \
		echo "  $(RED)✗ Unhealthy$(NC) (HTTP $$HEALTH)"; \
	fi
	@echo ""
	@echo "$(CYAN)Frontend:$(NC)"
	@HEALTH=$$(curl -s -o /dev/null -w "%{http_code}" http://localhost:5173 2>/dev/null || echo "000"); \
	if [ "$$HEALTH" = "200" ]; then \
		echo "  $(GREEN)✓ Healthy$(NC) (HTTP $$HEALTH)"; \
	else \
		echo "  $(RED)✗ Unhealthy$(NC) (HTTP $$HEALTH)"; \
	fi
	@echo ""
	@echo "$(CYAN)Database:$(NC)"
	@$(DOCKER_CMD) exec -T postgres pg_isready -U postgres > /dev/null 2>&1 && \
		echo "  $(GREEN)✓ Ready$(NC)" || \
		echo "  $(RED)✗ Not ready$(NC)"
	@echo ""

logs: ## Show all container logs (live, Ctrl+C to exit)
	@echo "$(BLUE)📋 All logs (Ctrl+C to exit)$(NC)"
	@echo "$(CYAN)────────────────────────────────────────────────────────────────$(NC)"
	@$(DOCKER_CMD) logs -f

logs-backend: ## Show backend container logs (live)
	@echo "$(BLUE)📋 Backend logs (Ctrl+C to exit)$(NC)"
	@echo "$(CYAN)────────────────────────────────────────────────────────────────$(NC)"
	@$(DOCKER_CMD) logs -f backend

logs-frontend: ## Show frontend container logs (live)
	@echo "$(BLUE)📋 Frontend logs (Ctrl+C to exit)$(NC)"
	@echo "$(CYAN)────────────────────────────────────────────────────────────────$(NC)"
	@$(DOCKER_CMD) logs -f frontend

logs-db: ## Show database container logs (live)
	@echo "$(BLUE)📋 Database logs (Ctrl+C to exit)$(NC)"
	@echo "$(CYAN)────────────────────────────────────────────────────────────────$(NC)"
	@$(DOCKER_CMD) logs -f postgres

# ==============================================================================
# SHELL ACCESS
# ==============================================================================

shell: shell-backend ## Open shell in backend container (alias)

shell-backend: ## Open shell in backend container
	@echo "$(BLUE)🐚 Opening backend shell...$(NC)"
	@echo ""
	@$(DOCKER_CMD) exec -it backend bash

shell-frontend: ## Open shell in frontend container
	@echo "$(BLUE)🐚 Opening frontend shell...$(NC)"
	@echo ""
	@$(DOCKER_CMD) exec -it frontend bash

shell-db: ## Open PostgreSQL shell
	@echo "$(BLUE)🐚 Opening PostgreSQL shell...$(NC)"
	@echo ""
	@$(DOCKER_CMD) exec -it postgres psql -U postgres -d ehopdb

# ==============================================================================
# BACKUP & RECOVERY
# ==============================================================================

backup: ## Backup database volume
	@echo "$(BLUE)💾 Backing up database...$(NC)"
	@echo ""
	@mkdir -p $(BACKUP_DIR)
	@BACKUP_FILE="$(BACKUP_DIR)/ehop-db-$(TIMESTAMP).sql.gz"; \
	echo "$(YELLOW)Dumping database to $$BACKUP_FILE...$(NC)"; \
	$(DOCKER_CMD) exec postgres pg_dump -U postgres ehopdb | gzip > $$BACKUP_FILE && \
	echo "$(GREEN)✓ Backup created: $$BACKUP_FILE$(NC)" || \
	echo "$(RED)❌ Backup failed$(NC)"
	@echo ""

backup-rotate: ## Backup database with retention policy (backup service)
	@echo "$(BLUE)💾 Running rotating backup...$(NC)"
	@echo ""
	@$(DOCKER_CMD) up -d backup
	@$(DOCKER_CMD) exec -T backup /usr/local/bin/backup-db.sh
	@echo ""

migrate: ## Run database migrations (one-shot)
	@echo "$(BLUE)🧭 Running database migrations...$(NC)"
	@echo ""
	@$(DOCKER_CMD) --profile migrations run --rm migrator
	@echo ""

restore: ## Restore database from backup
	@echo "$(BLUE)📥 Restoring database from backup...$(NC)"
	@echo ""
	@echo "$(CYAN)Available backups:$(NC)"
	@if [ -d "$(BACKUP_DIR)" ] && [ -n "$$(ls $(BACKUP_DIR)/*.sql.gz 2>/dev/null)" ]; then \
		ls -1t $(BACKUP_DIR)/*.sql.gz | head -10 | nl; \
		echo ""; \
		read -p "Select backup number to restore: " num; \
		BACKUP_FILE=$$(ls -1t $(BACKUP_DIR)/*.sql.gz | sed -n "$${num}p"); \
		if [ -n "$$BACKUP_FILE" ]; then \
			echo "$(YELLOW)Restoring from: $$BACKUP_FILE$(NC)"; \
			gunzip -c $$BACKUP_FILE | $(DOCKER_CMD) exec -T postgres psql -U postgres ehopdb && \
			echo "$(GREEN)✅ Restore complete$(NC)"; \
		else \
			echo "$(RED)Invalid selection$(NC)"; \
		fi; \
	else \
		echo "$(YELLOW)No backups found in $(BACKUP_DIR)$(NC)"; \
	fi
	@echo ""

# ==============================================================================
# CLEANUP
# ==============================================================================

clean: ## Remove containers and volumes (keep images)
	@echo "$(BLUE)🧹 Cleaning Docker environment...$(NC)"
	@echo ""
	@read -p "Remove volumes too? (y/N): " response; \
	if [ "$$response" = "y" ]; then \
		echo "$(YELLOW)Removing containers and volumes...$(NC)"; \
		$(DOCKER_CMD) down -v; \
	else \
		echo "$(YELLOW)Removing containers (keeping volumes)...$(NC)"; \
		$(DOCKER_CMD) down; \
	fi
	@echo ""
	@echo "$(GREEN)✅ Cleanup complete$(NC)"
	@echo ""

prune: ## Remove all unused Docker resources (frees disk space)
	@echo "$(BLUE)🧹 Pruning Docker system...$(NC)"
	@echo ""
	@echo "$(YELLOW)This will remove:$(NC)"
	@echo "  • Stopped containers"
	@echo "  • Unused images"
	@echo "  • Unused volumes"
	@echo "  • Unused networks"
	@echo ""
	@read -p "Continue? (y/N): " response; \
	if [ "$$response" = "y" ]; then \
		docker system prune -a -f; \
		echo ""; \
		echo "$(GREEN)✅ Prune complete$(NC)"; \
	else \
		echo "$(YELLOW)Cancelled$(NC)"; \
	fi
	@echo ""

# ==============================================================================
# UPDATES & UPGRADES
# ==============================================================================

update: pull migrate restart ## Update images, run migrations, restart containers
	@echo ""
	@echo "$(GREEN)✅ Update complete - services restarted$(NC)"
	@echo ""

upgrade: rebuild ## Full rebuild and restart (same as rebuild)
	@echo ""
	@echo "$(GREEN)✅ Upgrade complete$(NC)"
	@echo ""

# ==============================================================================
# LANGUAGE INSTALLATION (for build host)
# ==============================================================================

install-go: ## Install Go (1.21) - requires sudo
	@echo "$(BLUE)📥 Installing Go $(GO_VERSION)...$(NC)"
	@if command -v go &> /dev/null; then \
		echo "$(YELLOW)ℹ️  Go is already installed: $$(go version)$(NC)"; \
	else \
		echo "$(YELLOW)Downloading and installing Go...$(NC)"; \
		cd /tmp && \
		curl -sSL https://go.dev/dl/go$(GO_VERSION).linux-amd64.tar.gz -o go.tar.gz && \
		sudo tar -C /usr/local -xzf go.tar.gz && \
		rm go.tar.gz && \
		echo "$(GREEN)✓ Go installed to /usr/local/go$(NC)"; \
		echo "$(YELLOW)Add to PATH: export PATH=\$$PATH:/usr/local/go/bin$(NC)"; \
	fi

install-node: ## Install Node.js (20) - requires sudo
	@echo "$(BLUE)📥 Installing Node.js $(NODE_VERSION)...$(NC)"
	@if command -v node &> /dev/null; then \
		echo "$(YELLOW)ℹ️  Node.js is already installed: $$(node -v)$(NC)"; \
	else \
		echo "$(YELLOW)Installing via NodeSource...$(NC)"; \
		curl -fsSL https://deb.nodesource.com/setup_$(NODE_VERSION).x | sudo -E bash - && \
		sudo apt-get install -y nodejs && \
		echo "$(GREEN)✓ Node.js installed$(NC)"; \
	fi

install-python: ## Install Python (3.11) - requires sudo
	@echo "$(BLUE)📥 Installing Python $(PYTHON_VERSION)...$(NC)"
	@if command -v python$(PYTHON_VERSION) &> /dev/null; then \
		echo "$(YELLOW)ℹ️  Python $(PYTHON_VERSION) is already installed$(NC)"; \
	else \
		echo "$(YELLOW)Installing Python $(PYTHON_VERSION)...$(NC)"; \
		sudo apt-get update && \
		sudo apt-get install -y python$(PYTHON_VERSION) python$(PYTHON_VERSION)-venv && \
		echo "$(GREEN)✓ Python $(PYTHON_VERSION) installed$(NC)"; \
	fi

install-deps: ## Install Docker and Docker Compose
	@echo "$(BLUE)📦 Installing Docker and Docker Compose...$(NC)"
	@echo ""
	@if command -v docker &> /dev/null; then \
		echo "$(GREEN)✓ Docker is installed: $$(docker --version)$(NC)"; \
	else \
		echo "$(YELLOW)Installing Docker...$(NC)"; \
		curl -fsSL https://get.docker.com -o get-docker.sh && \
		sudo sh get-docker.sh && \
		rm get-docker.sh && \
		echo "$(GREEN)✓ Docker installed$(NC)"; \
	fi
	@echo ""
	@if docker compose version &> /dev/null; then \
		echo "$(GREEN)✓ Docker Compose is installed: $$(docker compose version)$(NC)"; \
	else \
		echo "$(YELLOW)Installing Docker Compose...$(NC)"; \
		sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$$(uname -s)-$$(uname -m)" -o /usr/local/bin/docker-compose && \
		sudo chmod +x /usr/local/bin/docker-compose && \
		echo "$(GREEN)✓ Docker Compose installed$(NC)"; \
	fi
	@echo ""
	@echo "$(YELLOW)Don't forget to add your user to the docker group:$(NC)"; \
	@echo "  sudo usermod -aG docker \$$USER"; \
	@echo ""
