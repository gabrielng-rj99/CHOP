# ==============================================================================
# Client Hub - Monolith Deployment Makefile
# ==============================================================================
# Single entry point for monolith installation and management.
#
# Usage: cd deploy/monolith && make <target>
#        OR make -f deploy/monolith/Makefile <target>
#
# What is a monolith deployment?
#   - Complete single-unit installation of the entire application
#   - Installs: backend binary, frontend assets, database, systemd services
#   - Production-ready setup with proper permissions and configuration
#   - Default installation path: /opt/ehop
#
# Environment versions (configured in versions.ini):
#   - Go:         >= 1.21
#   - Node.js:    >= 18.0.0
#   - Python:     3.11 (for utilities/scripts)
#   - PostgreSQL: >= 12
# ==============================================================================

SHELL := /bin/bash
.SHELLFLAGS := -c

# Configuration files
CONFIG_FILE := monolith.ini
VERSIONS_FILE := versions.ini
BACKUP_DIR := ../app/monolith/backups
BACKUP_DB_DIR := ../app/monolith/backups/db
BACKUP_DB_DAYS := 90
BACKUP_DB_MAX_BYTES := 524288000
BACKUP_DB_COMPRESS := true
TIMESTAMP := $(shell date +%Y%m%d-%H%M%S)

# Colors
RED := $(shell printf '\033[0;31m')
GREEN := $(shell printf '\033[0;32m')
YELLOW := $(shell printf '\033[1;33m')
BLUE := $(shell printf '\033[0;34m')
MAGENTA := $(shell printf '\033[0;35m')
CYAN := $(shell printf '\033[0;36m')
BOLD := $(shell printf '\033[1m')
NC := $(shell printf '\033[0m')

# Default target
.DEFAULT_GOAL := help

.PHONY: help \
        info status \
        install uninstall \
        start stop restart \
        logs logs-backend logs-frontend \
        backup backup-db restore restore-db \
        update upgrade \
        clean config versions \
        health-check

# ==============================================================================
# HELP
# ==============================================================================

help: ## Show this help message
	@echo ""
	@echo "$(BLUE)╔══════════════════════════════════════════════════════════════════════════════╗$(NC)"
	@echo "$(BLUE)║$(NC)$(BOLD)              Client Hub - Monolith Deployment                              $(BLUE)║$(NC)"
	@echo "$(BLUE)╚══════════════════════════════════════════════════════════════════════════════╝$(NC)"
	@echo ""
	@echo "$(YELLOW)━━━ QUICK START ━━━$(NC)"
	@echo "  $(GREEN)make info$(NC)              Show deployment information"
	@echo "  $(GREEN)make install$(NC)           Install monolith (one-time setup)"
	@echo "  $(GREEN)make start$(NC)             Start monolith services"
	@echo "  $(GREEN)make status$(NC)            Show installation & service status"
	@echo ""
	@echo "$(YELLOW)━━━ SERVICE MANAGEMENT ━━━$(NC)"
	@echo "  $(GREEN)start$(NC)                  Start monolith services"
	@echo "  $(GREEN)stop$(NC)                   Stop monolith services"
	@echo "  $(GREEN)restart$(NC)                Restart monolith services"
	@echo ""
	@echo "$(YELLOW)━━━ INSTALLATION ━━━$(NC)"
	@echo "  $(GREEN)install$(NC)                Complete monolith installation"
	@echo "  $(GREEN)uninstall$(NC)              Remove monolith installation"
	@echo ""
	@echo "$(YELLOW)━━━ MONITORING ━━━$(NC)"
	@echo "  $(GREEN)status$(NC)                 Show service and installation status"
	@echo "  $(GREEN)health-check$(NC)           Check health of all services"
	@echo "  $(GREEN)logs$(NC)                   Show all service logs"
	@echo "  $(GREEN)logs-backend$(NC)           Show backend logs only"
	@echo "  $(GREEN)logs-frontend$(NC)          Show frontend logs only"
	@echo ""
	@echo "$(YELLOW)━━━ BACKUP & RECOVERY ━━━$(NC)"
	@echo "  $(GREEN)backup$(NC)                 Create backup of config and data"
	@echo "  $(GREEN)backup-db$(NC)              Create database snapshot with retention"
	@echo "  $(GREEN)restore$(NC)                Restore from backup"
	@echo "  $(GREEN)restore-db$(NC)             Restore database from snapshot"
	@echo ""
	@echo "$(YELLOW)━━━ MAINTENANCE ━━━$(NC)"
	@echo "  $(GREEN)config$(NC)                 Show current configuration"
	@echo "  $(GREEN)versions$(NC)               Show component versions"
	@echo "  $(GREEN)update$(NC)                 Update component versions"
	@echo "  $(GREEN)upgrade$(NC)                Upgrade to new versions"
	@echo "  $(GREEN)clean$(NC)                  Clean temporary files and logs"
	@echo ""
	@echo "$(YELLOW)━━━ CONFIGURATION ━━━$(NC)"
	@echo "  Config file:      $(CYAN)$(CONFIG_FILE)$(NC)"
	@echo "  Versions file:    $(CYAN)$(VERSIONS_FILE)$(NC)"
	@echo "  Backup directory: $(CYAN)$(BACKUP_DIR)/$(NC)"
	@echo ""

# ==============================================================================
# INFORMATION & STATUS
# ==============================================================================

info: ## Show monolith deployment information
	@echo ""
	@echo "$(BLUE)ℹ️  Monolith Deployment Information$(NC)"
	@echo ""
	@echo "$(BOLD)What is a Monolith?$(NC)"
	@echo "  A complete, self-contained installation of the entire application"
	@echo "  packaged as a single unit. Includes:"
	@echo "    • Backend binary (compiled)"
	@echo "    • Frontend assets (built)"
	@echo "    • Database (PostgreSQL)"
	@echo "    • Systemd services"
	@echo "    • Configuration and secrets"
	@echo ""
	@echo "$(BOLD)Default Paths:$(NC)"
	@echo "  Installation:  /opt/ehop"
	@echo "  Logs:          /var/log/ehop"
	@echo "  Data:          /var/lib/ehop"
	@echo "  Config:        /etc/ehop"
	@echo ""
	@echo "$(BOLD)Services:$(NC)"
	@echo "  Frontend:  http://localhost:80"
	@echo "  Backend:   http://localhost:3000"
	@echo "  Database:  localhost:5432"
	@echo ""
	@echo "$(BOLD)Next Steps:$(NC)"
	@if [ -f "$(CONFIG_FILE)" ]; then \
		echo "  • Installation already configured"; \
		echo "  • Run '$(GREEN)make start$(NC)' to start services"; \
		echo "  • Run '$(GREEN)make status$(NC)' to check status"; \
	else \
		echo "  • Run '$(GREEN)make install$(NC)' to begin installation"; \
		echo "  • Or configure '$(CYAN)$(CONFIG_FILE)$(NC)' manually first"; \
	fi
	@echo ""

status: ## Show installation and service status
	@echo ""
	@echo "$(BLUE)╔══════════════════════════════════════════════════════════════════════════════╗$(NC)"
	@echo "$(BLUE)║$(NC)$(BOLD)              Monolith Status                                              $(BLUE)║$(NC)"
	@echo "$(BLUE)╚══════════════════════════════════════════════════════════════════════════════╝$(NC)"
	@echo ""
	@echo "$(CYAN)Installation:$(NC)"
	@if [ -f "$(CONFIG_FILE)" ]; then \
		echo "  $(GREEN)✓ Configuration exists$(NC)"; \
		INSTALL_PATH=$$(grep "^INSTALL_PATH=" $(CONFIG_FILE) 2>/dev/null | cut -d'=' -f2 | tr -d ' ' || echo "/opt/ehop"); \
		echo "  Path: $$INSTALL_PATH"; \
		if [ -d "$$INSTALL_PATH" ]; then \
			echo "  $(GREEN)✓ Installation directory found$(NC)"; \
		else \
			echo "  $(YELLOW)○ Installation directory not found (not installed yet)$(NC)"; \
		fi; \
	else \
		echo "  $(RED)✗ Not installed$(NC)"; \
		echo "  Run '$(GREEN)make install$(NC)' to begin"; \
	fi
	@echo ""
	@echo "$(CYAN)Services:$(NC)"
	@systemctl is-active --quiet ehop-backend && echo "  $(GREEN)● Backend running$(NC)" || echo "  $(RED)○ Backend stopped$(NC)"
	@systemctl is-active --quiet ehop-frontend && echo "  $(GREEN)● Frontend running$(NC)" || echo "  $(RED)○ Frontend stopped$(NC)"
	@systemctl is-active --quiet postgresql && echo "  $(GREEN)● PostgreSQL running$(NC)" || echo "  $(RED)○ PostgreSQL stopped$(NC)"
	@echo ""
	@echo "$(CYAN)Endpoints:$(NC)"
	@echo "  Backend:  http://localhost:3000"
	@echo "  Frontend: http://localhost:80"
	@echo ""

# ==============================================================================
# INSTALLATION & SETUP
# ==============================================================================

install: ## Install monolith (complete one-time setup)
	@echo ""
	@echo "$(BLUE)╔══════════════════════════════════════════════════════════════════════════════╗$(NC)"
	@echo "$(BLUE)║$(NC)$(BOLD)              Monolith Installation                                        $(BLUE)║$(NC)"
	@echo "$(BLUE)╚══════════════════════════════════════════════════════════════════════════════╝$(NC)"
	@echo ""
	@echo "This will install the complete monolith application:"
	@echo "  • Backend binary"
	@echo "  • Frontend assets"
	@echo "  • Database (PostgreSQL)"
	@echo "  • Systemd services"
	@echo ""
	@echo "$(YELLOW)Requirements:$(NC)"
	@echo "  • sudo access"
	@echo "  • 5GB free disk space"
	@echo "  • PostgreSQL installed"
	@echo ""
	@read -p "Continue with installation? (y/N): " response; \
	if [ "$$response" = "y" ]; then \
		echo ""; \
		echo "$(YELLOW)Checking prerequisites...$(NC)"; \
		./install-monolith.sh; \
		if [ $$? -eq 0 ]; then \
			echo ""; \
			echo "$(GREEN)╔══════════════════════════════════════════════════════════════════════════════╗$(NC)"; \
			echo "$(GREEN)║  ✅  Installation complete!                                                  ║$(NC)"; \
			echo "$(GREEN)╚══════════════════════════════════════════════════════════════════════════════╝$(NC)"; \
			echo ""; \
			echo "$(BOLD)Next Steps:$(NC)"; \
			echo "  1. Review configuration: $(GREEN)make config$(NC)"; \
			echo "  2. Start services:      $(GREEN)make start$(NC)"; \
			echo "  3. Check status:        $(GREEN)make status$(NC)"; \
		else \
			echo "$(RED)Installation failed - see errors above$(NC)"; \
			exit 1; \
		fi; \
	else \
		echo "$(YELLOW)Installation cancelled$(NC)"; \
	fi
	@echo ""

uninstall: ## Remove monolith installation (WARNING: deletes everything)
	@echo ""
	@echo "$(RED)╔══════════════════════════════════════════════════════════════════════════════╗$(NC)"
	@echo "$(RED)║  ⚠️   WARNING: This will REMOVE the entire monolith installation              ║$(NC)"
	@echo "$(RED)╚══════════════════════════════════════════════════════════════════════════════╝$(NC)"
	@echo ""
	@echo "This will DELETE:"
	@echo "  $(RED)✗ All services and binaries$(NC)"
	@echo "  $(RED)✗ Database and all data$(NC)"
	@echo "  $(RED)✗ Configuration and secrets$(NC)"
	@echo "  $(RED)✗ All logs$(NC)"
	@echo ""
	@read -p "Type 'uninstall' to confirm: " response; \
	if [ "$$response" = "uninstall" ]; then \
		echo ""; \
		echo "$(YELLOW)Removing monolith...$(NC)"; \
		./destroy-monolith.sh; \
		if [ $$? -eq 0 ]; then \
			echo ""; \
			echo "$(GREEN)✅ Monolith uninstalled$(NC)"; \
		else \
			echo "$(RED)Uninstall failed - see errors above$(NC)"; \
			exit 1; \
		fi; \
	else \
		echo "$(YELLOW)Uninstall cancelled$(NC)"; \
	fi
	@echo ""

# ==============================================================================
# SERVICE MANAGEMENT
# ==============================================================================

start: ## Start all monolith services
	@echo "$(BLUE)🚀 Starting monolith services...$(NC)"
	@echo ""
	@if [ ! -f "$(CONFIG_FILE)" ]; then \
		echo "$(RED)❌ Not installed - run 'make install' first$(NC)"; \
		exit 1; \
	fi
	@echo "$(CYAN)Starting backend...$(NC)"
	@sudo systemctl start ehop-backend && echo "  $(GREEN)✓ Backend started$(NC)" || echo "  $(YELLOW)⚠️  Backend may not have started$(NC)"
	@echo "$(CYAN)Starting frontend...$(NC)"
	@sudo systemctl start ehop-frontend && echo "  $(GREEN)✓ Frontend started$(NC)" || echo "  $(YELLOW)⚠️  Frontend may not have started$(NC)"
	@echo ""
	@echo "$(GREEN)✅ Services started$(NC)"
	@echo ""
	@echo "$(BOLD)Access:$(NC)"
	@echo "  Frontend: http://localhost:80"
	@echo "  Backend:  http://localhost:3000"
	@echo ""

stop: ## Stop all monolith services
	@echo "$(BLUE)🛑 Stopping monolith services...$(NC)"
	@echo ""
	@echo "$(CYAN)Stopping backend...$(NC)"
	@sudo systemctl stop ehop-backend && echo "  $(GREEN)✓ Backend stopped$(NC)" || echo "  $(YELLOW)⚠️  Backend may not have been running$(NC)"
	@echo "$(CYAN)Stopping frontend...$(NC)"
	@sudo systemctl stop ehop-frontend && echo "  $(GREEN)✓ Frontend stopped$(NC)" || echo "  $(YELLOW)⚠️  Frontend may not have been running$(NC)"
	@echo ""
	@echo "$(GREEN)✅ All services stopped$(NC)"
	@echo ""

restart: stop start ## Restart all monolith services (stop → start)

# ==============================================================================
# MONITORING & HEALTH
# ==============================================================================

health-check: ## Check health of all services
	@echo "$(BLUE)🏥 Health Check$(NC)"
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
	@HEALTH=$$(curl -s -o /dev/null -w "%{http_code}" http://localhost:80 2>/dev/null || echo "000"); \
	if [ "$$HEALTH" = "200" ]; then \
		echo "  $(GREEN)✓ Healthy$(NC) (HTTP $$HEALTH)"; \
	else \
		echo "  $(RED)✗ Unhealthy$(NC) (HTTP $$HEALTH)"; \
	fi
	@echo ""
	@echo "$(CYAN)Database:$(NC)"
	@sudo systemctl is-active --quiet postgresql && echo "  $(GREEN)✓ Running$(NC)" || echo "  $(RED)✗ Not running$(NC)"
	@echo ""

logs: ## Show all service logs (live)
	@echo "$(BLUE)📋 Monolith logs (Ctrl+C to exit)$(NC)"
	@echo "$(CYAN)────────────────────────────────────────────────────────────────$(NC)"
	@sudo journalctl -u ehop-backend -u ehop-frontend -f

logs-backend: ## Show backend logs (live)
	@echo "$(BLUE)📋 Backend logs (Ctrl+C to exit)$(NC)"
	@echo "$(CYAN)────────────────────────────────────────────────────────────────$(NC)"
	@sudo journalctl -u ehop-backend -f

logs-frontend: ## Show frontend logs (live)
	@echo "$(BLUE)📋 Frontend logs (Ctrl+C to exit)$(NC)"
	@echo "$(CYAN)────────────────────────────────────────────────────────────────$(NC)"
	@sudo journalctl -u ehop-frontend -f

# ==============================================================================
# BACKUP & RECOVERY
# ==============================================================================

backup: ## Create backup of configuration and data
	@echo "$(BLUE)💾 Creating monolith backup...$(NC)"
	@echo ""
	@mkdir -p $(BACKUP_DIR)
	@BACKUP_FILE="$(BACKUP_DIR)/monolith-$(TIMESTAMP).tar.gz"; \
	echo "$(YELLOW)Backing up to: $$BACKUP_FILE$(NC)"; \
	if [ -f "$(CONFIG_FILE)" ]; then \
		tar czf $$BACKUP_FILE $(CONFIG_FILE) $(VERSIONS_FILE) 2>/dev/null && \
		echo "$(GREEN)✓ Configuration backed up$(NC)" || \
		echo "$(YELLOW)⚠️  Config backup failed$(NC)"; \
	fi
	@echo "$(GREEN)✅ Backup complete$(NC)"
	@echo ""
	@ls -lh $(BACKUP_DIR)/ | tail -5
	@echo ""

backup-db: ## Create database snapshot with retention
	@echo "$(BLUE)💾 Creating database snapshot...$(NC)"
	@echo ""
	@INI_FILE="$(CONFIG_FILE)" BACKUP_DIR="$(BACKUP_DB_DIR)" DAYS_KEEP="$(BACKUP_DB_DAYS)" MAX_TOTAL_BYTES="$(BACKUP_DB_MAX_BYTES)" COMPRESS="$(BACKUP_DB_COMPRESS)" ../backup/backup-db.sh
	@echo ""

restore: ## Restore monolith from backup
	@echo "$(BLUE)📥 Restoring monolith from backup...$(NC)"
	@echo ""
	@echo "$(CYAN)Available backups:$(NC)"
	@if [ -d "$(BACKUP_DIR)" ] && [ -n "$$(ls $(BACKUP_DIR)/*.tar.gz 2>/dev/null)" ]; then \
		ls -1t $(BACKUP_DIR)/*.tar.gz | head -10 | nl; \
		echo ""; \
		read -p "Select backup number to restore: " num; \
		BACKUP_FILE=$$(ls -1t $(BACKUP_DIR)/*.tar.gz | sed -n "$${num}p"); \
		if [ -n "$$BACKUP_FILE" ]; then \
			echo "$(YELLOW)Restoring from: $$BACKUP_FILE$(NC)"; \
			tar xzf $$BACKUP_FILE && \
			echo "$(GREEN)✅ Restore complete$(NC)"; \
		else \
			echo "$(RED)Invalid selection$(NC)"; \
		fi; \
	else \
		echo "$(YELLOW)No backups found$(NC)"; \
	fi
	@echo ""

restore-db: ## Restore database from snapshot
	@echo "$(BLUE)📥 Restoring database from snapshot...$(NC)"
	@echo ""
	@echo "$(CYAN)Available database backups:$(NC)"
	@if [ -d "$(BACKUP_DB_DIR)" ] && [ -n "$$(ls $(BACKUP_DB_DIR)/ehop_*.sql* 2>/dev/null)" ]; then \
		ls -1t $(BACKUP_DB_DIR)/ehop_*.sql* | head -10 | nl; \
		echo ""; \
		read -p "Select backup number to restore: " num; \
		BACKUP_FILE=$$(ls -1t $(BACKUP_DB_DIR)/ehop_*.sql* | sed -n "$${num}p"); \
		if [ -n "$$BACKUP_FILE" ]; then \
			echo "$(YELLOW)Restoring from: $$BACKUP_FILE$(NC)"; \
			set -a; . $(CONFIG_FILE); set +a; \
			if [[ "$$BACKUP_FILE" == *.gz ]]; then \
				gunzip -c $$BACKUP_FILE | PGPASSWORD=$$DB_PASSWORD psql -h $${DB_HOST:-localhost} -p $${DB_PORT:-5432} -U $$DB_USER -d $$DB_NAME; \
			else \
				PGPASSWORD=$$DB_PASSWORD psql -h $${DB_HOST:-localhost} -p $${DB_PORT:-5432} -U $$DB_USER -d $$DB_NAME < $$BACKUP_FILE; \
			fi; \
			echo "$(GREEN)✅ Database restore complete$(NC)"; \
		else \
			echo "$(RED)Invalid selection$(NC)"; \
		fi; \
	else \
		echo "$(YELLOW)No database backups found$(NC)"; \
	fi
	@echo ""

# ==============================================================================
# CONFIGURATION & VERSIONS
# ==============================================================================

config: ## Show current configuration
	@echo ""
	@echo "$(BLUE)📋 Monolith Configuration$(NC)"
	@echo ""
	@if [ -f "$(CONFIG_FILE)" ]; then \
		echo "$(CYAN)Current values:$(NC)"; \
		grep "^[^#]" $(CONFIG_FILE) | sed 's/^/  /'; \
	else \
		echo "$(YELLOW)No configuration found - run 'make install'$(NC)"; \
	fi
	@echo ""

versions: ## Show component versions
	@echo ""
	@echo "$(BLUE)ℹ️  Component Versions$(NC)"
	@echo ""
	@if [ -f "$(VERSIONS_FILE)" ]; then \
		echo "$(CYAN)Configured versions:$(NC)"; \
		grep "^[^#]" $(VERSIONS_FILE) | sed 's/^/  /'; \
	else \
		echo "$(YELLOW)Version file not found$(NC)"; \
	fi
	@echo ""

update: ## Update version configuration
	@echo "$(BLUE)📦 Updating versions...$(NC)"
	@echo ""
	@echo "$(YELLOW)Edit $(VERSIONS_FILE) with new versions, then run 'make upgrade'$(NC)"
	@echo ""

upgrade: ## Upgrade monolith to new versions
	@echo "$(BLUE)🔄 Upgrading monolith...$(NC)"
	@echo ""
	@echo "$(YELLOW)Stopping services...$(NC)"
	@$(MAKE) -s stop
	@echo ""
	@echo "$(YELLOW)Building and deploying new versions...$(NC)"
	@./install-monolith.sh upgrade
	@echo ""
	@echo "$(YELLOW)Starting services...$(NC)"
	@$(MAKE) -s start
	@echo ""
	@echo "$(GREEN)✅ Upgrade complete$(NC)"
	@echo ""

# ==============================================================================
# MAINTENANCE
# ==============================================================================

clean: ## Clean temporary files and old logs
	@echo "$(BLUE)🧹 Cleaning monolith...$(NC)"
	@echo ""
	@echo "$(CYAN)Cleaning temporary files...$(NC)"
	@find . -name "*.log" -delete 2>/dev/null && echo "  $(GREEN)✓ Logs cleaned$(NC)" || true
	@find . -name "__pycache__" -delete 2>/dev/null && echo "  $(GREEN)✓ Cache cleaned$(NC)" || true
	@find . -name ".DS_Store" -delete 2>/dev/null && echo "  $(GREEN)✓ macOS files cleaned$(NC)" || true
	@echo ""
	@echo "$(GREEN)✅ Cleanup complete$(NC)"
	@echo ""

# ==============================================================================
# Default goal
# ==============================================================================

.SILENT:
