# EHOP - Monolith Deployment Makefile
# Located in: deploy/monolith/Makefile
# Usage: make -f deploy/monolith/Makefile <target>
# Or: cd deploy/monolith && make <target>

.PHONY: help install start stop destroy reset logs status health-check clean uninstall

# Colors
RED := \033[0;31m
GREEN := \033[0;32m
YELLOW := \033[1;33m
BLUE := \033[0;34m
NC := \033[0m

help: ## Show monolith deployment commands
	@echo "$(BLUE)╔════════════════════════════════════════════════════════════╗$(NC)"
	@echo "$(BLUE)║$(NC)    EHOP - Monolith Deployment Environment                $(BLUE)║$(NC)"
	@echo "$(BLUE)╚════════════════════════════════════════════════════════════╝$(NC)"
	@echo ""
	@echo "$(YELLOW)Installation & Management:$(NC)"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  $(GREEN)%-20s$(NC) %s\n", $$1, $$2}'
	@echo ""
	@echo "$(YELLOW)Configuration:$(NC)"
	@echo "  Config file: monolith.ini"
	@echo "  Installation path: /opt/ehop (default)"
	@echo "  Backend: http://localhost:3000"
	@echo "  Frontend: http://localhost:80"
	@echo ""
	@echo "$(YELLOW)See Also:$(NC)"
	@echo "  - Installation guide: cat README.md"
	@echo "  - Version config: cat versions.ini"
	@echo ""

install: ## Install monolith (one-time setup)
	@echo "$(BLUE)📦 Installing EHOP monolith...$(NC)"
	@echo "$(YELLOW)This will install the entire application as a single unit.$(NC)"
	@echo ""
	@read -p "Continue with installation? (y/N): " response; \
	if [ "$$response" = "y" ]; then \
		echo "$(YELLOW)Running installation script...$(NC)"; \
		./install-monolith.sh; \
		echo "$(GREEN)✅ Installation complete$(NC)"; \
		echo ""; \
		echo "$(YELLOW)Next steps:$(NC)"; \
		echo "  1. Review configuration: cat monolith.ini"; \
		echo "  2. Start services: make start"; \
		echo "  3. Check status: make status"; \
	else \
		echo "$(YELLOW)Installation cancelled$(NC)"; \
	fi

start: ## Start monolith services
	@echo "$(BLUE)🚀 Starting monolith services...$(NC)"
	./start-monolith.sh
	@echo "$(GREEN)✅ Services started$(NC)"
	@echo ""
	@echo "  Backend: http://localhost:3000"
	@echo "  Frontend: http://localhost:80"
	@echo ""

stop: ## Stop monolith services
	@echo "$(YELLOW)⏹️  Stopping monolith services...$(NC)"
	./stop-monolith.sh
	@echo "$(GREEN)✅ Services stopped$(NC)"

restart: stop start ## Restart monolith services

reset: ## Reset monolith configuration (keeps installation)
	@echo "$(YELLOW)⚠️  This will reset configuration but keep installation.$(NC)"
	@read -p "Continue? (y/N): " response; \
	if [ "$$response" = "y" ]; then \
		echo "$(YELLOW)Resetting configuration...$(NC)"; \
		./stop-monolith.sh; \
		sleep 2; \
		./start-monolith.sh; \
		echo "$(GREEN)✅ Configuration reset$(NC)"; \
	else \
		echo "$(YELLOW)Cancelled$(NC)"; \
	fi

destroy: ## Uninstall monolith completely (WARNING: removes everything)
	@echo "$(RED)⚠️  This will completely remove the monolith installation!$(NC)"
	@echo "$(RED)⚠️  All data and configuration will be lost!$(NC)"
	@read -p "Type 'yes' to confirm removal: " response; \
	if [ "$$response" = "yes" ]; then \
		echo "$(YELLOW)Destroying monolith...$(NC)"; \
		./destroy-monolith.sh; \
		echo "$(GREEN)✅ Monolith removed$(NC)"; \
	else \
		echo "$(YELLOW)Cancelled$(NC)"; \
	fi

logs: ## Show monolith logs
	@echo "$(BLUE)📋 Monolith logs...$(NC)"
	@echo "$(YELLOW)Log location depends on installation.$(NC)"
	@echo "Check /var/log/ehop/ or configured log directory"

logs-backend: ## Show backend logs
	@echo "$(BLUE)📋 Backend logs...$(NC)"
	@tail -f /var/log/ehop/backend.log 2>/dev/null || echo "  Backend logs not found (may not be installed)"

logs-frontend: ## Show frontend logs
	@echo "$(BLUE)📋 Frontend logs...$(NC)"
	@tail -f /var/log/ehop/frontend.log 2>/dev/null || echo "  Frontend logs not found (may not be installed)"

status: ## Check monolith installation and service status
	@echo "$(BLUE)📊 Monolith Status:$(NC)"
	@echo ""
	@echo "  Installation:"
	@if [ -f monolith.ini ]; then \
		echo "    $(GREEN)✅$(NC) Configuration exists"; \
		grep "^INSTALL_PATH" monolith.ini | sed 's/^/    /'; \
	else \
		echo "    $(RED)❌$(NC) Not installed"; \
	fi
	@echo ""
	@echo "  Services:"
	@pgrep -f "ehop-backend" > /dev/null && echo "    $(GREEN)✅$(NC) Backend running" || echo "    $(RED)❌$(NC) Backend stopped"
	@pgrep -f "frontend\|nginx\|http" > /dev/null && echo "    $(GREEN)✅$(NC) Frontend running" || echo "    $(RED)❌$(NC) Frontend stopped"
	@systemctl is-active --quiet postgresql && echo "    $(GREEN)✅$(NC) PostgreSQL running" || echo "    $(RED)❌$(NC) PostgreSQL stopped"
	@echo ""
	@echo "  Endpoints:"
	@echo "    Backend: http://localhost:3000"
	@echo "    Frontend: http://localhost:80"
	@echo ""

health-check: ## Check if monolith services are healthy
	@echo "$(BLUE)🏥 Running health checks...$(NC)"
	@echo ""
	@echo "  Backend health:"
	@curl -s -o /dev/null -w "    Status: %{http_code}\n" http://localhost:3000/health || echo "    $(RED)❌ No response$(NC)"
	@echo ""
	@echo "  Frontend:"
	@curl -s -o /dev/null -w "    Status: %{http_code}\n" http://localhost:80 || echo "    $(RED)❌ No response$(NC)"
	@echo ""
	@echo "  Database:"
	@psql -U postgres -c "SELECT 1" > /dev/null 2>&1 && echo "    $(GREEN)✅$(NC) Database ready" || echo "    $(RED)❌$(NC) Database not ready"
	@echo ""

config: ## Show current configuration
	@echo "$(BLUE)📋 Monolith Configuration:$(NC)"
	@echo ""
	@if [ -f monolith.ini ]; then \
		echo "  Configuration values:"; \
		grep "^[^#]" monolith.ini | sed 's/^/    /'; \
	else \
		echo "  $(RED)No configuration found$(NC)"; \
		echo "  Run 'make install' first"; \
	fi
	@echo ""

versions: ## Show version information
	@echo "$(BLUE)ℹ️  Component Versions:$(NC)"
	@echo ""
	@if [ -f versions.ini ]; then \
		echo "  Configured versions:"; \
		grep "^[^#]" versions.ini | sed 's/^/    /'; \
	else \
		echo "  Version file not found"; \
	fi
	@echo ""

clean: ## Clean monolith artifacts and logs
	@echo "$(YELLOW)🧹 Cleaning monolith artifacts...$(NC)"
	@find . -name "*.log" -delete 2>/dev/null || true
	@find . -name "__pycache__" -delete 2>/dev/null || true
	@find . -name ".DS_Store" -delete 2>/dev/null || true
	@echo "$(GREEN)✅ Cleaned$(NC)"

uninstall: destroy ## Alias for destroy (remove everything)

upgrade: ## Upgrade monolith components (if supported)
	@echo "$(BLUE)📦 Upgrading monolith...$(NC)"
	@echo "$(YELLOW)Update versions in versions.ini and run this command.$(NC)"
	@echo "TODO: Implement upgrade logic based on versions.ini"

backup: ## Create backup of monolith configuration and data
	@echo "$(BLUE)💾 Creating monolith backup...$(NC)"
	@mkdir -p backups
	@tar czf backups/monolith-config-$$(date +%Y%m%d-%H%M%S).tar.gz monolith.ini versions.ini
	@echo "$(GREEN)✅ Backup created in backups/$(NC)"

restore: ## Restore monolith from backup
	@echo "$(BLUE)📥 Restoring monolith...$(NC)"
	@echo "$(YELLOW)Available backups:$(NC)"
	@ls -lh backups/*.tar.gz 2>/dev/null || echo "  No backups found"

info: ## Show monolith deployment information
	@echo "$(BLUE)ℹ️  EHOP Monolith Information:$(NC)"
	@echo ""
	@echo "  Deployment Type: Monolith"
	@echo "  Installation Method: Single-unit installation"
	@echo "  Services: Backend, Frontend, Database"
	@echo ""
	@echo "  Configuration:"
	@echo "    Config: monolith.ini"
	@echo "    Versions: versions.ini"
	@echo ""
	@echo "  Default Paths:"
	@echo "    Installation: /opt/ehop"
	@echo "    Logs: /var/log/ehop"
	@echo "    Data: /var/lib/ehop"
	@echo ""

.DEFAULT_GOAL := help
.SILENT:
