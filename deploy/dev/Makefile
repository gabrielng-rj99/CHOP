# EHOP - Development Environment Makefile
# Located in: deploy/dev/Makefile
# Usage: make -f deploy/dev/Makefile <target>
# Or: cd deploy/dev && make <target>

.PHONY: help start stop restart reset logs status health-check clean

# Colors
RED := \033[0;31m
GREEN := \033[0;32m
YELLOW := \033[1;33m
BLUE := \033[0;34m
NC := \033[0m

help: ## Show development environment commands
	@echo "$(BLUE)╔════════════════════════════════════════════════════════════╗$(NC)"
	@echo "$(BLUE)║$(NC)    EHOP - Development Environment Tasks                  $(BLUE)║$(NC)"
	@echo "$(BLUE)╚════════════════════════════════════════════════════════════╝$(NC)"
	@echo ""
	@echo "$(YELLOW)Environment Management:$(NC)"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  $(GREEN)%-20s$(NC) %s\n", $$1, $$2}'
	@echo ""
	@echo "$(YELLOW)Configuration:$(NC)"
	@echo "  Config file: dev.ini"
	@echo "  Database: ehopdb_dev (PostgreSQL)"
	@echo "  Backend: http://localhost:3000"
	@echo "  Frontend: http://localhost:5173"
	@echo ""
	@echo "$(YELLOW)See Also:$(NC)"
	@echo "  - Quick start: cat INICIO-RAPIDO.md"
	@echo "  - Dev tests: cd ../.. && make test-blocking"
	@echo ""

start: ## Start development environment (backend + frontend)
	@echo "$(BLUE)🚀 Starting development environment...$(NC)"
	./start-dev.sh
	@echo "$(GREEN)✅ Environment started$(NC)"
	@echo "  Backend: http://localhost:3000"
	@echo "  Frontend: http://localhost:5173"

stop: ## Stop development environment
	@echo "$(YELLOW)⏹️  Stopping development environment...$(NC)"
	./stop-dev.sh
	@echo "$(GREEN)✅ Environment stopped$(NC)"

restart: stop start ## Restart development environment

reset: ## Reset development environment (WARNING: loses all data)
	@echo "$(RED)⚠️  This will reset the development environment!$(NC)"
	@echo "$(RED)⚠️  All data will be lost!$(NC)"
	@read -p "Are you sure? Type 'yes' to confirm: " response; \
	if [ "$$response" = "yes" ]; then \
		echo "$(YELLOW)Destroying environment...$(NC)"; \
		./destroy-dev.sh; \
		echo "$(YELLOW)Waiting for cleanup...$(NC)"; \
		sleep 2; \
		echo "$(YELLOW)Starting fresh environment...$(NC)"; \
		./start-dev.sh; \
		echo "$(GREEN)✅ Development environment reset$(NC)"; \
	else \
		echo "$(YELLOW)Cancelled$(NC)"; \
	fi

logs: ## Show development logs (all services)
	@echo "$(BLUE)📋 Development logs...$(NC)"
	@echo "Path: ../../logs/backend_dev/server.log"
	tail -f ../../logs/backend_dev/server.log

logs-blocking: ## Show login blocking system logs only
	@echo "$(BLUE)🔐 Login blocking system logs...$(NC)"
	tail -f ../../logs/backend_dev/server.log | grep -E "(🔒|🚫|✅|📝|❌)"

status: ## Check environment status
	@echo "$(BLUE)📊 Development Environment Status:$(NC)"
	@echo ""
	@echo "  Configuration:"
	@echo "    Config: dev.ini"
	@grep "^DB_NAME" dev.ini | sed 's/^/    Database: /'
	@grep "^API_PORT" dev.ini | sed 's/^/    API Port: /'
	@echo ""
	@echo "  Services:"
	@pgrep -f "ehop-backend-dev" > /dev/null && echo "    $(GREEN)✅$(NC) Backend running" || echo "    $(RED)❌$(NC) Backend stopped"
	@lsof -i :5173 > /dev/null 2>&1 && echo "    $(GREEN)✅$(NC) Frontend (5173)" || echo "    $(RED)❌$(NC) Frontend (5173)"
	@lsof -i :3000 > /dev/null 2>&1 && echo "    $(GREEN)✅$(NC) API (3000)" || echo "    $(RED)❌$(NC) API (3000)"
	@echo ""
	@echo "  Endpoints:"
	@echo "    Frontend: http://localhost:5173"
	@echo "    API: http://localhost:3000"
	@echo "    Health: http://localhost:3000/health"
	@echo ""

health-check: ## Check if services are healthy
	@echo "$(BLUE)🏥 Running health checks...$(NC)"
	@echo ""
	@echo "  Backend health:"
	@curl -s -o /dev/null -w "    Status: %{http_code}\n" http://localhost:3000/health || echo "    $(RED)❌ No response$(NC)"
	@echo ""
	@echo "  Frontend:"
	@curl -s -o /dev/null -w "    Status: %{http_code}\n" http://localhost:5173 || echo "    $(RED)❌ No response$(NC)"
	@echo ""

populate: ## Populate development database with sample data
	@echo "$(BLUE)📊 Populating database with sample data...$(NC)"
	./populate.sh
	@echo "$(GREEN)✅ Database populated$(NC)"

permissions: ## Reset file permissions (if needed)
	@echo "$(YELLOW)🔐 Resetting permissions...$(NC)"
	./reset-permissions.sh
	@echo "$(GREEN)✅ Permissions reset$(NC)"

clean: ## Clean development artifacts and logs
	@echo "$(YELLOW)🧹 Cleaning development artifacts...$(NC)"
	find . -name "*.log" -delete 2>/dev/null || true
	find . -name "__pycache__" -delete 2>/dev/null || true
	find . -name ".DS_Store" -delete 2>/dev/null || true
	rm -rf ../../logs/backend_dev/*.log 2>/dev/null || true
	@echo "$(GREEN)✅ Cleaned$(NC)"

.DEFAULT_GOAL := help
.SILENT:
