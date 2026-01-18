# EHOP - Docker Deployment Makefile
# Located in: deploy/docker/Makefile
# Usage: make -f deploy/docker/Makefile <target>
# Or: cd deploy/docker && make <target>

.PHONY: help build up down logs status health-check clean rebuild restart

# Colors
RED := \033[0;31m
GREEN := \033[0;32m
YELLOW := \033[1;33m
BLUE := \033[0;34m
NC := \033[0m

help: ## Show Docker deployment commands
	@echo "$(BLUE)╔════════════════════════════════════════════════════════════╗$(NC)"
	@echo "$(BLUE)║$(NC)    EHOP - Docker Deployment Environment                  $(BLUE)║$(NC)"
	@echo "$(BLUE)╚════════════════════════════════════════════════════════════╝$(NC)"
	@echo ""
	@echo "$(YELLOW)Container Management:$(NC)"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  $(GREEN)%-20s$(NC) %s\n", $$1, $$2}'
	@echo ""
	@echo "$(YELLOW)Configuration:$(NC)"
	@echo "  Docker Compose: docker-compose.yml"
	@echo "  Environment: .env"
	@echo "  Backend: http://localhost:3000"
	@echo "  Frontend: http://localhost:5173"
	@echo ""
	@echo "$(YELLOW)See Also:$(NC)"
	@echo "  - Docker docs: cat .env.example"
	@echo "  - Compose config: cat docker-compose.yml"
	@echo ""

build: ## Build Docker images
	@echo "$(BLUE)🐳 Building Docker images...$(NC)"
	docker compose -f docker-compose.yml build
	@echo "$(GREEN)✅ Images built successfully$(NC)"
	@docker images | grep -E "ehop|IMAGE" || true

up: ## Start Docker containers
	@echo "$(BLUE)🚀 Starting Docker containers...$(NC)"
	docker compose -f docker-compose.yml up -d
	@echo "$(GREEN)✅ Containers started$(NC)"
	@echo ""
	@echo "  Backend: http://localhost:3000"
	@echo "  Frontend: http://localhost:5173"
	@echo "  PostgreSQL: localhost:5432"

down: ## Stop Docker containers
	@echo "$(YELLOW)⏹️  Stopping Docker containers...$(NC)"
	docker compose -f docker-compose.yml down
	@echo "$(GREEN)✅ Containers stopped$(NC)"

restart: down up ## Restart Docker containers

rebuild: ## Rebuild Docker images and restart containers
	@echo "$(BLUE)🔨 Rebuilding Docker environment...$(NC)"
	docker compose -f docker-compose.yml down -v
	docker compose -f docker-compose.yml build --no-cache
	docker compose -f docker-compose.yml up -d
	@echo "$(GREEN)✅ Docker environment rebuilt and running$(NC)"

logs: ## Show Docker logs (all services)
	@echo "$(BLUE)📋 Docker logs...$(NC)"
	docker compose -f docker-compose.yml logs -f

logs-backend: ## Show backend logs only
	@echo "$(BLUE)📋 Backend logs...$(NC)"
	docker compose -f docker-compose.yml logs -f backend

logs-frontend: ## Show frontend logs only
	@echo "$(BLUE)📋 Frontend logs...$(NC)"
	docker compose -f docker-compose.yml logs -f frontend

logs-db: ## Show database logs only
	@echo "$(BLUE)📋 Database logs...$(NC)"
	docker compose -f docker-compose.yml logs -f postgres

status: ## Check Docker containers status
	@echo "$(BLUE)📊 Docker Containers Status:$(NC)"
	@echo ""
	@docker compose -f docker-compose.yml ps
	@echo ""
	@echo "$(YELLOW)Image Information:$(NC)"
	@docker images | grep ehop || echo "  No EHOP images built yet"

health-check: ## Check if Docker services are healthy
	@echo "$(BLUE)🏥 Running Docker health checks...$(NC)"
	@echo ""
	@echo "  Backend health:"
	@curl -s -o /dev/null -w "    Status: %{http_code}\n" http://localhost:3000/health || echo "    $(RED)❌ No response$(NC)"
	@echo ""
	@echo "  Frontend:"
	@curl -s -o /dev/null -w "    Status: %{http_code}\n" http://localhost:5173 || echo "    $(RED)❌ No response$(NC)"
	@echo ""
	@echo "  Database:"
	@docker compose -f docker-compose.yml exec -T postgres pg_isready -U postgres > /dev/null 2>&1 && echo "    $(GREEN)✅$(NC) Database ready" || echo "    $(RED)❌$(NC) Database not ready"
	@echo ""

shell-backend: ## Open shell in backend container
	@echo "$(BLUE)🐚 Opening backend shell...$(NC)"
	docker compose -f docker-compose.yml exec backend bash

shell-frontend: ## Open shell in frontend container
	@echo "$(BLUE)🐚 Opening frontend shell...$(NC)"
	docker compose -f docker-compose.yml exec frontend bash

shell-db: ## Open PostgreSQL shell
	@echo "$(BLUE)🐚 Opening PostgreSQL shell...$(NC)"
	docker compose -f docker-compose.yml exec postgres psql -U postgres -d ehopdb

clean: ## Clean Docker volumes and containers (WARNING: loses data)
	@echo "$(RED)⚠️  This will remove containers and volumes!$(NC)"
	@read -p "Remove volumes too? (y/N): " response; \
	if [ "$$response" = "y" ]; then \
		echo "$(YELLOW)Removing containers and volumes...$(NC)"; \
		docker compose -f docker-compose.yml down -v; \
	else \
		echo "$(YELLOW)Removing containers only...$(NC)"; \
		docker compose -f docker-compose.yml down; \
	fi
	@echo "$(GREEN)✅ Cleaned$(NC)"

prune: ## Remove unused Docker resources (free up space)
	@echo "$(YELLOW)🧹 Pruning Docker resources...$(NC)"
	docker system prune -f
	@echo "$(GREEN)✅ Docker resources pruned$(NC)"

env-check: ## Verify environment configuration
	@echo "$(BLUE)📋 Environment Configuration:$(NC)"
	@echo ""
	@if [ -f .env ]; then \
		echo "  $(GREEN)✅$(NC) .env file exists"; \
		echo ""; \
		echo "  Configuration:"; \
		grep "^[^#]" .env | sed 's/^/    /'; \
	else \
		echo "  $(RED)❌$(NC) .env file missing"; \
		echo "    Creating from .env.example..."; \
		cp .env.example .env; \
		echo "    $(GREEN)✅$(NC) .env created (please review and update)"; \
	fi
	@echo ""

validate: ## Validate Docker Compose configuration
	@echo "$(BLUE)✓ Validating Docker Compose configuration...$(NC)"
	docker compose -f docker-compose.yml config > /dev/null && echo "$(GREEN)✅ Configuration is valid$(NC)" || echo "$(RED)❌ Configuration errors found$(NC)"

info: ## Show Docker and environment information
	@echo "$(BLUE)ℹ️  Docker Information:$(NC)"
	@echo ""
	@echo "  Docker Version:"
	@docker --version
	@echo ""
	@echo "  Docker Compose Version:"
	@docker compose version
	@echo ""
	@echo "  Compose File: docker-compose.yml"
	@echo "  Environment File: .env"
	@echo ""

.DEFAULT_GOAL := help
.SILENT:
