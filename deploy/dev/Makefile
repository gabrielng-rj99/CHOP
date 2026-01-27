# ==============================================================================
# Client Hub - Development Environment Makefile
# ==============================================================================
# Single entry point for all development operations.
# Located: deploy/dev/Makefile
# Usage: cd deploy/dev && make <target>
#        OR make -C deploy/dev <target>
#
# Key features:
# - Clear, organized command structure (no duplicates)
# - Intuitive naming (start, stop, logs, etc)
# - Language installation support (Go, Python, Node.js)
# - Automatic conflict detection
# - Comprehensive database management
# ==============================================================================

SHELL := /bin/bash
.SHELLFLAGS := -c

# ============================================================================
# VARIABLES & CONFIGURATION
# ============================================================================

# Paths
SCRIPT_DIR := $(CURDIR)
PROJECT_ROOT := $(shell cd $(CURDIR)/../.. && pwd)
BACKEND_DIR := $(PROJECT_ROOT)/backend
FRONTEND_DIR := $(PROJECT_ROOT)/frontend
LOGS_DIR := $(PROJECT_ROOT)/logs/backend_dev
CONFIG_FILE := $(SCRIPT_DIR)/dev.ini

# Binary names
BACKEND_BINARY := ehop-backend-dev
BACKEND_PATH := $(BACKEND_DIR)/$(BACKEND_BINARY)

# PID files
PID_DIR := $(PROJECT_ROOT)/.dev-pids
BACKEND_PID_FILE := $(PID_DIR)/backend.pid
VITE_PID_FILE := $(PID_DIR)/vite.pid

# Version requirements
GO_VERSION := 1.21
NODE_VERSION := 20
PYTHON_VERSION := 3.11

# Default ports (high-range for backend/frontend, standard for postgres)
# Backend & Frontend: High-range (40000-49999) to avoid conflicts
# PostgreSQL: ALWAYS 5432 (system native installation)
# Production uses: 80, 3000, 5432
# Tests use: 63000, 65080, 65432
# Dev uses: 43000, 45173, 5432
API_PORT ?= 43000
VITE_PORT ?= 45173
DB_PORT ?= 5432

# Color definitions
RED := $(shell printf '\033[0;31m')
GREEN := $(shell printf '\033[0;32m')
YELLOW := $(shell printf '\033[1;33m')
BLUE := $(shell printf '\033[0;34m')
MAGENTA := $(shell printf '\033[0;35m')
CYAN := $(shell printf '\033[0;36m')
WHITE := $(shell printf '\033[1;37m')
NC := $(shell printf '\033[0m')
BOLD := $(shell printf '\033[1m')

# ============================================================================
# LOAD CONFIGURATION
# ============================================================================

ifneq (,$(wildcard $(CONFIG_FILE)))
    API_PORT := $(shell grep -E "^API_PORT=" $(CONFIG_FILE) 2>/dev/null | cut -d'=' -f2 | tr -d ' ' || echo "43000")
    VITE_PORT := $(shell grep -E "^VITE_PORT=" $(CONFIG_FILE) 2>/dev/null | cut -d'=' -f2 | tr -d ' ' || echo "45173")
    DB_PORT := $(shell grep -E "^DB_PORT=" $(CONFIG_FILE) 2>/dev/null | cut -d'=' -f2 | tr -d ' ' || echo "5432")
    DB_HOST := $(shell grep -E "^DB_HOST=" $(CONFIG_FILE) 2>/dev/null | cut -d'=' -f2 | tr -d ' ' || echo "localhost")
    DB_USER := $(shell grep -E "^DB_USER=" $(CONFIG_FILE) 2>/dev/null | cut -d'=' -f2 | tr -d ' ' || echo "ehopuser")
    DB_NAME := $(shell grep -E "^DB_NAME=" $(CONFIG_FILE) 2>/dev/null | cut -d'=' -f2 | tr -d ' ' || echo "ehopdb_dev")
    DB_PASSWORD := $(shell grep -E "^DB_PASSWORD=" $(CONFIG_FILE) 2>/dev/null | cut -d'=' -f2 || echo "")
    JWT_SECRET := $(shell grep -E "^JWT_SECRET=" $(CONFIG_FILE) 2>/dev/null | cut -d'=' -f2 || echo "")
endif

# ============================================================================
# DEFAULT GOAL & PHONY TARGETS
# ============================================================================

.DEFAULT_GOAL := help

.PHONY: help \
        start stop restart build logs status health \
        db-status db-connect db-reset destroy-all \
        clean check-ports check-processes \
        install-deps \
        install-go install-python install-node \
        test test-coverage

# ============================================================================
# HELP
# ============================================================================

help: ## Show this help message
	@echo ""
	@echo "$(BLUE)╔══════════════════════════════════════════════════════════════════════════════╗$(NC)"
	@echo "$(BLUE)║$(NC)$(BOLD)              Client Hub - Development Environment                            $(BLUE)║$(NC)"
	@echo "$(BLUE)╚══════════════════════════════════════════════════════════════════════════════╝$(NC)"
	@echo ""
	@echo "$(YELLOW)━━━ QUICK START ━━━$(NC)"
	@echo "  $(GREEN)make start$(NC)         Start dev environment (backend + frontend)"
	@echo "  $(GREEN)make stop$(NC)          Stop all services"
	@echo "  $(GREEN)make logs$(NC)          View live backend logs"
	@echo "  $(GREEN)make status$(NC)        Check service status"
	@echo ""
	@echo "$(YELLOW)━━━ SERVICE MANAGEMENT ━━━$(NC)"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | grep -E "^\s*(start|stop|restart|build|logs|status|health)" | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  $(GREEN)%-20s$(NC) %s\n", $$1, $$2}'
	@echo ""
	@echo "$(YELLOW)━━━ DATABASE ━━━$(NC)"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | grep -E "^\s*db-" | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  $(GREEN)%-20s$(NC) %s\n", $$1, $$2}'
	@echo ""
	@echo "$(YELLOW)━━━ ENVIRONMENT MANAGEMENT ━━━$(NC)"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | grep -E "^\s*(clean|destroy-all|check)" | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  $(GREEN)%-20s$(NC) %s\n", $$1, $$2}'
	@echo ""
	@echo "$(YELLOW)━━━ LANGUAGE SETUP (for unconfigured environments only) ━━━$(NC)"
	@echo "$(MAGENTA)⚠️  Note: Skip these if you use pyenv, nvm, asdf, or similar managers$(NC)"
	@grep -E '^install-(go|python|node):.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  $(GREEN)%-20s$(NC) %s\n", $$1, $$2}'
	@echo ""
	@echo "$(YELLOW)━━━ DEPENDENCIES & TESTING ━━━$(NC)"
	@grep -E '^(install-deps|test):.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  $(GREEN)%-20s$(NC) %s\n", $$1, $$2}'
	@echo ""
	@echo "$(YELLOW)━━━ CONFIGURATION ━━━$(NC)"
	@echo "  Config:     $(CYAN)$(CONFIG_FILE)$(NC)"
	@echo "  Backend:    $(CYAN)http://localhost:$(API_PORT)$(NC)"
	@echo "  Frontend:   $(CYAN)http://localhost:$(VITE_PORT)$(NC)"
	@echo "  Database:   $(CYAN)$(DB_NAME)@$(DB_HOST):$(DB_PORT)$(NC)"
	@echo ""

# ============================================================================
# PRE-FLIGHT CHECKS
# ============================================================================

_check-config:
	@if [ ! -f "$(CONFIG_FILE)" ]; then \
		echo "$(RED)❌ Configuration file not found: $(CONFIG_FILE)$(NC)"; \
		echo "$(YELLOW)   Run 'make install-deps' first or create dev.ini$(NC)"; \
		exit 1; \
	fi

_check-go:
	@if ! command -v go &> /dev/null; then \
		echo "$(RED)❌ Go is not installed$(NC)"; \
		echo "$(YELLOW)   Install with: make install-go$(NC)"; \
		exit 1; \
	fi

_check-node:
	@if ! command -v node &> /dev/null || ! command -v npm &> /dev/null; then \
		echo "$(RED)❌ Node.js/npm is not installed$(NC)"; \
		echo "$(YELLOW)   Install with: make install-node$(NC)"; \
		exit 1; \
	fi

_check-postgres:
	@echo "$(CYAN)🔍 Checking PostgreSQL...$(NC)"
	@if ! pg_isready -h $(DB_HOST) -p $(DB_PORT) > /dev/null 2>&1; then \
		echo "$(YELLOW)⏳ PostgreSQL is not running. Starting with sudo...$(NC)"; \
		sudo systemctl start postgresql && echo "$(GREEN)✓ PostgreSQL started$(NC)" || { echo "$(RED)❌ Failed to start PostgreSQL$(NC)"; exit 1; }; \
		sleep 2; \
		RETRY=0; \
		while ! pg_isready -h $(DB_HOST) -p $(DB_PORT) > /dev/null 2>&1 && [ $$RETRY -lt 30 ]; do \
			echo "$(YELLOW)⏳ Waiting for PostgreSQL to be ready... ($$RETRY/30)$(NC)"; \
			sleep 1; \
			RETRY=$$((RETRY + 1)); \
		done; \
		if ! pg_isready -h $(DB_HOST) -p $(DB_PORT) > /dev/null 2>&1; then \
			echo "$(RED)❌ PostgreSQL failed to start on $(DB_HOST):$(DB_PORT)$(NC)"; \
			exit 1; \
		fi; \
		echo "$(GREEN)✓ PostgreSQL is ready$(NC)"; \
	else \
		echo "$(GREEN)✓ PostgreSQL is already running$(NC)"; \
	fi

_ensure-dirs:
	@mkdir -p $(LOGS_DIR)
	@mkdir -p $(PID_DIR)

# ============================================================================
# ENVIRONMENT SETUP - LANGUAGE INSTALLATION
# ============================================================================

install-go: ## Install Go ($(GO_VERSION)) - skip if using system Go or version manager
	@echo "$(BLUE)📦 Installing Go $(GO_VERSION)...$(NC)"
	@if command -v go &> /dev/null; then \
		CURRENT=$$(go version | awk '{print $$3}' | sed 's/go//'); \
		echo "$(YELLOW)ℹ️  Go is already installed: $$CURRENT$(NC)"; \
	else \
		echo "$(YELLOW)Downloading Go $(GO_VERSION)...$(NC)"; \
		cd /tmp && \
		curl -sSL https://go.dev/dl/go$(GO_VERSION).linux-amd64.tar.gz -o go.tar.gz && \
		sudo tar -C /usr/local -xzf go.tar.gz && \
		rm go.tar.gz && \
		echo "$(GREEN)✓ Go installed to /usr/local/go$(NC)"; \
		echo "$(YELLOW)Add to your PATH: export PATH=\$$PATH:/usr/local/go/bin$(NC)"; \
		go version; \
	fi

install-node: ## Install Node.js ($(NODE_VERSION)) - skip if using nvm/fnm/asdf
	@echo "$(BLUE)📦 Installing Node.js $(NODE_VERSION)...$(NC)"
	@if command -v node &> /dev/null; then \
		CURRENT=$$(node -v); \
		echo "$(YELLOW)ℹ️  Node.js is already installed: $$CURRENT$(NC)"; \
	else \
		echo "$(YELLOW)Installing via NodeSource...$(NC)"; \
		curl -fsSL https://deb.nodesource.com/setup_$(NODE_VERSION).x | sudo -E bash - && \
		sudo apt-get install -y nodejs && \
		echo "$(GREEN)✓ Node.js installed$(NC)"; \
		node -v && npm -v; \
	fi

install-python: ## Install Python ($(PYTHON_VERSION)) - skip if using pyenv/conda/venv
	@echo "$(BLUE)📦 Installing Python $(PYTHON_VERSION)...$(NC)"
	@if command -v python3 &> /dev/null; then \
		CURRENT=$$(python3 --version | awk '{print $$2}'); \
		echo "$(YELLOW)ℹ️  Python is already installed: $$CURRENT$(NC)"; \
	else \
		echo "$(YELLOW)Installing via deadsnakes PPA...$(NC)"; \
		sudo apt-get update && \
		sudo apt-get install -y python$(PYTHON_VERSION) python$(PYTHON_VERSION)-venv && \
		echo "$(GREEN)✓ Python installed$(NC)"; \
		python$(PYTHON_VERSION) --version; \
	fi

install-deps: _check-go _check-node ## Install all project dependencies (Go + npm)
	@echo "$(BLUE)📦 Installing dependencies...$(NC)"
	@echo ""
	@echo "$(CYAN)Backend (Go modules):$(NC)"
	@cd $(BACKEND_DIR) && go mod download && go mod tidy
	@echo "$(GREEN)✓ Go modules installed$(NC)"
	@echo ""
	@echo "$(CYAN)Frontend (npm):$(NC)"
	@cd $(FRONTEND_DIR) && npm install
	@echo "$(GREEN)✓ npm packages installed$(NC)"
	@echo ""
	@echo "$(GREEN)✅ All dependencies installed$(NC)"

# ============================================================================
# BUILD
# ============================================================================

build: _check-go ## Build backend binary (from latest code)
	@echo "$(BLUE)🔧 Building backend...$(NC)"
	@cd $(BACKEND_DIR) && \
		rm -f $(BACKEND_BINARY) && \
		go build -o $(BACKEND_BINARY) ./main.go
	@echo "$(GREEN)✓ Backend built successfully$(NC)"
	@ls -lh $(BACKEND_PATH) | awk '{print "  Size: " $$5 ", Modified: " $$6 " " $$7 " " $$8}'

build-fresh: _check-go ## Clean build (clears Go cache, rebuilds everything)
	@echo "$(BLUE)🔧 Clean build backend...$(NC)"
	@cd $(BACKEND_DIR) && \
		rm -f $(BACKEND_BINARY) && \
		go clean -cache && \
		go build -o $(BACKEND_BINARY) ./main.go
	@echo "$(GREEN)✓ Backend built (cache cleared)$(NC)"

# ============================================================================
# SERVICE MANAGEMENT - START/STOP/RESTART
# ============================================================================

start: _check-config _ensure-dirs ## Start dev environment (backend + frontend)
	@echo ""
	@echo "$(BLUE)╔══════════════════════════════════════════════════════════════════════════════╗$(NC)"
	@echo "$(BLUE)║$(NC)$(BOLD)              Starting Development Environment                                $(BLUE)║$(NC)"
	@echo "$(BLUE)╚══════════════════════════════════════════════════════════════════════════════╝$(NC)"
	@echo ""
	@$(MAKE) -s _detect-conflicts
	@$(MAKE) -s _check-go
	@$(MAKE) -s _check-node
	@$(MAKE) -s _check-postgres
	@if [ ! -f "$(BACKEND_PATH)" ]; then \
		$(MAKE) -s build; \
	else \
		echo "$(CYAN)ℹ️  Using existing backend binary$(NC)"; \
		echo "   (Run 'make build' to rebuild)"; \
		echo ""; \
	fi
	@$(MAKE) -s _start-backend
	@$(MAKE) -s _start-frontend
	@$(MAKE) -s _show-started

stop: ## Stop all services (backend + frontend)
	@echo "$(BLUE)🛑 Stopping services...$(NC)"
	@echo ""
	@if [ -f "$(BACKEND_PID_FILE)" ]; then \
		PID=$$(cat $(BACKEND_PID_FILE)); \
		if kill -0 $$PID 2>/dev/null; then \
			kill $$PID 2>/dev/null || true; \
			sleep 1; \
			if kill -0 $$PID 2>/dev/null; then kill -9 $$PID 2>/dev/null || true; fi; \
			echo "$(GREEN)✓ Backend stopped (PID: $$PID)$(NC)"; \
		fi; \
		rm -f $(BACKEND_PID_FILE); \
	else \
		if pgrep -f "$(BACKEND_BINARY)" > /dev/null; then \
			pkill -f "$(BACKEND_BINARY)" 2>/dev/null && echo "$(GREEN)✓ Backend stopped$(NC)"; \
		fi; \
	fi
	@if [ -f "$(VITE_PID_FILE)" ]; then \
		PID=$$(cat $(VITE_PID_FILE)); \
		if kill -0 $$PID 2>/dev/null; then \
			kill $$PID 2>/dev/null || true; \
			sleep 1; \
			if kill -0 $$PID 2>/dev/null; then kill -9 $$PID 2>/dev/null || true; fi; \
			echo "$(GREEN)✓ Frontend stopped (PID: $$PID)$(NC)"; \
		fi; \
		rm -f $(VITE_PID_FILE); \
	else \
		if pgrep -f "vite" > /dev/null; then \
			pkill -f "vite" 2>/dev/null && echo "$(GREEN)✓ Frontend stopped$(NC)"; \
		fi; \
	fi
	@echo ""
	@echo "$(GREEN)✅ All services stopped$(NC)"

restart: ## Rebuild and restart all services (stop → build → start)
	@$(MAKE) -s stop
	@sleep 1
	@$(MAKE) -s build
	@$(MAKE) -s start

restart-backend: ## Rebuild and restart backend only
	@echo "$(BLUE)🔄 Restarting backend...$(NC)"
	@if [ -f "$(BACKEND_PID_FILE)" ]; then \
		PID=$$(cat $(BACKEND_PID_FILE)); \
		kill $$PID 2>/dev/null || true; \
		rm -f $(BACKEND_PID_FILE); \
	fi
	@pkill -f "$(BACKEND_BINARY)" 2>/dev/null || true
	@sleep 1
	@$(MAKE) -s build
	@$(MAKE) -s _start-backend
	@echo ""
	@echo "$(GREEN)✅ Backend restarted$(NC)"

restart-frontend: ## Rebuild and restart frontend only
	@echo "$(BLUE)🔄 Restarting frontend...$(NC)"
	@if [ -f "$(VITE_PID_FILE)" ]; then \
		PID=$$(cat $(VITE_PID_FILE)); \
		kill $$PID 2>/dev/null || true; \
		rm -f $(VITE_PID_FILE); \
	fi
	@pkill -f "vite" 2>/dev/null || true
	@sleep 1
	@$(MAKE) -s _start-frontend
	@echo ""
	@echo "$(GREEN)✅ Frontend restarted$(NC)"

# ============================================================================
# INTERNAL START HELPERS
# ============================================================================

_detect-conflicts:
	@CONFLICT=0; \
	echo "$(CYAN)Checking for conflicts...$(NC)"; \
	OLD_BACKEND=$$(ps aux | grep -E "./ehop-backend[^-]" | grep -v grep | awk '{print $$2}' | head -1 || true); \
	if [ -n "$$OLD_BACKEND" ]; then \
		echo ""; \
		echo "$(RED)╔══════════════════════════════════════════════════════════════════════════════╗$(NC)"; \
		echo "$(RED)║  ⚠️   WARNING: OLD BACKEND PROCESS DETECTED                                  ║$(NC)"; \
		echo "$(RED)╚══════════════════════════════════════════════════════════════════════════════╝$(NC)"; \
		echo ""; \
		echo "  $(YELLOW)A stale backend process is running (PID: $$OLD_BACKEND)$(NC)"; \
		echo "  This may be using outdated code!"; \
		echo ""; \
		echo "$(BOLD)Options:$(NC)"; \
		echo "  1. Run '$(GREEN)make clean$(NC)' to kill all processes"; \
		echo "  2. Run '$(GREEN)kill $$OLD_BACKEND$(NC)' to kill just this process"; \
		echo ""; \
		exit 1; \
	fi; \
	API_PID=$$(lsof -ti :$(API_PORT) 2>/dev/null || true); \
	if [ -n "$$API_PID" ]; then \
		echo ""; \
		echo "$(RED)╔══════════════════════════════════════════════════════════════════════════════╗$(NC)"; \
		echo "$(RED)║  ⚠️   WARNING: PORT $(API_PORT) IS ALREADY IN USE                                   ║$(NC)"; \
		echo "$(RED)╚══════════════════════════════════════════════════════════════════════════════╝$(NC)"; \
		echo ""; \
		echo "$(BOLD)Options:$(NC)"; \
		echo "  1. Run '$(GREEN)make clean$(NC)' to free ports"; \
		echo "  2. Run '$(GREEN)kill $$API_PID$(NC)' to kill the process"; \
		echo "  3. Change API_PORT in dev.ini"; \
		echo ""; \
		exit 1; \
	fi; \
	VITE_PID=$$(lsof -ti :$(VITE_PORT) 2>/dev/null || true); \
	if [ -n "$$VITE_PID" ]; then \
		echo ""; \
		echo "$(RED)╔══════════════════════════════════════════════════════════════════════════════╗$(NC)"; \
		echo "$(RED)║  ⚠️   WARNING: PORT $(VITE_PORT) IS ALREADY IN USE                                  ║$(NC)"; \
		echo "$(RED)╚══════════════════════════════════════════════════════════════════════════════╝$(NC)"; \
		echo ""; \
		echo "$(BOLD)Options:$(NC)"; \
		echo "  1. Run '$(GREEN)make clean$(NC)' to free ports"; \
		echo "  2. Run '$(GREEN)kill $$VITE_PID$(NC)' to kill the process"; \
		echo "  3. Change VITE_PORT in dev.ini"; \
		echo ""; \
		exit 1; \
	fi; \
	echo "$(GREEN)✓ No conflicts detected$(NC)"; \
	echo ""

_start-backend:
	@echo "$(CYAN)Starting backend...$(NC)"
	@mkdir -p $(PID_DIR) $(LOGS_DIR)
	@cd $(BACKEND_DIR) && \
		DB_HOST=$(DB_HOST) \
		DB_PORT=$(DB_PORT) \
		DB_USER=$(DB_USER) \
		DB_PASSWORD="$(DB_PASSWORD)" \
		DB_NAME=$(DB_NAME) \
		JWT_SECRET="$(JWT_SECRET)" \
		API_PORT=$(API_PORT) \
		APP_ENV=development \
		./$(BACKEND_BINARY) > $(LOGS_DIR)/server.log 2>&1 & \
		echo $$! > $(BACKEND_PID_FILE) && \
		echo "PID written to $(BACKEND_PID_FILE)"
	@sleep 2
	@if [ -f "$(BACKEND_PID_FILE)" ]; then \
		PID=$$(cat $(BACKEND_PID_FILE)); \
		if [ -n "$$PID" ]; then \
			echo "$(GREEN)✓ Backend started (PID: $$PID)$(NC)"; \
		else \
			echo "$(RED)❌ Backend failed to start (empty PID)$(NC)"; \
			echo "$(YELLOW)   Check logs: $(LOGS_DIR)/server.log$(NC)"; \
			tail -20 $(LOGS_DIR)/server.log 2>/dev/null || true; \
			rm -f $(BACKEND_PID_FILE); \
			exit 1; \
		fi; \
	else \
		echo "$(RED)❌ PID file not created at $(BACKEND_PID_FILE)$(NC)"; \
		echo "$(YELLOW)   Check logs: $(LOGS_DIR)/server.log$(NC)"; \
		tail -20 $(LOGS_DIR)/server.log 2>/dev/null || true; \
		exit 1; \
	fi

_start-frontend:
	@echo "$(CYAN)Starting Vite dev server...$(NC)"
	@cd $(FRONTEND_DIR) && \
		if [ ! -d "node_modules" ]; then \
			echo "$(YELLOW)   Installing npm dependencies...$(NC)"; \
			npm install --silent; \
		fi && \
		VITE_PORT=$(VITE_PORT) API_PORT=$(API_PORT) \
		npm run dev > $(LOGS_DIR)/../vite-dev.log 2>&1 & \
		echo $$! > $(VITE_PID_FILE)
	@sleep 3
	@if [ -f "$(VITE_PID_FILE)" ]; then \
		PID=$$(cat $(VITE_PID_FILE)); \
		if [ -n "$$PID" ]; then \
			echo "$(GREEN)✓ Frontend started (PID: $$PID)$(NC)"; \
		else \
			echo "$(RED)❌ Frontend failed to start$(NC)"; \
			tail -20 $(LOGS_DIR)/../vite-dev.log 2>/dev/null || true; \
			exit 1; \
		fi; \
	fi

_show-started:
	@echo ""
	@echo "$(GREEN)╔══════════════════════════════════════════════════════════════════════════════╗$(NC)"
	@echo "$(GREEN)║  ✅  Development environment started successfully!                           ║$(NC)"
	@echo "$(GREEN)╚══════════════════════════════════════════════════════════════════════════════╝$(NC)"
	@echo ""
	@echo "$(BOLD)Services:$(NC)"
	@echo "  Frontend (Vite):  $(CYAN)http://localhost:$(VITE_PORT)$(NC)  ⚡ Hot reload enabled"
	@echo "  Backend API:      $(CYAN)http://localhost:$(API_PORT)$(NC)"
	@echo "  API Health:       $(CYAN)http://localhost:$(API_PORT)/health$(NC)"
	@echo ""
	@echo "$(BOLD)Logs:$(NC)"
	@echo "  Backend:  $(CYAN)$(LOGS_DIR)/server.log$(NC)"
	@echo "  Vite:     $(CYAN)$(LOGS_DIR)/../vite-dev.log$(NC)"
	@echo ""
	@echo "$(BOLD)Commands:$(NC)"
	@echo "  make logs       - View backend logs (live)"
	@echo "  make status     - Check service status"
	@echo "  make stop       - Stop all services"
	@echo "  make restart    - Rebuild and restart"
	@echo ""

# ============================================================================
# MONITORING - STATUS, HEALTH, LOGS
# ============================================================================

status: ## Show status of all services
	@echo ""
	@echo "$(BLUE)╔══════════════════════════════════════════════════════════════════════════════╗$(NC)"
	@echo "$(BLUE)║$(NC)$(BOLD)              Development Environment Status                                  $(BLUE)║$(NC)"
	@echo "$(BLUE)╚══════════════════════════════════════════════════════════════════════════════╝$(NC)"
	@echo ""
	@echo "$(CYAN)Backend:$(NC)"
	@if [ -f "$(BACKEND_PID_FILE)" ]; then \
		PID=$$(cat $(BACKEND_PID_FILE)); \
		if kill -0 $$PID 2>/dev/null; then \
			UPTIME=$$(ps -p $$PID -o etime= 2>/dev/null | xargs || echo "unknown"); \
			echo "  $(GREEN)● Running$(NC) (PID: $$PID, uptime: $$UPTIME)"; \
		else \
			echo "  $(RED)○ Stopped$(NC) (stale PID file)"; \
		fi; \
	else \
		RUNNING=$$(lsof -ti :$(API_PORT) 2>/dev/null || true); \
		if [ -n "$$RUNNING" ]; then \
			echo "  $(YELLOW)● Running$(NC) (PID: $$RUNNING) - No PID file"; \
		else \
			echo "  $(RED)○ Stopped$(NC)"; \
		fi; \
	fi
	@echo "  URL: http://localhost:$(API_PORT)"
	@echo ""
	@echo "$(CYAN)Frontend (Vite):$(NC)"
	@if [ -f "$(VITE_PID_FILE)" ]; then \
		PID=$$(cat $(VITE_PID_FILE)); \
		if kill -0 $$PID 2>/dev/null; then \
			UPTIME=$$(ps -p $$PID -o etime= 2>/dev/null | xargs || echo "unknown"); \
			echo "  $(GREEN)● Running$(NC) (PID: $$PID, uptime: $$UPTIME)"; \
		else \
			echo "  $(RED)○ Stopped$(NC) (stale PID file)"; \
		fi; \
	else \
		RUNNING=$$(lsof -ti :$(VITE_PORT) 2>/dev/null || true); \
		if [ -n "$$RUNNING" ]; then \
			echo "  $(YELLOW)● Running$(NC) (PID: $$RUNNING) - No PID file"; \
		else \
			echo "  $(RED)○ Stopped$(NC)"; \
		fi; \
	fi
	@echo "  URL: http://localhost:$(VITE_PORT)"
	@echo ""
	@echo "$(CYAN)PostgreSQL:$(NC)"
	@if pg_isready -h $(DB_HOST) -p $(DB_PORT) > /dev/null 2>&1; then \
		echo "  $(GREEN)● Running$(NC) ($(DB_HOST):$(DB_PORT))"; \
		echo "  Database: $(DB_NAME)"; \
	else \
		echo "  $(RED)○ Not available$(NC)"; \
	fi
	@echo ""

health: ## Check health of all services
	@echo "$(BLUE)🏥 Health Check$(NC)"
	@echo ""
	@echo "$(CYAN)Backend:$(NC)"
	@HEALTH=$$(curl -s -o /dev/null -w "%{http_code}" http://localhost:$(API_PORT)/health 2>/dev/null || echo "000"); \
	if [ "$$HEALTH" = "200" ]; then \
		echo "  $(GREEN)✓ Healthy$(NC) (HTTP $$HEALTH)"; \
		curl -s http://localhost:$(API_PORT)/health 2>/dev/null | python3 -m json.tool 2>/dev/null | sed 's/^/  /' || true; \
	else \
		echo "  $(RED)✗ Unhealthy$(NC) (HTTP $$HEALTH)"; \
	fi
	@echo ""
	@echo "$(CYAN)Frontend:$(NC)"
	@HEALTH=$$(curl -s -o /dev/null -w "%{http_code}" http://localhost:$(VITE_PORT) 2>/dev/null || echo "000"); \
	if [ "$$HEALTH" = "200" ]; then \
		echo "  $(GREEN)✓ Healthy$(NC) (HTTP $$HEALTH)"; \
	else \
		echo "  $(RED)✗ Unhealthy$(NC) (HTTP $$HEALTH)"; \
	fi
	@echo ""
	@echo "$(CYAN)Database:$(NC)"
	@if pg_isready -h $(DB_HOST) -p $(DB_PORT) > /dev/null 2>&1; then \
		echo "  $(GREEN)✓ Healthy$(NC)"; \
	else \
		echo "  $(RED)✗ Unhealthy$(NC)"; \
	fi
	@echo ""

logs: ## View live backend logs (Ctrl+C to exit)
	@echo "$(BLUE)📋 Backend logs (Ctrl+C to exit)$(NC)"
	@echo "$(CYAN)────────────────────────────────────────────────────────────────$(NC)"
	@tail -f $(LOGS_DIR)/server.log 2>/dev/null || echo "$(YELLOW)No logs found. Is the backend running?$(NC)"

logs-frontend: ## View live frontend (Vite) logs (Ctrl+C to exit)
	@echo "$(BLUE)📋 Frontend logs (Ctrl+C to exit)$(NC)"
	@echo "$(CYAN)────────────────────────────────────────────────────────────────$(NC)"
	@tail -f $(LOGS_DIR)/../vite-dev.log 2>/dev/null || echo "$(YELLOW)No logs found. Is Vite running?$(NC)"

logs-all: ## View all logs (backend + frontend, Ctrl+C to exit)
	@echo "$(BLUE)📋 All logs (Ctrl+C to exit)$(NC)"
	@echo "$(CYAN)────────────────────────────────────────────────────────────────$(NC)"
	@tail -f $(LOGS_DIR)/server.log $(LOGS_DIR)/../vite-dev.log 2>/dev/null || echo "$(YELLOW)No logs found$(NC)"

# ============================================================================
# DATABASE MANAGEMENT
# ============================================================================

db-status: _check-postgres ## Show database info and users
	@echo "$(BLUE)🗄️  Database Status$(NC)"
	@echo ""
	@echo "$(CYAN)Connection:$(NC)"
	@echo "  Host: $(DB_HOST):$(DB_PORT)"
	@echo "  Database: $(DB_NAME)"
	@echo "  User: $(DB_USER)"
	@echo ""
	@echo "$(CYAN)Tables:$(NC)"
	@PGPASSWORD="$(DB_PASSWORD)" psql -h $(DB_HOST) -p $(DB_PORT) -U $(DB_USER) -d $(DB_NAME) -c "\dt" 2>/dev/null | sed 's/^/  /' || echo "  $(RED)Could not connect$(NC)"
	@echo ""
	@echo "$(CYAN)Users in database:$(NC)"
	@PGPASSWORD="$(DB_PASSWORD)" psql -h $(DB_HOST) -p $(DB_PORT) -U $(DB_USER) -d $(DB_NAME) -c "SELECT username, role, failed_attempts, lock_level, locked_until FROM users WHERE deleted_at IS NULL;" 2>/dev/null | sed 's/^/  /' || echo "  $(RED)Could not query$(NC)"

db-connect: _check-postgres ## Open interactive PostgreSQL shell
	@echo "$(BLUE)🗄️  Connecting to $(DB_NAME)...$(NC)"
	@PGPASSWORD="$(DB_PASSWORD)" psql -h $(DB_HOST) -p $(DB_PORT) -U $(DB_USER) -d $(DB_NAME)

db-reset: _check-postgres ## Reset database (delete all data, recreate schema)
	@echo ""
	@echo "$(RED)╔══════════════════════════════════════════════════════════════════════════════╗$(NC)"
	@echo "$(RED)║  ⚠️   WARNING: This will DELETE ALL DATA in $(DB_NAME)                       ║$(NC)"
	@echo "$(RED)╚══════════════════════════════════════════════════════════════════════════════╝$(NC)"
	@echo ""
	@read -p "Type 'reset' to confirm: " confirm; \
	if [ "$$confirm" = "reset" ]; then \
		echo ""; \
		echo "$(YELLOW)Dropping database...$(NC)"; \
		sudo -u postgres psql -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '$(DB_NAME)';" > /dev/null 2>&1 || true; \
		sudo -u postgres psql -c "DROP DATABASE IF EXISTS $(DB_NAME);" > /dev/null 2>&1; \
		echo "$(YELLOW)Creating database...$(NC)"; \
		sudo -u postgres psql -c "CREATE DATABASE $(DB_NAME) OWNER $(DB_USER);" > /dev/null 2>&1; \
		echo "$(GREEN)✅ Database reset complete$(NC)"; \
		echo ""; \
		echo "$(YELLOW)Restart backend to reinitialize schema:$(NC)"; \
		echo "  make restart-backend"; \
	else \
		echo "$(YELLOW)Cancelled$(NC)"; \
	fi

# ============================================================================
# ENVIRONMENT CLEANUP
# ============================================================================

clean: ## Kill all dev processes and clean up (keeps code & config)
	@echo "$(BLUE)🧹 Cleaning development environment...$(NC)"
	@echo ""
	@echo "$(CYAN)Killing processes by port (most reliable)...$(NC)"
	@lsof -ti :$(API_PORT) 2>/dev/null | xargs -r kill -9 2>/dev/null || true
	@sleep 0.3
	@echo "  $(GREEN)✓ Port $(API_PORT) freed$(NC)"
	@lsof -ti :$(VITE_PORT) 2>/dev/null | xargs -r kill -9 2>/dev/null || true
	@sleep 0.3
	@echo "  $(GREEN)✓ Port $(VITE_PORT) freed$(NC)"
	@echo "$(CYAN)Cleaning PID files...$(NC)"
	@rm -rf $(PID_DIR) 2>/dev/null || true
	@echo "  $(GREEN)✓ PID files cleaned$(NC)"
	@echo ""
	@echo "$(GREEN)✅ Cleanup complete (code and config preserved)$(NC)"

destroy-all: _check-postgres clean ## Completely destroy dev environment (processes + database + logs, keeps code)
	@echo ""
	@echo "$(RED)╔══════════════════════════════════════════════════════════════════════════════╗$(NC)"
	@echo "$(RED)║  🔥 DANGER: COMPLETE ENVIRONMENT DESTRUCTION 🔥                             ║$(NC)"
	@echo "$(RED)╚══════════════════════════════════════════════════════════════════════════════╝$(NC)"
	@echo ""
	@echo "This will DELETE:"
	@echo "  $(RED)✗$(NC) All running dev processes"
	@echo "  $(RED)✗$(NC) Development database ($(DB_NAME)) - ALL DATA LOST"
	@echo "  $(RED)✗$(NC) All log files"
	@echo "  $(RED)✗$(NC) Compiled backend binary"
	@echo ""
	@echo "This will KEEP:"
	@echo "  $(GREEN)✓$(NC) Source code (backend & frontend)"
	@echo "  $(GREEN)✓$(NC) Configuration (dev.ini)"
	@echo "  $(GREEN)✓$(NC) node_modules (frontend deps)"
	@echo "  $(GREEN)✓$(NC) Go module cache"
	@echo ""
	@read -p "Type 'destroy-all' to confirm COMPLETE DESTRUCTION: " confirm; \
	if [ "$$confirm" = "destroy-all" ]; then \
		echo ""; \
		echo "$(YELLOW)Dropping database...$(NC)"; \
		sudo -u postgres psql -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '$(DB_NAME)';" > /dev/null 2>&1 || true; \
		sudo -u postgres psql -c "DROP DATABASE IF EXISTS $(DB_NAME);" > /dev/null 2>&1 && echo "$(GREEN)✓ Database destroyed$(NC)" || echo "$(YELLOW)Database did not exist$(NC)"; \
		echo ""; \
		echo "$(YELLOW)Cleaning files...$(NC)"; \
		rm -rf $(LOGS_DIR) 2>/dev/null && echo "$(GREEN)✓ Backend logs deleted$(NC)" || true; \
		rm -f $(PROJECT_ROOT)/logs/vite-dev.log 2>/dev/null && echo "$(GREEN)✓ Frontend logs deleted$(NC)" || true; \
		rm -rf $(PROJECT_ROOT)/logs 2>/dev/null || true; \
		rm -f $(BACKEND_PATH) 2>/dev/null && echo "$(GREEN)✓ Backend binary deleted$(NC)" || true; \
		echo ""; \
		echo "$(GREEN)╔══════════════════════════════════════════════════════════════════════════════╗$(NC)"; \
		echo "$(GREEN)║  ✅  DEVELOPMENT ENVIRONMENT DESTROYED                                        ║$(NC)"; \
		echo "$(GREEN)╚══════════════════════════════════════════════════════════════════════════════╝$(NC)"; \
		echo ""; \
		echo "To recreate fresh environment, run: $(CYAN)make start$(NC)"; \
	else \
		echo "$(YELLOW)Cancelled$(NC)"; \
	fi

# ============================================================================
# DIAGNOSTICS
# ============================================================================

check-ports: ## Show which ports are in use
	@echo "$(BLUE)🔍 Checking port availability...$(NC)"
	@echo ""
	@API_PID=$$(lsof -ti :$(API_PORT) 2>/dev/null || true); \
	if [ -n "$$API_PID" ]; then \
		API_CMD=$$(ps -p $$API_PID -o comm= 2>/dev/null || echo "unknown"); \
		echo "$(RED)❌ Port $(API_PORT) (API) is in use:$(NC)"; \
		echo "   PID: $$API_PID ($$API_CMD)"; \
	else \
		echo "$(GREEN)✓ Port $(API_PORT) (API) is available$(NC)"; \
	fi
	@echo ""
	@VITE_PID=$$(lsof -ti :$(VITE_PORT) 2>/dev/null || true); \
	if [ -n "$$VITE_PID" ]; then \
		VITE_CMD=$$(ps -p $$VITE_PID -o comm= 2>/dev/null || echo "unknown"); \
		echo "$(RED)❌ Port $(VITE_PORT) (Vite) is in use:$(NC)"; \
		echo "   PID: $$VITE_PID ($$VITE_CMD)"; \
	else \
		echo "$(GREEN)✓ Port $(VITE_PORT) (Vite) is available$(NC)"; \
	fi
	@echo ""

check-processes: ## Show running dev processes
	@echo "$(BLUE)🔍 Checking for running dev processes...$(NC)"
	@echo ""
	@echo "$(CYAN)Backend processes:$(NC)"
	@ps aux 2>/dev/null | grep -E "ehop-backend" | grep -v grep || echo "  None running"
	@echo ""
	@echo "$(CYAN)Frontend (Vite) processes:$(NC)"
	@ps aux 2>/dev/null | grep -E "vite|npm run dev" | grep -v grep || echo "  None running"
	@echo ""

# ============================================================================
# TESTING
# ============================================================================

test: _check-go ## Run backend tests
	@echo "$(BLUE)🧪 Running backend tests...$(NC)"
	@cd $(BACKEND_DIR) && go test -v ./...

test-coverage: _check-go ## Run tests with coverage report
	@echo "$(BLUE)🧪 Running tests with coverage...$(NC)"
	@cd $(BACKEND_DIR) && go test -coverprofile=coverage.out ./... && go tool cover -html=coverage.out -o coverage.html
	@echo "$(GREEN)✓ Coverage report: $(BACKEND_DIR)/coverage.html$(NC)"
