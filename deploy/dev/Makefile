# ==============================================================================
# Client Hub - Development Environment Makefile
# ==============================================================================
# Single entry point for all development operations.
# Located: deploy/dev/Makefile
# Usage: cd deploy/dev && make <target>
#        OR make -C deploy/dev <target>
#
# Key features:
# - Sector-first naming (backend-*, frontend-*, db-*)
# - Clear, organized command structure (no duplicates)
# - Intuitive naming (start, stop, logs, etc)
# - Language installation support (Go, Python, Node.js)
# - Automatic conflict detection
# - Comprehensive database management
# - Proper PID handling and process daemonization
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
RUNTIME_DIR := $(PROJECT_ROOT)/app/dev
LOGS_DIR := $(RUNTIME_DIR)/logs
CONFIG_FILE := $(SCRIPT_DIR)/dev.ini

# Binary and log file names (standardized with .bin and .log extensions)
BACKEND_BINARY := ehop-backend-dev.bin
BACKEND_PATH := $(RUNTIME_DIR)/bin/$(BACKEND_BINARY)
BACKEND_LOG_FILE := $(RUNTIME_DIR)/logs/backend.log
FRONTEND_LOG_FILE := $(RUNTIME_DIR)/logs/frontend.log

# PID files
PID_DIR := $(RUNTIME_DIR)/pids
BACKEND_PID_FILE := $(PID_DIR)/backend.pid
FRONTEND_PID_FILE := $(PID_DIR)/frontend.pid

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
        backend-build backend-build-fresh backend-start backend-stop backend-restart backend-logs backend-status \
        frontend-start frontend-stop frontend-restart frontend-logs frontend-status \
        db-init db-reset db-destroy db-update db-status db-connect db-stop db-start \
        start stop restart status health \
        logs logs-frontend logs-all \
        clean destroy-all check-ports check-processes \
        install-deps install-go install-python install-node \
        test test-coverage \
        _check-config _check-go _check-node _check-postgres _ensure-dirs _detect-conflicts _detect-backend-conflicts _detect-frontend-conflicts _show-started

# ============================================================================
# HELP
# ============================================================================

help: ## Show this help message
	@echo ""
	@echo "$(BLUE)╔══════════════════════════════════════════════════════════════════════════════╗$(NC)"
	@echo "$(BLUE)║$(NC)$(BOLD)              Client Hub - Development Environment                            $(BLUE)║$(NC)"
	@echo "$(BLUE)╚══════════════════════════════════════════════════════════════════════════════╝$(NC)"
	@echo ""
	@echo "$(YELLOW)━━━ BACKEND ━━━$(NC)"
	@grep -E '^backend-[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  $(GREEN)%-25s$(NC) %s\n", $$1, $$2}'
	@echo ""
	@echo "$(YELLOW)━━━ FRONTEND ━━━$(NC)"
	@grep -E '^frontend-[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  $(GREEN)%-25s$(NC) %s\n", $$1, $$2}'
	@echo ""
	@echo "$(YELLOW)━━━ DATABASE ━━━$(NC)"
	@grep -E '^db-[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  $(GREEN)%-25s$(NC) %s\n", $$1, $$2}'
	@echo ""
	@echo "$(YELLOW)━━━ QUICK START ━━━$(NC)"
	@grep -E '^(start|stop|restart|status|health|logs):[^a-zA-Z_-].*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  $(GREEN)%-25s$(NC) %s\n", $$1, $$2}'
	@echo ""
	@echo "$(YELLOW)━━━ ENVIRONMENT ━━━$(NC)"
	@grep -E '^(clean|destroy-all|check-ports|check-processes).*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  $(GREEN)%-25s$(NC) %s\n", $$1, $$2}'
	@echo ""
	@echo "$(YELLOW)━━━ LANGUAGE SETUP ━━━$(NC)"
	@echo "$(MAGENTA)⚠️  Note: Skip these if you use pyenv, nvm, asdf, or similar managers$(NC)"
	@grep -E '^install-(go|python|node):.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  $(GREEN)%-25s$(NC) %s\n", $$1, $$2}'
	@echo ""
	@echo "$(YELLOW)━━━ TESTING ━━━$(NC)"
	@grep -E '^(test|test-coverage):.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  $(GREEN)%-25s$(NC) %s\n", $$1, $$2}'
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
		echo "$(YELLOW)   Run 'make install-go'$(NC)"; \
		exit 1; \
	fi

_check-node:
	@if ! command -v node &> /dev/null; then \
		echo "$(RED)❌ Node.js is not installed$(NC)"; \
		echo "$(YELLOW)   Run 'make install-node'$(NC)"; \
		exit 1; \
	fi

_check-postgres:
	@echo "$(BLUE)🔍 Checking PostgreSQL...$(NC)"
	@if ! pg_isready -h localhost -p 5432 > /dev/null 2>&1; then \
		echo "$(YELLOW)⏳ PostgreSQL is not running. Starting with sudo...$(NC)"; \
		sudo systemctl start postgresql && echo "$(GREEN)✓ PostgreSQL started$(NC)" || { echo "$(RED)❌ Failed to start PostgreSQL$(NC)"; exit 1; }; \
		sleep 2; \
		RETRY=0; \
		while ! pg_isready -h localhost -p 5432 > /dev/null 2>&1 && [ $$RETRY -lt 30 ]; do \
			echo "$(YELLOW)⏳ Waiting for PostgreSQL to be ready... ($$RETRY/30)$(NC)"; \
			sleep 1; \
			RETRY=$$((RETRY + 1)); \
		done; \
		if ! pg_isready -h localhost -p 5432 > /dev/null 2>&1; then \
			echo "$(RED)❌ PostgreSQL failed to start on localhost:5432$(NC)"; \
			exit 1; \
		fi; \
		echo "$(GREEN)✓ PostgreSQL is ready$(NC)"; \
	else \
		echo "$(GREEN)✓ PostgreSQL is already running$(NC)"; \
	fi

_ensure-dirs:
	@mkdir -p "$(PID_DIR)" "$(LOGS_DIR)" "$(RUNTIME_DIR)/bin"

_ensure-db-schema:
	@echo "$(BLUE)🔍 Checking database schema...$(NC)"
	@if PGPASSWORD="$(DB_PASSWORD)" psql -h "$(DB_HOST)" -p "$(DB_PORT)" -U "$(DB_USER)" -d "$(DB_NAME)" -c "SELECT 1 FROM users LIMIT 1;" > /dev/null 2>&1; then \
		echo "$(GREEN)✓ Database schema is present$(NC)"; \
	else \
		echo "$(YELLOW)⏳ Database schema not found, initializing...$(NC)"; \
		$(MAKE) -s db-init; \
	fi

_detect-conflicts:
	@API_PID=$$(lsof -ti :$(API_PORT) 2>/dev/null || true); \
	VITE_PID=$$(lsof -ti :$(VITE_PORT) 2>/dev/null || true); \
	if [ -n "$$API_PID" ]; then \
		KNOWN_PID=""; \
		if [ -f "$(BACKEND_PID_FILE)" ]; then \
			KNOWN_PID=$$(cat "$(BACKEND_PID_FILE)" 2>/dev/null); \
		fi; \
		if [ "$$API_PID" != "$$KNOWN_PID" ]; then \
			echo "$(RED)❌ Port $(API_PORT) is already in use (PID: $$API_PID)$(NC)"; \
			echo "  Options:"; \
			echo "  1. Run '$(GREEN)make clean$(NC)' to free ports"; \
			echo "  2. Run '$(GREEN)kill $$API_PID$(NC)' to kill the process"; \
			echo "  3. Change API_PORT in dev.ini"; \
			echo ""; \
			exit 1; \
		fi; \
	fi; \
	if [ -n "$$VITE_PID" ]; then \
		KNOWN_PID=""; \
		if [ -f "$(FRONTEND_PID_FILE)" ]; then \
			KNOWN_PID=$$(cat "$(FRONTEND_PID_FILE)" 2>/dev/null); \
		fi; \
		if [ "$$VITE_PID" != "$$KNOWN_PID" ]; then \
			echo "$(RED)❌ Port $(VITE_PORT) is already in use (PID: $$VITE_PID)$(NC)"; \
			echo "  Options:"; \
			echo "  1. Run '$(GREEN)make clean$(NC)' to free ports"; \
			echo "  2. Run '$(GREEN)kill $$VITE_PID$(NC)' to kill the process"; \
			echo "  3. Change VITE_PORT in dev.ini"; \
			echo ""; \
			exit 1; \
		fi; \
	fi

_detect-backend-conflicts:
	@API_PID=$$(lsof -ti :$(API_PORT) 2>/dev/null || true); \
	if [ -n "$$API_PID" ]; then \
		KNOWN_PID=""; \
		if [ -f "$(BACKEND_PID_FILE)" ]; then \
			KNOWN_PID=$$(cat "$(BACKEND_PID_FILE)" 2>/dev/null); \
		fi; \
		if [ "$$API_PID" != "$$KNOWN_PID" ]; then \
			echo "$(RED)❌ Port $(API_PORT) is already in use (PID: $$API_PID)$(NC)"; \
			echo "  Options:"; \
			echo "  1. Run '$(GREEN)make clean$(NC)' to free ports"; \
			echo "  2. Run '$(GREEN)kill $$API_PID$(NC)' to kill the process"; \
			echo "  3. Change API_PORT in dev.ini"; \
			echo ""; \
			exit 1; \
		fi; \
	fi

_detect-frontend-conflicts:
	@VITE_PID=$$(lsof -ti :$(VITE_PORT) 2>/dev/null || true); \
	if [ -n "$$VITE_PID" ]; then \
		KNOWN_PID=""; \
		if [ -f "$(FRONTEND_PID_FILE)" ]; then \
			KNOWN_PID=$$(cat "$(FRONTEND_PID_FILE)" 2>/dev/null); \
		fi; \
		if [ "$$VITE_PID" != "$$KNOWN_PID" ]; then \
			echo "$(RED)❌ Port $(VITE_PORT) is already in use (PID: $$VITE_PID)$(NC)"; \
			echo "  Options:"; \
			echo "  1. Run '$(GREEN)make clean$(NC)' to free ports"; \
			echo "  2. Run '$(GREEN)kill $$VITE_PID$(NC)' to kill the process"; \
			echo "  3. Change VITE_PORT in dev.ini"; \
			echo ""; \
			exit 1; \
		fi; \
	fi

# ============================================================================
# LANGUAGE INSTALLATION
# ============================================================================

install-go: ## Install Go ($(GO_VERSION)) - skip if using system Go or version manager
	@echo "$(BLUE)📦 Installing Go $(GO_VERSION)...$(NC)"
	@if command -v go &> /dev/null; then \
		echo "$(YELLOW)⚠️  Go is already installed:$(NC)"; \
		go version; \
		echo "$(YELLOW)   Skipping installation$(NC)"; \
	else \
		curl -sL https://go.dev/dl/go$(GO_VERSION).linux-amd64.tar.gz | sudo tar -xz -C /usr/local; \
		echo "$(GREEN)✓ Go installed successfully$(NC)"; \
		echo "$(YELLOW)   Add to PATH: export PATH=\$$PATH:/usr/local/go/bin$(NC)"; \
	fi

install-node: ## Install Node.js ($(NODE_VERSION)) - skip if using nvm/fnm/asdf
	@echo "$(BLUE)📦 Installing Node.js $(NODE_VERSION)...$(NC)"
	@if command -v node &> /dev/null; then \
		echo "$(YELLOW)⚠️  Node.js is already installed:$(NC)"; \
		node --version; \
		echo "$(YELLOW)   Skipping installation$(NC)"; \
	else \
		curl -fsSL https://deb.nodesource.com/setup_$(NODE_VERSION).x | sudo -E bash - && sudo apt-get install -y nodejs; \
		echo "$(GREEN)✓ Node.js installed successfully$(NC)"; \
	fi

install-python: ## Install Python ($(PYTHON_VERSION)) - skip if using pyenv/conda/venv
	@echo "$(BLUE)📦 Installing Python $(PYTHON_VERSION)...$(NC)"
	@if command -v python$(PYTHON_VERSION) &> /dev/null; then \
		echo "$(YELLOW)⚠️  Python $(PYTHON_VERSION) is already installed$(NC)"; \
	else \
		sudo apt-get update && sudo apt-get install -y python$(PYTHON_VERSION) python$(PYTHON_VERSION)-venv python$(PYTHON_VERSION)-dev; \
		echo "$(GREEN)✓ Python $(PYTHON_VERSION) installed successfully$(NC)"; \
	fi

install-deps: _check-go _check-node ## Install all project dependencies (Go + npm)
	@echo "$(BLUE)📦 Installing dependencies...$(NC)"
	@echo ""
	@echo "$(CYAN)Backend (Go modules)...$(NC)"
	@cd "$(BACKEND_DIR)" && go mod download && go mod tidy
	@echo "$(CYAN)Frontend (npm)...$(NC)"
	@cd "$(FRONTEND_DIR)" && npm install
	@echo "$(GREEN)✅ All dependencies installed$(NC)"

# ============================================================================
# BACKEND TARGETS
# ============================================================================

backend-build: _check-go ## Build backend binary (from latest code)
	@echo "$(BLUE)🔧 Building backend...$(NC)"
	@cd "$(BACKEND_DIR)" && \
		rm -f "$(BACKEND_PATH)" && \
		go build -o "$(BACKEND_PATH)" ./main.go
	@echo "$(GREEN)✓ Backend built successfully$(NC)"
	@ls -lh "$(BACKEND_PATH)" | awk '{print "  Size: " $$5 ", Modified: " $$6 " " $$7 " " $$8}'

backend-build-fresh: _check-go ## Clean build (clears Go cache, rebuilds everything)
	@echo "$(BLUE)🔧 Clean build backend...$(NC)"
	@cd "$(BACKEND_DIR)" && \
		rm -f "$(BACKEND_PATH)" && \
		go clean -cache && \
		go build -o "$(BACKEND_PATH)" ./main.go
	@echo "$(GREEN)✓ Backend built (cache cleared)$(NC)"

backend-start: _check-config _ensure-dirs ## Start backend server
	@echo "$(CYAN)Starting backend...$(NC)"
	@if [ -f "$(BACKEND_PID_FILE)" ]; then \
		OLD_PID=$$(cat "$(BACKEND_PID_FILE)"); \
		if kill -0 $$OLD_PID 2>/dev/null; then \
			echo "$(YELLOW)⚠️  Backend is already running (PID: $$OLD_PID)$(NC)"; \
			echo "   Use 'make backend-restart' to restart"; \
			exit 0; \
		else \
			rm -f "$(BACKEND_PID_FILE)"; \
		fi; \
	fi
	@if [ ! -f "$(BACKEND_PATH)" ]; then \
		echo "$(YELLOW)Binary not found, building...$(NC)"; \
		cd "$(BACKEND_DIR)" && go build -o "$(BACKEND_PATH)" ./main.go; \
	fi
	@$(MAKE) -s _detect-backend-conflicts
	@cd "$(BACKEND_DIR)" && \
		DB_HOST="$(DB_HOST)" \
		DB_PORT="$(DB_PORT)" \
		DB_USER="$(DB_USER)" \
		DB_PASSWORD="$(DB_PASSWORD)" \
		DB_NAME="$(DB_NAME)" \
		JWT_SECRET="$(JWT_SECRET)" \
		API_PORT="$(API_PORT)" \
		LOG_FILE="$(BACKEND_LOG_FILE)" \
		APP_ENV="development" \
		nohup "$(BACKEND_PATH)" >> "$(BACKEND_LOG_FILE)" 2>&1 &
	@sleep 2
	@PID=$$(pidof $(BACKEND_BINARY) 2>/dev/null | awk '{print $$1}'); \
	if [ -n "$$PID" ]; then \
		echo "$$PID" > "$(BACKEND_PID_FILE)"; \
		echo "$(GREEN)✓ Backend started (PID: $$PID)$(NC)"; \
		echo "$(CYAN)  URL: http://localhost:$(API_PORT)$(NC)"; \
		echo "$(CYAN)  Logs: make backend-logs$(NC)"; \
	else \
		echo "$(RED)❌ Backend failed to start$(NC)"; \
		echo "$(YELLOW)   Check logs: tail -50 $(BACKEND_LOG_FILE)$(NC)"; \
		rm -f "$(BACKEND_PID_FILE)"; \
		exit 1; \
	fi

backend-stop: ## Stop backend server
	@echo "$(BLUE)⏹️  Stopping backend...$(NC)"
	@# First try to get PID from pidof (most reliable)
	@REAL_PID=$$(pidof $(BACKEND_BINARY) 2>/dev/null | awk '{print $$1}'); \
	if [ -n "$$REAL_PID" ]; then \
		kill $$REAL_PID 2>/dev/null; \
		sleep 1; \
		if kill -0 $$REAL_PID 2>/dev/null; then \
			kill -9 $$REAL_PID 2>/dev/null || true; \
		fi; \
		echo "$(GREEN)✓ Backend stopped (PID: $$REAL_PID)$(NC)"; \
		rm -f "$(BACKEND_PID_FILE)"; \
	elif [ -f "$(BACKEND_PID_FILE)" ]; then \
		PID=$$(cat "$(BACKEND_PID_FILE)"); \
		if kill -0 $$PID 2>/dev/null; then \
			kill $$PID 2>/dev/null; \
			sleep 1; \
			kill -9 $$PID 2>/dev/null || true; \
			echo "$(GREEN)✓ Backend stopped (PID: $$PID)$(NC)"; \
		else \
			echo "$(YELLOW)⚠️  Process $$PID not found (stale PID file)$(NC)"; \
		fi; \
		rm -f "$(BACKEND_PID_FILE)"; \
	else \
		echo "$(YELLOW)⚠️  Backend not running$(NC)"; \
	fi

backend-restart: _check-config _ensure-dirs ## Rebuild and restart backend (or start if stopped)
	@echo "$(BLUE)🔄 Restarting backend...$(NC)"
	@# Stop existing process using pidof (most reliable)
	@REAL_PID=$$(pidof $(BACKEND_BINARY) 2>/dev/null | awk '{print $$1}'); \
	if [ -n "$$REAL_PID" ]; then \
		echo "$(CYAN)Stopping backend (PID: $$REAL_PID)...$(NC)"; \
		kill $$REAL_PID 2>/dev/null || true; \
		sleep 1; \
		kill -9 $$REAL_PID 2>/dev/null || true; \
	fi; \
	rm -f "$(BACKEND_PID_FILE)"
	@# Build
	@echo "$(CYAN)Building backend...$(NC)"
	@cd "$(BACKEND_DIR)" && \
		rm -f "$(BACKEND_PATH)" && \
		go build -o "$(BACKEND_PATH)" ./main.go
	@echo "$(GREEN)✓ Backend built$(NC)"
	@# Start
	@$(MAKE) -s _detect-backend-conflicts
	@echo "$(CYAN)Starting backend...$(NC)"
	@cd "$(BACKEND_DIR)" && \
		DB_HOST="$(DB_HOST)" \
		DB_PORT="$(DB_PORT)" \
		DB_USER="$(DB_USER)" \
		DB_PASSWORD="$(DB_PASSWORD)" \
		DB_NAME="$(DB_NAME)" \
		JWT_SECRET="$(JWT_SECRET)" \
		API_PORT="$(API_PORT)" \
		LOG_FILE="$(BACKEND_LOG_FILE)" \
		APP_ENV="development" \
		nohup "$(BACKEND_PATH)" >> "$(BACKEND_LOG_FILE)" 2>&1 &
	@sleep 2
	@PID=$$(pidof $(BACKEND_BINARY) 2>/dev/null | awk '{print $$1}'); \
	if [ -n "$$PID" ]; then \
		echo "$$PID" > "$(BACKEND_PID_FILE)"; \
		echo "$(GREEN)✅ Backend restarted (PID: $$PID)$(NC)"; \
		echo "$(CYAN)  URL: http://localhost:$(API_PORT)$(NC)"; \
		echo "$(CYAN)  Logs: make backend-logs$(NC)"; \
	else \
		echo "$(RED)❌ Backend failed to start$(NC)"; \
		echo "$(YELLOW)   Check logs: tail -50 $(BACKEND_LOG_FILE)$(NC)"; \
		rm -f "$(BACKEND_PID_FILE)"; \
		exit 1; \
	fi

backend-logs: ## View live backend logs (Ctrl+C to exit)
	@if [ -f "$(BACKEND_LOG_FILE)" ]; then \
		echo "$(BLUE)📋 Backend logs ($(BACKEND_LOG_FILE))$(NC)"; \
		echo "$(YELLOW)   Press Ctrl+C to exit$(NC)"; \
		echo ""; \
		tail -f "$(BACKEND_LOG_FILE)"; \
	else \
		echo "$(YELLOW)⚠️  No logs yet. Start backend with 'make backend-start'$(NC)"; \
	fi

backend-status: ## Show backend server status
	@if [ -f "$(BACKEND_PID_FILE)" ]; then \
		PID=$$(cat "$(BACKEND_PID_FILE)"); \
		if kill -0 $$PID 2>/dev/null; then \
			UPTIME=$$(ps -p $$PID -o etime= 2>/dev/null | tr -d ' '); \
			echo "$(GREEN)✓ Backend is running$(NC)"; \
			echo "  PID: $$PID"; \
			echo "  Uptime: $$UPTIME"; \
			echo "  URL: http://localhost:$(API_PORT)"; \
		else \
			echo "$(RED)✗ Backend is stopped (stale PID file)$(NC)"; \
			rm -f "$(BACKEND_PID_FILE)"; \
		fi; \
	else \
		echo "$(RED)✗ Backend is stopped$(NC)"; \
	fi

# ============================================================================
# FRONTEND TARGETS
# ============================================================================

frontend-start: _check-node _ensure-dirs ## Start frontend dev server (Vite)
	@echo "$(CYAN)Starting Vite dev server...$(NC)"
	@if [ -f "$(FRONTEND_PID_FILE)" ]; then \
		OLD_PID=$$(cat "$(FRONTEND_PID_FILE)"); \
		if kill -0 $$OLD_PID 2>/dev/null; then \
			echo "$(YELLOW)⚠️  Frontend is already running (PID: $$OLD_PID)$(NC)"; \
			echo "   Use 'make frontend-restart' to restart"; \
			exit 0; \
		else \
			rm -f "$(FRONTEND_PID_FILE)"; \
		fi; \
	fi
	@cd "$(FRONTEND_DIR)" && \
		if [ ! -d "node_modules" ]; then \
			echo "$(YELLOW)   Installing npm dependencies...$(NC)"; \
			npm install --silent || { echo "$(RED)npm install failed$(NC)"; exit 1; }; \
		fi
	@$(MAKE) -s _detect-frontend-conflicts
	@cd "$(FRONTEND_DIR)" && \
		VITE_PORT="$(VITE_PORT)" \
		nohup npm run dev >> "$(FRONTEND_LOG_FILE)" 2>&1 &
	@sleep 3
	@PID=$$(lsof -ti :$(VITE_PORT) 2>/dev/null | head -1); \
	if [ -n "$$PID" ]; then \
		echo "$$PID" > "$(FRONTEND_PID_FILE)"; \
		echo "$(GREEN)✓ Frontend started (PID: $$PID)$(NC)"; \
		echo "$(CYAN)  URL: http://localhost:$(VITE_PORT)$(NC)"; \
		echo "$(CYAN)  Logs: make frontend-logs$(NC)"; \
	else \
		echo "$(RED)❌ Frontend failed to start$(NC)"; \
		echo "$(YELLOW)   Check logs: tail -50 $(FRONTEND_LOG_FILE)$(NC)"; \
		rm -f "$(FRONTEND_PID_FILE)"; \
		exit 1; \
	fi

frontend-stop: ## Stop frontend dev server
	@echo "$(BLUE)⏹️  Stopping frontend...$(NC)"
	@if [ -f "$(FRONTEND_PID_FILE)" ]; then \
		PID=$$(cat "$(FRONTEND_PID_FILE)"); \
		if kill -0 $$PID 2>/dev/null; then \
			kill $$PID 2>/dev/null; \
			sleep 1; \
			if kill -0 $$PID 2>/dev/null; then \
				kill -9 $$PID 2>/dev/null || true; \
			fi; \
			echo "$(GREEN)✓ Frontend stopped (PID: $$PID)$(NC)"; \
		else \
			echo "$(YELLOW)⚠️  Process $$PID not found (stale PID file)$(NC)"; \
		fi; \
		rm -f "$(FRONTEND_PID_FILE)"; \
	else \
		echo "$(YELLOW)⚠️  Frontend not running$(NC)"; \
	fi
	@# Also kill any orphan vite/node processes on the port
	@VITE_PIDS=$$(lsof -ti :$(VITE_PORT) 2>/dev/null || true); \
	if [ -n "$$VITE_PIDS" ]; then \
		echo "$(YELLOW)Killing processes on port $(VITE_PORT)...$(NC)"; \
		kill $$VITE_PIDS 2>/dev/null || true; \
		sleep 1; \
		kill -9 $$VITE_PIDS 2>/dev/null || true; \
	fi

frontend-restart: _check-node _ensure-dirs ## Rebuild and restart frontend (or start if stopped)
	@echo "$(BLUE)🔄 Restarting frontend...$(NC)"
	@# Stop existing process
	@if [ -f "$(FRONTEND_PID_FILE)" ]; then \
		PID=$$(cat "$(FRONTEND_PID_FILE)"); \
		if kill -0 $$PID 2>/dev/null; then \
			echo "$(CYAN)Stopping frontend (PID: $$PID)...$(NC)"; \
			kill $$PID 2>/dev/null || true; \
			sleep 1; \
			kill -9 $$PID 2>/dev/null || true; \
		fi; \
		rm -f "$(FRONTEND_PID_FILE)"; \
	fi
	@# Kill any orphan processes on the port
	@VITE_PIDS=$$(lsof -ti :$(VITE_PORT) 2>/dev/null || true); \
	if [ -n "$$VITE_PIDS" ]; then \
		kill $$VITE_PIDS 2>/dev/null || true; \
		sleep 1; \
	fi
	@# Ensure deps are installed
	@cd "$(FRONTEND_DIR)" && \
		if [ ! -d "node_modules" ]; then \
			echo "$(YELLOW)   Installing npm dependencies...$(NC)"; \
			npm install --silent || { echo "$(RED)npm install failed$(NC)"; exit 1; }; \
		fi
	@# Start
	@$(MAKE) -s _detect-frontend-conflicts
	@echo "$(CYAN)Starting frontend...$(NC)"
	@cd "$(FRONTEND_DIR)" && \
		VITE_PORT="$(VITE_PORT)" \
		nohup npm run dev >> "$(FRONTEND_LOG_FILE)" 2>&1 &
	@sleep 3
	@PID=$$(lsof -ti :$(VITE_PORT) 2>/dev/null | head -1); \
	if [ -n "$$PID" ]; then \
		echo "$$PID" > "$(FRONTEND_PID_FILE)"; \
		echo "$(GREEN)✅ Frontend restarted (PID: $$PID)$(NC)"; \
		echo "$(CYAN)  URL: http://localhost:$(VITE_PORT)$(NC)"; \
		echo "$(CYAN)  Logs: make frontend-logs$(NC)"; \
	else \
		echo "$(RED)❌ Frontend failed to start$(NC)"; \
		echo "$(YELLOW)   Check logs: tail -50 $(FRONTEND_LOG_FILE)$(NC)"; \
		rm -f "$(FRONTEND_PID_FILE)"; \
		exit 1; \
	fi

frontend-logs: ## View live frontend logs (Ctrl+C to exit)
	@if [ -f "$(FRONTEND_LOG_FILE)" ]; then \
		echo "$(BLUE)📋 Frontend logs ($(FRONTEND_LOG_FILE))$(NC)"; \
		echo "$(YELLOW)   Press Ctrl+C to exit$(NC)"; \
		echo ""; \
		tail -f "$(FRONTEND_LOG_FILE)"; \
	else \
		echo "$(YELLOW)⚠️  No logs yet. Start frontend with 'make frontend-start'$(NC)"; \
	fi

frontend-status: ## Show frontend server status
	@if [ -f "$(FRONTEND_PID_FILE)" ]; then \
		PID=$$(cat "$(FRONTEND_PID_FILE)"); \
		if kill -0 $$PID 2>/dev/null; then \
			UPTIME=$$(ps -p $$PID -o etime= 2>/dev/null | tr -d ' '); \
			echo "$(GREEN)✓ Frontend is running$(NC)"; \
			echo "  PID: $$PID"; \
			echo "  Uptime: $$UPTIME"; \
			echo "  URL: http://localhost:$(VITE_PORT)"; \
		else \
			echo "$(RED)✗ Frontend is stopped (stale PID file)$(NC)"; \
			rm -f "$(FRONTEND_PID_FILE)"; \
		fi; \
	else \
		echo "$(RED)✗ Frontend is stopped$(NC)"; \
	fi

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
	@PGPASSWORD="$(DB_PASSWORD)" psql -h "$(DB_HOST)" -p "$(DB_PORT)" -U "$(DB_USER)" -d "$(DB_NAME)" -c "\dt" 2>/dev/null | sed 's/^/  /' || echo "  $(RED)Could not connect$(NC)"
	@echo ""
	@echo "$(CYAN)Users in database:$(NC)"
	@PGPASSWORD="$(DB_PASSWORD)" psql -h "$(DB_HOST)" -p "$(DB_PORT)" -U "$(DB_USER)" -d "$(DB_NAME)" -c "SELECT username, role, failed_attempts, lock_level, locked_until FROM users WHERE deleted_at IS NULL;" 2>/dev/null | sed 's/^/  /' || echo "  $(RED)Could not query$(NC)"

db-connect: _check-postgres ## Open interactive PostgreSQL shell
	@echo "$(BLUE)🗄️  Connecting to $(DB_NAME)...$(NC)"
	@PGPASSWORD="$(DB_PASSWORD)" psql -h "$(DB_HOST)" -p "$(DB_PORT)" -U "$(DB_USER)" -d "$(DB_NAME)"

db-stop: ## Stop PostgreSQL service
	@echo "$(BLUE)⏹️  Stopping PostgreSQL...$(NC)"
	@sudo systemctl stop postgresql && echo "$(GREEN)✓ PostgreSQL stopped$(NC)" || echo "$(RED)❌ Failed to stop PostgreSQL$(NC)"

db-start: ## Start PostgreSQL service and ensure database is initialized
	@echo "$(BLUE)▶️  Starting PostgreSQL and ensuring database setup...$(NC)"
	@$(MAKE) -s _check-postgres
	@$(MAKE) -s _ensure-db-schema
	@echo "$(GREEN)✅ PostgreSQL started and database ready$(NC)"

db-init: _check-postgres ## Initialize database from scratch
	@echo ""
	@echo "$(BLUE)🗄️  Initializing database $(DB_NAME)...$(NC)"
	@echo ""
	@echo "$(YELLOW)Creating user...$(NC)"
	@sudo -u postgres psql -c "CREATE USER $(DB_USER) WITH PASSWORD '$(DB_PASSWORD)' SUPERUSER;" 2>/dev/null && \
		echo "$(GREEN)✅ User created$(NC)" || \
		echo "$(YELLOW)User may already exist$(NC)"
	@echo ""
	@echo "$(YELLOW)Creating database...$(NC)"
	@sudo -u postgres psql -c "CREATE DATABASE $(DB_NAME) OWNER $(DB_USER);" 2>/dev/null && \
		echo "$(GREEN)✅ Database created$(NC)" || \
		echo "$(YELLOW)Database already exists$(NC)"
	@echo ""
	@echo "$(YELLOW)Applying schema...$(NC)"
	@cd "$(BACKEND_DIR)/database" && \
		PGPASSWORD="$(DB_PASSWORD)" psql -h "$(DB_HOST)" -p "$(DB_PORT)" -U "$(DB_USER)" -d "$(DB_NAME)" -f init.sql > /dev/null 2>&1 && \
		echo "$(GREEN)✅ Schema applied successfully$(NC)" || \
		echo "$(YELLOW)⚠️  Schema may already exist or failed to apply$(NC)"
	@echo ""
	@echo "$(GREEN)✅ Database initialized$(NC)"
	@echo "   Next: $(CYAN)make backend-start$(NC)"

db-reset: _check-postgres ## Reset database (clear all data, reinitialize schema)
	@echo ""
	@echo "$(RED)╔══════════════════════════════════════════════════════════════════════════════╗$(NC)"
	@echo "$(RED)║  ⚠️   WARNING: This will DELETE ALL DATA in $(DB_NAME)                       ║$(NC)"
	@echo "$(RED)╚══════════════════════════════════════════════════════════════════════════════╝$(NC)"
	@echo ""
	@read -p "Type 'reset' to confirm: " confirm; \
	if [ "$$confirm" = "reset" ]; then \
		echo ""; \
		echo "$(YELLOW)Terminating connections...$(NC)"; \
		sudo -u postgres psql -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '$(DB_NAME)';" > /dev/null 2>&1 || true; \
		echo "$(YELLOW)Creating user...$(NC)"; \
		sudo -u postgres psql -c "CREATE USER $(DB_USER) WITH PASSWORD '$(DB_PASSWORD)' SUPERUSER;" 2>/dev/null && \
			echo "$(GREEN)✅ User created$(NC)" || \
			echo "$(YELLOW)User may already exist$(NC)"; \
		echo "$(YELLOW)Dropping database...$(NC)"; \
		sudo -u postgres psql -c "DROP DATABASE IF EXISTS $(DB_NAME);" > /dev/null 2>&1; \
		echo "$(YELLOW)Recreating database...$(NC)"; \
		sudo -u postgres psql -c "CREATE DATABASE $(DB_NAME) OWNER $(DB_USER);" > /dev/null 2>&1; \
		echo "$(GREEN)✓ Database recreated$(NC)"; \
		echo ""; \
		echo "$(YELLOW)Applying schema from init.sql...$(NC)"; \
		cd "$(BACKEND_DIR)/database" && \
		PGPASSWORD="$(DB_PASSWORD)" psql -h "$(DB_HOST)" -p "$(DB_PORT)" -U "$(DB_USER)" -d "$(DB_NAME)" -f init.sql > /dev/null 2>&1 && \
			echo "$(GREEN)✅ Schema applied successfully$(NC)" || \
			echo "$(RED)❌ Failed to apply schema$(NC)"; \
		echo ""; \
		echo "$(GREEN)✅ Database reset complete$(NC)"; \
		echo "   Next: $(CYAN)make backend-start$(NC)"; \
	else \
		echo "$(YELLOW)Cancelled$(NC)"; \
	fi

db-destroy: _check-postgres ## Destroy database completely
	@echo ""
	@echo "$(RED)╔══════════════════════════════════════════════════════════════════════════════╗$(NC)"
	@echo "$(RED)║  🔥 DANGER: This will PERMANENTLY DELETE database $(DB_NAME)                ║$(NC)"
	@echo "$(RED)╚══════════════════════════════════════════════════════════════════════════════╝$(NC)"
	@echo ""
	@read -p "Type 'destroy' to confirm PERMANENT DELETION: " confirm; \
	if [ "$$confirm" = "destroy" ]; then \
		echo ""; \
		echo "$(YELLOW)Terminating connections...$(NC)"; \
		sudo -u postgres psql -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '$(DB_NAME)';" > /dev/null 2>&1 || true; \
		echo "$(YELLOW)Dropping database...$(NC)"; \
		sudo -u postgres psql -c "DROP DATABASE IF EXISTS $(DB_NAME);" > /dev/null 2>&1 && \
			echo "$(GREEN)✅ Database destroyed$(NC)" || \
			echo "$(YELLOW)Database did not exist$(NC)"; \
		echo "$(YELLOW)Dropping user...$(NC)"; \
		sudo -u postgres psql -c "DROP ROLE IF EXISTS $(DB_USER);" > /dev/null 2>&1 && \
			echo "$(GREEN)✅ User destroyed$(NC)" || \
			echo "$(YELLOW)User did not exist$(NC)"; \
		echo ""; \
		echo "To recreate: $(CYAN)make db-init$(NC)"; \
	else \
		echo "$(YELLOW)Cancelled$(NC)"; \
	fi

db-update: _check-postgres ## Apply pending migrations (reinitialize schema)
	@echo ""
	@echo "$(BLUE)🔄 Applying migrations to $(DB_NAME)...$(NC)"
	@echo ""
	@echo "$(YELLOW)Running database initialization script...$(NC)"
	@cd "$(BACKEND_DIR)/database" && \
		PGPASSWORD="$(DB_PASSWORD)" psql -h "$(DB_HOST)" -p "$(DB_PORT)" -U "$(DB_USER)" -d "$(DB_NAME)" -f init.sql && \
		echo "$(GREEN)✅ Schema reinitialized from init.sql$(NC)" || \
		echo "$(YELLOW)⚠️  Failed to apply schema. Check database connection.$(NC)"
	@echo ""

db-clean: _check-postgres ## Clean all data from database (keep schema and root user)
	@echo "$(BLUE)🧹 Cleaning database data...$(NC)"
	@PGPASSWORD="$(DB_PASSWORD)" psql -h "$(DB_HOST)" -p "$(DB_PORT)" -U "$(DB_USER)" -d "$(DB_NAME)" -c "BEGIN; DELETE FROM audit_logs; DELETE FROM financial_installments; DELETE FROM contract_financial; DELETE FROM contracts; DELETE FROM affiliates; DELETE FROM clients; DELETE FROM subcategories; DELETE FROM categories; DELETE FROM user_theme_settings; DELETE FROM login_attempts; DELETE FROM password_history; DELETE FROM users WHERE username != 'root'; COMMIT;" > /dev/null 2>&1 && \
		echo "$(GREEN)✅ Database cleaned successfully$(NC)" || \
		echo "$(RED)❌ Failed to clean database$(NC)"

# ============================================================================
# QUICK START TARGETS (Aliases & Combined)
# ============================================================================

start: _check-config _ensure-dirs _check-postgres _ensure-db-schema  ## Start dev environment (backend + frontend)
	@echo ""
	@echo "$(BLUE)╔══════════════════════════════════════════════════════════════════════════════╗$(NC)"
	@echo "$(BLUE)║$(NC)$(BOLD)              Starting Development Environment                                $(BLUE)║$(NC)"
	@echo "$(BLUE)╚══════════════════════════════════════════════════════════════════════════════╝$(NC)"
	@echo ""
	@# Build backend first
	@if [ ! -f "$(BACKEND_PATH)" ]; then \
		echo "$(YELLOW)Building backend...$(NC)"; \
		cd "$(BACKEND_DIR)" && go build -o "$(BACKEND_PATH)" ./main.go; \
		echo "$(GREEN)✓ Backend built$(NC)"; \
		echo ""; \
	fi
	@echo "$(YELLOW)Starting services...$(NC)"
	@echo ""
	@$(MAKE) -s backend-start
	@echo ""
	@echo "$(YELLOW)Initializing root user...$(NC)"
	@sleep 2
	@curl -s -X POST http://localhost:$(API_PORT)/api/initialize/admin \
		-H "Content-Type: application/json" \
		-d '{"username":"root","display_name":"System Administrator","password":"$(DB_PASSWORD)"}' > /dev/null 2>&1 && \
		echo "$(GREEN)✅ Root user initialized$(NC)" || \
		echo "$(YELLOW)⚠️  Root user may already exist$(NC)"
	@echo ""
	@$(MAKE) -s frontend-start
	@echo ""
	@$(MAKE) -s _show-started

stop: ## Stop all services (backend + frontend)
	@echo ""
	@echo "$(BLUE)╔══════════════════════════════════════════════════════════════════════════════╗$(NC)"
	@echo "$(BLUE)║$(NC)$(BOLD)              Stopping All Services                                            $(BLUE)║$(NC)"
	@echo "$(BLUE)╚══════════════════════════════════════════════════════════════════════════════╝$(NC)"
	@echo ""
	@$(MAKE) -s backend-stop
	@$(MAKE) -s frontend-stop
	@echo ""
	@echo "$(GREEN)✅ All services stopped$(NC)"

restart: ## Rebuild and restart all services (stop → build → start)
	@echo ""
	@echo "$(BLUE)╔══════════════════════════════════════════════════════════════════════════════╗$(NC)"
	@echo "$(BLUE)║$(NC)$(BOLD)              Restarting All Services                                         $(BLUE)║$(NC)"
	@echo "$(BLUE)╚══════════════════════════════════════════════════════════════════════════════╝$(NC)"
	@echo ""
	@$(MAKE) -s backend-restart
	@echo ""
	@$(MAKE) -s frontend-restart
	@echo ""
	@$(MAKE) -s _show-started

_show-started:
	@echo ""
	@echo "$(BLUE)╔══════════════════════════════════════════════════════════════════════════════╗$(NC)"
	@echo "$(BLUE)║$(NC)$(BOLD)              Development Environment Started                                $(BLUE)║$(NC)"
	@echo "$(BLUE)╚══════════════════════════════════════════════════════════════════════════════╝$(NC)"
	@echo ""
	@echo "$(CYAN)Backend:$(NC)"
	@echo "  $(GREEN)✓$(NC) http://localhost:$(API_PORT)"
	@echo "  $(GREEN)✓$(NC) Logs: make backend-logs"
	@echo ""
	@echo "$(CYAN)Frontend:$(NC)"
	@echo "  $(GREEN)✓$(NC) http://localhost:$(VITE_PORT)"
	@echo "  $(GREEN)✓$(NC) Logs: make frontend-logs"
	@echo ""
	@echo "$(CYAN)Database:$(NC)"
	@echo "  $(GREEN)✓$(NC) $(DB_NAME)@$(DB_HOST):$(DB_PORT)"
	@echo "  $(GREEN)✓$(NC) Status: make db-status"
	@echo ""

status: ## Show status of all services
	@echo ""
	@echo "$(BLUE)╔══════════════════════════════════════════════════════════════════════════════╗$(NC)"
	@echo "$(BLUE)║              Development Environment Status                                  $(BLUE)║$(NC)"
	@echo "$(BLUE)╚══════════════════════════════════════════════════════════════════════════════╝$(NC)"
	@echo ""
	@echo "$(CYAN)Backend:$(NC)"
	@if [ -f "$(BACKEND_PID_FILE)" ]; then \
		PID=$$(cat "$(BACKEND_PID_FILE)"); \
		if kill -0 $$PID 2>/dev/null; then \
			UPTIME=$$(ps -p $$PID -o etime= 2>/dev/null | tr -d ' '); \
			echo "  $(GREEN)●$(NC) Running (PID: $$PID, uptime: $$UPTIME)"; \
		else \
			echo "  $(RED)○$(NC) Stopped (stale PID file)"; \
		fi; \
	else \
		echo "  $(RED)○$(NC) Stopped"; \
	fi
	@echo "  URL: $(CYAN)http://localhost:$(API_PORT)$(NC)"
	@echo ""
	@echo "$(CYAN)Frontend (Vite):$(NC)"
	@if [ -f "$(FRONTEND_PID_FILE)" ]; then \
		PID=$$(cat "$(FRONTEND_PID_FILE)"); \
		if kill -0 $$PID 2>/dev/null; then \
			UPTIME=$$(ps -p $$PID -o etime= 2>/dev/null | tr -d ' '); \
			echo "  $(GREEN)●$(NC) Running (PID: $$PID, uptime: $$UPTIME)"; \
		else \
			echo "  $(RED)○$(NC) Stopped (stale PID file)"; \
		fi; \
	else \
		echo "  $(RED)○$(NC) Stopped"; \
	fi
	@echo "  URL: $(CYAN)http://localhost:$(VITE_PORT)$(NC)"
	@echo ""
	@echo "$(CYAN)PostgreSQL:$(NC)"
	@if pg_isready -h localhost -p 5432 > /dev/null 2>&1; then \
		echo "  $(GREEN)●$(NC) Running ($(DB_HOST):$(DB_PORT))"; \
	else \
		echo "  $(RED)○$(NC) Not running"; \
	fi
	@echo "  Database: $(CYAN)$(DB_NAME)$(NC)"
	@echo ""

health: ## Check health of all services
	@echo "$(BLUE)🏥 Checking service health...$(NC)"
	@echo ""
	@echo "$(CYAN)Backend:$(NC)"
	@if curl -s --connect-timeout 3 http://localhost:$(API_PORT)/health > /dev/null 2>&1; then \
		echo "  $(GREEN)✓ Responding$(NC)"; \
	else \
		echo "  $(RED)✗ Not responding$(NC)"; \
	fi
	@echo ""
	@echo "$(CYAN)Frontend:$(NC)"
	@if curl -s --connect-timeout 3 http://localhost:$(VITE_PORT) > /dev/null 2>&1; then \
		echo "  $(GREEN)✓ Responding$(NC)"; \
	else \
		echo "  $(RED)✗ Not responding$(NC)"; \
	fi
	@echo ""
	@echo "$(CYAN)Database:$(NC)"
	@if PGPASSWORD="$(DB_PASSWORD)" psql -h "$(DB_HOST)" -p "$(DB_PORT)" -U "$(DB_USER)" -d "$(DB_NAME)" -c "SELECT 1;" > /dev/null 2>&1; then \
		echo "  $(GREEN)✓ Connected$(NC)"; \
	else \
		echo "  $(RED)✗ Not connected$(NC)"; \
	fi
	@echo ""

logs: ## View live backend logs (Ctrl+C to exit)
	@$(MAKE) -s backend-logs

logs-frontend: ## View live frontend logs (Ctrl+C to exit)
	@$(MAKE) -s frontend-logs

logs-all: ## View all logs (backend + frontend, Ctrl+C to exit)
	@echo "$(BLUE)📋 Tailing both logs (Ctrl+C to exit)...$(NC)"
	@echo ""
	@tail -f "$(BACKEND_LOG_FILE)" "$(FRONTEND_LOG_FILE)" 2>/dev/null || echo "$(YELLOW)No logs available yet$(NC)"

# ============================================================================
# ENVIRONMENT CLEANUP
# ============================================================================

clean: ## Kill all dev processes and clean up (keeps code & config)
	@echo "$(BLUE)🧹 Cleaning development environment...$(NC)"
	@echo ""
	@echo "$(CYAN)Stopping processes...$(NC)"
	@# Stop backend
	@if [ -f "$(BACKEND_PID_FILE)" ]; then \
		PID=$$(cat "$(BACKEND_PID_FILE)"); \
		kill $$PID 2>/dev/null || true; \
		kill -9 $$PID 2>/dev/null || true; \
		rm -f "$(BACKEND_PID_FILE)"; \
	fi
	@# Stop frontend
	@if [ -f "$(FRONTEND_PID_FILE)" ]; then \
		PID=$$(cat "$(FRONTEND_PID_FILE)"); \
		kill $$PID 2>/dev/null || true; \
		kill -9 $$PID 2>/dev/null || true; \
		rm -f "$(FRONTEND_PID_FILE)"; \
	fi
	@# Kill by port (most reliable fallback)
	@lsof -ti :$(API_PORT) 2>/dev/null | xargs -r kill -9 2>/dev/null || true
	@sleep 0.3
	@echo "  $(GREEN)✓ Port $(API_PORT) freed$(NC)"
	@lsof -ti :$(VITE_PORT) 2>/dev/null | xargs -r kill -9 2>/dev/null || true
	@sleep 0.3
	@echo "  $(GREEN)✓ Port $(VITE_PORT) freed$(NC)"
	@# Clean PID directory
	@echo "$(CYAN)Cleaning PID files...$(NC)"
	@rm -rf "$(PID_DIR)" 2>/dev/null || true
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
		echo "$(YELLOW)Terminating database connections...$(NC)"; \
		sudo -u postgres psql -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '$(DB_NAME)';" > /dev/null 2>&1 || true; \
		echo "$(YELLOW)Dropping database...$(NC)"; \
		sudo -u postgres psql -c "DROP DATABASE IF EXISTS $(DB_NAME);" > /dev/null 2>&1 && echo "$(GREEN)✓ Database destroyed$(NC)" || echo "$(YELLOW)Database did not exist$(NC)"; \
		echo ""; \
		echo "$(YELLOW)Cleaning files...$(NC)"; \
		rm -rf "$(LOGS_DIR)" 2>/dev/null && echo "$(GREEN)✓ All logs deleted$(NC)" || true; \
		rm -f "$(BACKEND_PATH)" 2>/dev/null && echo "$(GREEN)✓ Backend binary deleted$(NC)" || true; \
		echo ""; \
		echo "$(GREEN)╔══════════════════════════════════════════════════════════════════════════════╗$(NC)"; \
		echo "$(GREEN)║  ✅  DEVELOPMENT ENVIRONMENT DESTROYED                                        ║$(NC)"; \
		echo "$(GREEN)╚══════════════════════════════════════════════════════════════════════════════╝$(NC)"; \
		echo ""; \
		echo "To recreate fresh environment:"; \
		echo "  1. $(CYAN)make db-init$(NC)"; \
		echo "  2. $(CYAN)make start$(NC)"; \
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
		echo "$(RED)❌ Port $(API_PORT) (Backend) is in use:$(NC)"; \
		echo "   PID: $$API_PID ($$API_CMD)"; \
	else \
		echo "$(GREEN)✓ Port $(API_PORT) (Backend) is available$(NC)"; \
	fi
	@echo ""
	@VITE_PID=$$(lsof -ti :$(VITE_PORT) 2>/dev/null || true); \
	if [ -n "$$VITE_PID" ]; then \
		VITE_CMD=$$(ps -p $$VITE_PID -o comm= 2>/dev/null || echo "unknown"); \
		echo "$(RED)❌ Port $(VITE_PORT) (Frontend) is in use:$(NC)"; \
		echo "   PID: $$VITE_PID ($$VITE_CMD)"; \
	else \
		echo "$(GREEN)✓ Port $(VITE_PORT) (Frontend) is available$(NC)"; \
	fi
	@echo ""

check-processes: ## Show running dev processes
	@echo "$(BLUE)🔍 Checking for running dev processes...$(NC)"
	@echo ""
	@echo "$(CYAN)Backend processes:$(NC)"
	@ps aux 2>/dev/null | grep -E "$(BACKEND_BINARY)" | grep -v grep || echo "  None running"
	@echo ""
	@echo "$(CYAN)Frontend (Vite) processes:$(NC)"
	@ps aux 2>/dev/null | grep -E "vite|npm run dev" | grep -v grep || echo "  None running"
	@echo ""

# ============================================================================
# TESTING
# ============================================================================

test: _check-go ## Run backend tests
	@echo "$(BLUE)🧪 Running backend tests...$(NC)"
	@cd "$(BACKEND_DIR)" && go test -v ./...

test-coverage: _check-go ## Run tests with coverage report
	@echo "$(BLUE)🧪 Running tests with coverage...$(NC)"
	@cd "$(BACKEND_DIR)" && go test -coverprofile=coverage.out ./... && go tool cover -html=coverage.out -o coverage.html
	@echo "$(GREEN)✓ Coverage report: $(BACKEND_DIR)/coverage.html$(NC)"

populate: _check-postgres ## Populate database with test data
	@echo "$(BLUE)📊 Populating database with test data...$(NC)"
	@export SERVER_URL=http://localhost:$(API_PORT) && \
	export BASE_URL=http://localhost:$(API_PORT)/api && \
	export DB_USER=$(DB_USER) && \
	export DB_PASSWORD=$(DB_PASSWORD) && \
	export API_USERNAME=root && \
	export API_PASSWORD=$(DB_PASSWORD) && \
	../../backend/tools/populate.sh
