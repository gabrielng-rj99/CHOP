# CHOP - Backend Makefile
# Located in: backend/Makefile
# Usage: make -f backend/Makefile <target>
# Or: cd backend && make <target>

.PHONY: help build rebuild run clean test fmt lint coverage

# Colors
RED := \033[0;31m
GREEN := \033[0;32m
YELLOW := \033[1;33m
BLUE := \033[0;34m
NC := \033[0m

OUTPUT_DIR := ../app/dev/bin
BINARY_NAME := $(OUTPUT_DIR)/chop-backend-dev.bin
MAIN_PATH := ./main.go

help: ## Show backend build commands
	@echo "$(BLUE)╔════════════════════════════════════════════════════════════╗$(NC)"
	@echo "$(BLUE)║$(NC)    CHOP - Backend Build & Development Tasks             $(BLUE)║$(NC)"
	@echo "$(BLUE)╚════════════════════════════════════════════════════════════╝$(NC)"
	@echo ""
	@echo "$(YELLOW)Build Commands:$(NC)"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  $(GREEN)%-20s$(NC) %s\n", $$1, $$2}'
	@echo ""
	@echo "$(YELLOW)Configuration:$(NC)"
	@echo "  Language: Go 1.25.1+"
	@echo "  Main: $(MAIN_PATH)"
	@echo "  Binary: $(BINARY_NAME)"
	@echo ""

build: ## Build backend binary
	@echo "$(BLUE)🔨 Building backend...$(NC)"
	@mkdir -p $(OUTPUT_DIR)
	@go build -o $(BINARY_NAME) $(MAIN_PATH)
	@echo "$(GREEN)✅ Build complete: $(BINARY_NAME)$(NC)"

rebuild: clean build ## Clean and rebuild backend

run: build ## Build and run backend
	@echo "$(BLUE)🚀 Running backend...$(NC)"
	@$(BINARY_NAME)

dev: ## Run backend in development mode with hot reload (requires air)
	@echo "$(BLUE)🔄 Running with hot reload...$(NC)"
	@air || (echo "$(YELLOW)Installing air...$(NC)" && go install github.com/cosmtrek/air@latest && air)

test: ## Run backend tests
	@echo "$(BLUE)🧪 Running backend tests...$(NC)"
	@go test -v -cover ./...

test-coverage: ## Run tests with coverage report
	@echo "$(BLUE)📊 Running tests with coverage...$(NC)"
	@go test -v -coverprofile=coverage.out ./...
	@go tool cover -func=coverage.out | tail -n 1
	@echo "$(YELLOW)Generating HTML coverage report...$(NC)"
	@go tool cover -html=coverage.out -o coverage.html
	@echo "$(GREEN)✅ Coverage report: coverage.html$(NC)"

fmt: ## Format Go code
	@echo "$(BLUE)🎨 Formatting code...$(NC)"
	@go fmt ./...
	@echo "$(GREEN)✅ Code formatted$(NC)"

lint: ## Run Go linter
	@echo "$(BLUE)🔍 Running linter...$(NC)"
	@go vet ./...
	@echo "$(GREEN)✅ Linting complete$(NC)"

clean: ## Clean build artifacts
	@echo "$(YELLOW)🧹 Cleaning...$(NC)"
	@rm -f $(BINARY_NAME)
	@rm -f coverage.out coverage.html
	@go clean
	@echo "$(GREEN)✅ Cleaned$(NC)"

deps: ## Download and tidy dependencies
	@echo "$(BLUE)📦 Managing dependencies...$(NC)"
	@go mod download
	@go mod tidy
	@echo "$(GREEN)✅ Dependencies updated$(NC)"

mod-verify: ## Verify module integrity
	@echo "$(BLUE)🔍 Verifying modules...$(NC)"
	@go mod verify
	@echo "$(GREEN)✅ Module verification passed$(NC)"

info: ## Show backend information
	@echo "$(BLUE)ℹ️  Backend Information:$(NC)"
	@echo "  Go Version: $$(go version | awk '{print $$3}')"
	@echo "  Main: $(MAIN_PATH)"
	@echo "  Binary: $(BINARY_NAME)"
	@echo "  Module: $$(go list -m)"
	@echo ""

.DEFAULT_GOAL := help
.SILENT:
