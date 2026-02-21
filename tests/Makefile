# CHOP - Tests Makefile
# Located in: tests/Makefile
# Usage: make -f tests/Makefile <target>
# Or: cd tests && make <target>

.PHONY: help test test-all test-blocking test-security test-coverage test-verbose test-watch clean install-deps

# Colors
RED := \033[0;31m
GREEN := \033[0;32m
YELLOW := \033[1;33m
BLUE := \033[0;34m
NC := \033[0m

help: ## Show test commands
	@echo "$(BLUE)╔════════════════════════════════════════════════════════════╗$(NC)"
	@echo "$(BLUE)║$(NC)    CHOP - Test Suite Commands                            $(BLUE)║$(NC)"
	@echo "$(BLUE)╚════════════════════════════════════════════════════════════╝$(NC)"
	@echo ""
	@echo "$(YELLOW)Test Execution:$(NC)"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  $(GREEN)%-20s$(NC) %s\n", $$1, $$2}'
	@echo ""
	@echo "$(YELLOW)Configuration:$(NC)"
	@echo "  Test Framework: pytest 9.0.2"
	@echo "  Language: Python 3.13.9 (strict)"
	@echo "  Test Files: test_*.py"
	@echo "  API Endpoint: http://localhost:3000/api"
	@echo ""
	@echo "$(YELLOW)See Also:$(NC)"
	@echo "  - Documentation: cat README.md"
	@echo "  - Run all tests: ./run_all_tests.sh"
	@echo ""

test: ## Run all tests
	@echo "$(BLUE)🧪 Running all tests...$(NC)"
	./run_all_tests.sh

test-all: test ## Alias for test

test-blocking: ## Run login blocking tests only
	@echo "$(BLUE)🔐 Running login blocking tests...$(NC)"
	./run_all_tests.sh -m login_blocking

test-security: ## Run security tests only
	@echo "$(BLUE)🔒 Running security tests...$(NC)"
	./run_all_tests.sh -m security

test-coverage: ## Run tests with coverage report
	@echo "$(BLUE)📊 Running tests with coverage...$(NC)"
	./run_all_tests.sh --coverage

test-html: ## Run tests with HTML report
	@echo "$(BLUE)📊 Running tests with HTML report...$(NC)"
	./run_all_tests.sh --html

test-verbose: ## Run tests with verbose output
	@echo "$(BLUE)🔍 Running tests (verbose)...$(NC)"
	./run_all_tests.sh -v

test-watch: ## Run tests in watch mode (requires pytest-watch)
	@echo "$(BLUE)👁️  Running tests in watch mode...$(NC)"
	@command -v ptw >/dev/null 2>&1 || (echo "Installing pytest-watch..." && pip install pytest-watch)
	@ptw

test-keyword: ## Run tests matching keyword (usage: make test-keyword KEYWORD=blocking)
	@echo "$(BLUE)🔍 Running tests matching: $(KEYWORD)$(NC)"
	./run_all_tests.sh -k "$(KEYWORD)"

install-deps: ## Install test dependencies
	@echo "$(BLUE)📦 Installing test dependencies...$(NC)"
	@pip install -q -r requirements.txt
	@echo "$(GREEN)✅ Dependencies installed$(NC)"

clean: ## Clean test artifacts
	@echo "$(YELLOW)🧹 Cleaning test artifacts...$(NC)"
	@rm -rf htmlcov report.html .pytest_cache
	@find . -name "*.pyc" -delete
	@find . -name "__pycache__" -delete
	@echo "$(GREEN)✅ Cleaned$(NC)"

check: ## Check pytest and dependencies
	@echo "$(BLUE)✓ Checking pytest installation...$(NC)"
	@command -v pytest >/dev/null 2>&1 && echo "$(GREEN)✅ pytest installed$(NC)" || (echo "$(RED)❌ pytest not found$(NC)" && echo "Run: make install-deps")

info: ## Show test environment information
	@echo "$(BLUE)ℹ️  Test Environment:$(NC)"
	@echo ""
	@echo "  Python: $$(python --version 2>&1)"
	@echo "  pytest: $$(pytest --version 2>&1 | head -n1)"
	@echo "  Working Dir: $$(pwd)"
	@echo "  Test Files: $$(find . -name 'test_*.py' | wc -l)"
	@echo ""
	@echo "  Configuration:"
	@echo "    API: http://localhost:3000/api"
	@echo "    Framework: pytest"
	@echo "    Requirements: requirements.txt"
	@echo ""

.DEFAULT_GOAL := help
.SILENT:
