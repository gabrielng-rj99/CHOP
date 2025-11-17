# Makefile para testes de segurança do Contract Manager
# Simplifica a execução dos testes com comandos curtos

.PHONY: help test test-verbose test-coverage test-specific clean setup teardown keep-alive

# Cores para output
GREEN  := \033[0;32m
YELLOW := \033[1;33m
BLUE   := \033[0;34m
RED    := \033[0;31m
NC     := \033[0m # No Color

# Default target
.DEFAULT_GOAL := help

help: ## Mostra esta mensagem de ajuda
	@echo "$(BLUE)═══════════════════════════════════════════════════════════════$(NC)"
	@echo "$(BLUE)  Contract Manager - Comandos de Teste de Segurança$(NC)"
	@echo "$(BLUE)═══════════════════════════════════════════════════════════════$(NC)"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  $(GREEN)%-20s$(NC) %s\n", $$1, $$2}'
	@echo ""
	@echo "$(YELLOW)Stack de Testes:$(NC)"
	@echo "  PostgreSQL:  localhost:65432"
	@echo "  Backend API: localhost:63000"
	@echo "  Frontend:    localhost:65080 (se necessário)"
	@echo ""

test: ## Executar todos os testes de segurança
	@./run_security_tests.sh

test-v: ## Executar testes com output verbose
	@./run_security_tests.sh -v

test-verbose: test-v ## Alias para test-v

coverage: ## Executar testes com relatório de cobertura
	@./run_security_tests.sh -c

test-coverage: coverage ## Alias para coverage

cov: coverage ## Alias curto para coverage

test-cov-v: ## Executar testes verbose com cobertura
	@./run_security_tests.sh -v -c

# Testes específicos
test-token: ## Testar manipulação de tokens
	@./run_security_tests.sh -v -t TestTokenManipulation

test-priv: ## Testar escalação de privilégios
	@./run_security_tests.sh -v -t TestPrivilegeEscalation

test-sql: ## Testar SQL injection
	@./run_security_tests.sh -v -t TestSQLInjection

test-leak: ## Testar vazamento de dados
	@./run_security_tests.sh -v -t TestDataLeakage

test-auth: ## Testar fluxos de autenticação
	@./run_security_tests.sh -v -t TestAuthenticationFlows

test-password: ## Testar segurança de senhas
	@./run_security_tests.sh -v -t TestPasswordSecurity

test-xss: ## Testar prevenção de XSS
	@./run_security_tests.sh -v -t TestXSSPrevention

# Modo debug
keep-alive: ## Manter ambiente rodando após testes (debug)
	@./run_security_tests.sh --keep-alive

debug: keep-alive ## Alias para keep-alive

no-cleanup: ## Executar sem limpar no final (debug)
	@./run_security_tests.sh -v --no-cleanup

# Utilitários
clean: ## Limpar arquivos gerados pelos testes
	@echo "$(YELLOW)Limpando arquivos de teste...$(NC)"
	@rm -f test-server
	@rm -f server.log
	@rm -f coverage.out
	@rm -f coverage.html
	@rm -f *.test
	@echo "$(GREEN)✓ Arquivos limpos$(NC)"

clean-all: clean ## Limpar tudo incluindo Docker
	@echo "$(YELLOW)Limpando containers e volumes Docker...$(NC)"
	@docker stop contracts-test-db 2>/dev/null || true
	@docker rm contracts-test-db 2>/dev/null || true
	@docker volume rm contracts-test-db-volume 2>/dev/null || true
	@docker network rm contracts-test-network 2>/dev/null || true
	@echo "$(GREEN)✓ Docker limpo$(NC)"

setup: ## Verificar dependências e preparar ambiente
	@echo "$(BLUE)Verificando dependências...$(NC)"
	@command -v go >/dev/null 2>&1 || { echo "$(RED)✗ Go não instalado$(NC)"; exit 1; }
	@echo "$(GREEN)✓ Go: $$(go version | awk '{print $$3}')$(NC)"
	@command -v docker >/dev/null 2>&1 || { echo "$(RED)✗ Docker não instalado$(NC)"; exit 1; }
	@echo "$(GREEN)✓ Docker: $$(docker --version | awk '{print $$3}' | sed 's/,//')$(NC)"
	@docker info >/dev/null 2>&1 || { echo "$(RED)✗ Docker daemon não está rodando$(NC)"; exit 1; }
	@echo "$(GREEN)✓ Docker daemon: rodando$(NC)"
	@echo "$(GREEN)✓ Ambiente pronto para testes$(NC)"

teardown: clean-all ## Derrubar toda a stack de testes

status: ## Verificar status da stack de testes
	@echo "$(BLUE)Status da Stack de Testes:$(NC)"
	@echo ""
	@echo "$(YELLOW)PostgreSQL Container:$(NC)"
	@docker ps -a --filter name=contracts-test-db --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" || echo "  Não encontrado"
	@echo ""
	@echo "$(YELLOW)Volumes Docker:$(NC)"
	@docker volume ls --filter name=contracts-test-db-volume --format "table {{.Name}}\t{{.Driver}}" || echo "  Não encontrado"
	@echo ""
	@echo "$(YELLOW)Networks Docker:$(NC)"
	@docker network ls --filter name=contracts-test-network --format "table {{.Name}}\t{{.Driver}}" || echo "  Não encontrado"
	@echo ""
	@echo "$(YELLOW)Servidor de Teste:$(NC)"
	@pgrep -f "test-server" >/dev/null && echo "  $(GREEN)Rodando$(NC) (PID: $$(pgrep -f 'test-server'))" || echo "  Parado"
	@echo ""
	@echo "$(YELLOW)Arquivos Gerados:$(NC)"
	@ls -lh test-server 2>/dev/null || echo "  test-server: não encontrado"
	@ls -lh server.log 2>/dev/null || echo "  server.log: não encontrado"
	@ls -lh coverage.out 2>/dev/null || echo "  coverage.out: não encontrado"
	@ls -lh coverage.html 2>/dev/null || echo "  coverage.html: não encontrado"

logs: ## Ver logs do servidor de teste
	@if [ -f server.log ]; then \
		tail -f server.log; \
	else \
		echo "$(RED)Arquivo server.log não encontrado$(NC)"; \
		echo "$(YELLOW)Execute 'make test' primeiro$(NC)"; \
	fi

logs-db: ## Ver logs do container PostgreSQL
	@docker logs contracts-test-db 2>/dev/null || echo "$(RED)Container não encontrado. Execute 'make test' primeiro.$(NC)"

shell-db: ## Abrir shell no banco de testes
	@echo "$(BLUE)Conectando ao banco de testes...$(NC)"
	@docker exec -it contracts-test-db psql -U test_user -d contracts_test 2>/dev/null || \
		echo "$(RED)Container não encontrado. Execute 'make keep-alive' primeiro.$(NC)"

open-coverage: ## Abrir relatório de cobertura no navegador
	@if [ -f coverage.html ]; then \
		echo "$(GREEN)Abrindo relatório de cobertura...$(NC)"; \
		command -v xdg-open >/dev/null && xdg-open coverage.html || \
		command -v open >/dev/null && open coverage.html || \
		echo "$(YELLOW)Abra manualmente: file://$$(pwd)/coverage.html$(NC)"; \
	else \
		echo "$(RED)Arquivo coverage.html não encontrado$(NC)"; \
		echo "$(YELLOW)Execute 'make coverage' primeiro$(NC)"; \
	fi

# Atalhos úteis
quick: test ## Alias rápido para test
q: quick ## Alias super rápido

full: test-cov-v ## Testes completos com verbose e cobertura
f: full ## Alias para full

watch: ## Executar testes continuamente (Ctrl+C para parar)
	@echo "$(BLUE)Modo watch ativado - testes serão executados a cada alteração$(NC)"
	@echo "$(YELLOW)Pressione Ctrl+C para parar$(NC)"
	@while true; do \
		clear; \
		make test; \
		echo ""; \
		echo "$(YELLOW)Aguardando próxima execução em 5 segundos...$(NC)"; \
		sleep 5; \
	done

# Informações
info: ## Mostrar informações sobre a stack de testes
	@echo "$(BLUE)═══════════════════════════════════════════════════════════════$(NC)"
	@echo "$(BLUE)  Informações da Stack de Testes$(NC)"
	@echo "$(BLUE)═══════════════════════════════════════════════════════════════$(NC)"
	@echo ""
	@echo "$(GREEN)Portas:$(NC)"
	@echo "  PostgreSQL:  65432"
	@echo "  Backend API: 63000"
	@echo "  Frontend:    65080 (opcional)"
	@echo ""
	@echo "$(GREEN)Credenciais do Banco:$(NC)"
	@echo "  Host:     localhost:65432"
	@echo "  Database: contracts_test"
	@echo "  User:     test_user"
	@echo "  Password: test_password"
	@echo ""
	@echo "$(GREEN)URLs da API:$(NC)"
	@echo "  Health:  http://localhost:63000/api/health"
	@echo "  Login:   http://localhost:63000/api/login"
	@echo "  Users:   http://localhost:63000/api/users"
	@echo ""
	@echo "$(GREEN)Testes Disponíveis:$(NC)"
	@echo "  • TestTokenManipulation    (make test-token)"
	@echo "  • TestPrivilegeEscalation  (make test-priv)"
	@echo "  • TestSQLInjection         (make test-sql)"
	@echo "  • TestDataLeakage          (make test-leak)"
	@echo "  • TestAuthenticationFlows  (make test-auth)"
	@echo "  • TestPasswordSecurity     (make test-password)"
	@echo "  • TestXSSPrevention        (make test-xss)"
	@echo ""

version: ## Mostrar versões das ferramentas
	@echo "$(BLUE)Versões:$(NC)"
	@go version
	@docker --version
	@docker-compose --version 2>/dev/null || docker compose version

# Exemplos
examples: ## Mostrar exemplos de uso
	@echo "$(BLUE)═══════════════════════════════════════════════════════════════$(NC)"
	@echo "$(BLUE)  Exemplos de Uso$(NC)"
	@echo "$(BLUE)═══════════════════════════════════════════════════════════════$(NC)"
	@echo ""
	@echo "$(GREEN)1. Executar todos os testes:$(NC)"
	@echo "   $$ make test"
	@echo ""
	@echo "$(GREEN)2. Testes com cobertura:$(NC)"
	@echo "   $$ make coverage"
	@echo ""
	@echo "$(GREEN)3. Testar SQL injection específico:$(NC)"
	@echo "   $$ make test-sql"
	@echo ""
	@echo "$(GREEN)4. Debug (manter ambiente rodando):$(NC)"
	@echo "   $$ make keep-alive"
	@echo "   Em outro terminal:"
	@echo "   $$ curl http://localhost:63000/api/health"
	@echo ""
	@echo "$(GREEN)5. Conectar ao banco de testes:$(NC)"
	@echo "   $$ make shell-db"
	@echo ""
	@echo "$(GREEN)6. Ver logs do servidor:$(NC)"
	@echo "   $$ make logs"
	@echo ""
	@echo "$(GREEN)7. Limpar tudo:$(NC)"
	@echo "   $$ make clean-all"
	@echo ""
