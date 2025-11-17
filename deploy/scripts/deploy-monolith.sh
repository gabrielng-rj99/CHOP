#!/bin/bash

################################################################################
# Contract Manager - Monolith Deployment Script
#
# Script único para iniciar o projeto completo em modo desenvolvimento local:
# - Backend (Go API)
# - Frontend (React + Vite)
# - PostgreSQL (gerenciar e inicializar)
#
# Este script integra toda a funcionalidade de setup-db.sh
#
# Uso: ./deploy-monolith.sh [comando] [opções]
#
# Comandos:
#   start              Inicia tudo (padrão)
#   stop               Para tudo
#   restart            Reinicia tudo
#   backend            Inicia apenas o backend
#   frontend           Inicia apenas o frontend
#   db init            Inicializa banco de dados
#   db start           Inicia PostgreSQL
#   db stop            Para PostgreSQL
#   db status          Ver status do banco
#   db reset           Apaga e recria banco
#   logs               Mostra logs em tempo real
#   status             Verifica status de tudo
#   clean              Remove arquivos temporários
#   help               Mostra esta mensagem
#
# Exemplos:
#   ./deploy-monolith.sh              # Inicia tudo
#   ./deploy-monolith.sh backend      # Apenas backend
#   ./deploy-monolith.sh db init      # Setup do banco
#   ./deploy-monolith.sh logs         # Ver logs
#   ./deploy-monolith.sh stop         # Para tudo
#
################################################################################

set -euo pipefail

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuração
PROJECT_NAME="Contract Manager"
PROJECT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
BACKEND_DIR="$PROJECT_DIR/backend"
FRONTEND_DIR="$PROJECT_DIR/frontend"
CONFIG_FILE="$PROJECT_DIR/monolith.ini"
LOGS_DIR="$PROJECT_DIR/.logs"
PID_FILE="$LOGS_DIR/pids"
BACKEND_PID="$PID_FILE/backend.pid"
FRONTEND_PID="$PID_FILE/frontend.pid"
SCHEMA_FILE="$BACKEND_DIR/database/schema.sql"

# Configuração do banco de dados (padrão - pode ser alterado no frontend)
DB_HOST="${DB_HOST:-localhost}"
DB_PORT="${DB_PORT:-5432}"
DB_NAME="${DB_NAME:-contracts_manager}"
DB_USER="${DB_USER:-postgres}"
DB_PASSWORD="${DB_PASSWORD:-postgres}"

# Configuração dos serviços
BACKEND_PORT="${BACKEND_PORT:-3000}"
FRONTEND_PORT="${FRONTEND_PORT:-5173}"

################################################################################
# Funções de Log
################################################################################

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

log_error() {
    echo -e "${RED}[✗]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[⚠]${NC} $1"
}

log_section() {
    echo -e "\n${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${MAGENTA}$1${NC}"
    echo -e "${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"
}

print_header() {
    clear
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║  $PROJECT_NAME - Monolith Deployment                    ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

################################################################################
# Funções Auxiliares
################################################################################

# Criar diretórios necessários
setup_directories() {
    mkdir -p "$LOGS_DIR"
    mkdir -p "$PID_FILE"
    mkdir -p "$BACKEND_DIR/logs"
}

# Verificar se porta está em uso
check_port() {
    local port=$1
    if lsof -Pi :$port -sTCP:LISTEN -t >/dev/null 2>&1; then
        return 0  # Porta em uso
    else
        return 1  # Porta livre
    fi
}

# Verificar se arquivo PID existe e processo está rodando
is_process_running() {
    local pid_file=$1
    if [ -f "$pid_file" ]; then
        local pid=$(<"$pid_file")
        if kill -0 "$pid" 2>/dev/null; then
            return 0  # Rodando
        fi
    fi
    return 1  # Não rodando
}

# Limpar arquivo PID
clean_pid() {
    local pid_file=$1
    if [ -f "$pid_file" ]; then
        rm -f "$pid_file"
    fi
}

# Verificar se PostgreSQL está instalado
check_postgres_installed() {
    if ! command -v psql &> /dev/null; then
        return 1
    fi
    return 0
}

# Verificar conexão com PostgreSQL
check_postgres_running() {
    if ! pg_isready -h "$DB_HOST" -p "$DB_PORT" &> /dev/null; then
        return 1
    fi
    return 0
}

# Iniciar PostgreSQL (dependendo do SO)
postgres_start() {
    log_info "Iniciando PostgreSQL..."

    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        if ! check_postgres_running; then
            brew services start postgresql@16 2>/dev/null || {
                brew services start postgresql 2>/dev/null || {
                    log_error "Não foi possível iniciar PostgreSQL via Homebrew"
                    return 1
                }
            }
            sleep 2
        fi
    elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
        # Linux
        if ! check_postgres_running; then
            sudo systemctl start postgresql 2>/dev/null || {
                log_error "Não foi possível iniciar PostgreSQL via systemctl"
                return 1
            }
            sleep 2
        fi
    fi

    if check_postgres_running; then
        log_success "PostgreSQL está rodando"
        return 0
    else
        log_error "Falha ao iniciar PostgreSQL"
        return 1
    fi
}

# Parar PostgreSQL
postgres_stop() {
    log_info "Parando PostgreSQL..."

    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        brew services stop postgresql@16 2>/dev/null || brew services stop postgresql 2>/dev/null || true
    elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
        # Linux
        sudo systemctl stop postgresql 2>/dev/null || true
    fi

    log_success "PostgreSQL parado"
}

################################################################################
# Banco de Dados
################################################################################

db_init() {
    log_section "Inicializando Banco de Dados"

    if ! check_postgres_installed; then
        log_error "PostgreSQL não está instalado!"
        echo ""
        echo "Para instalar:"
        echo "  macOS: brew install postgresql@16 && brew services start postgresql@16"
        echo "  Ubuntu: sudo apt-get install postgresql"
        echo "  Fedora: sudo dnf install postgresql-server"
        return 1
    fi

    if ! check_postgres_running; then
        log_warn "PostgreSQL não está rodando, tentando iniciar..."
        if ! postgres_start; then
            log_error "Não foi possível iniciar PostgreSQL"
            return 1
        fi
    fi

    if [ ! -f "$SCHEMA_FILE" ]; then
        log_error "Schema file não encontrado: $SCHEMA_FILE"
        return 1
    fi

    log_info "Configuração:"
    log_info "  Host: $DB_HOST"
    log_info "  Porta: $DB_PORT"
    log_info "  Banco: $DB_NAME"
    log_info "  Usuário: $DB_USER"

    # Criar banco de dados
    log_info "Criando banco de dados '$DB_NAME'..."
    psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -tc \
        "SELECT 1 FROM pg_database WHERE datname = '$DB_NAME'" 2>/dev/null | grep -q 1 || \
    psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -c "CREATE DATABASE $DB_NAME;" 2>/dev/null

    if [ $? -eq 0 ]; then
        log_success "Banco de dados '$DB_NAME' criado/verificado"
    else
        log_error "Erro ao criar banco de dados"
        return 1
    fi

    # Executar schema
    log_info "Executando schema..."
    psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -f "$SCHEMA_FILE" > /dev/null 2>&1

    if [ $? -eq 0 ]; then
        log_success "Schema executado com sucesso"
    else
        log_error "Erro ao executar schema"
        return 1
    fi

    # Verificar tabelas criadas
    TABLES=$(psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -t -c \
        "SELECT count(*) FROM information_schema.tables WHERE table_schema='public';" 2>/dev/null || echo "0")

    log_success "Banco inicializado com $TABLES tabelas"
    echo ""
}

db_reset() {
    log_section "Reset do Banco de Dados"

    log_warn "Isso deletará TUDO no banco de dados '$DB_NAME'"
    echo ""
    read -p "Tem certeza? Digite 'sim' para confirmar: " -r
    echo ""

    if [[ ! $REPLY =~ ^[Ss][Ii][Mm]$ ]]; then
        log_info "Operação cancelada"
        return 0
    fi

    if ! check_postgres_running; then
        log_warn "PostgreSQL não está rodando, tentando iniciar..."
        postgres_start || {
            log_error "Não foi possível iniciar PostgreSQL"
            return 1
        }
    fi

    # Desconectar clientes
    log_info "Desconectando clientes da base..."
    psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -tc \
        "SELECT pg_terminate_backend(pg_stat_activity.pid)
         FROM pg_stat_activity
         WHERE pg_stat_activity.datname = '$DB_NAME'
         AND pid <> pg_backend_pid();" > /dev/null 2>&1 || true

    # Dropar banco
    log_info "Deletando banco de dados '$DB_NAME'..."
    psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -c "DROP DATABASE IF EXISTS $DB_NAME;" > /dev/null 2>&1 || true

    log_success "Banco deletado"

    # Reinicializar
    log_info "Recriando banco de dados..."
    db_init
}

db_status() {
    log_section "Status do Banco de Dados"

    echo -e "${MAGENTA}PostgreSQL:${NC}"
    if command -v pg_isready &> /dev/null; then
        if check_postgres_running; then
            log_success "PostgreSQL está rodando"
            echo "  Host: $DB_HOST"
            echo "  Porta: $DB_PORT"
        else
            log_error "PostgreSQL não está rodando"
            return 1
        fi
    else
        log_error "psql não encontrado"
        return 1
    fi

    echo ""
    echo -e "${MAGENTA}Banco de Dados:${NC}"
    if psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -lqt 2>/dev/null | cut -d \| -f 1 | grep -qw "$DB_NAME"; then
        log_success "Banco de dados '$DB_NAME' existe"

        TABLES=$(psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -t -c \
            "SELECT count(*) FROM information_schema.tables WHERE table_schema='public';" 2>/dev/null || echo "0")
        log_success "Banco tem $TABLES tabelas"
    else
        log_warn "Banco de dados '$DB_NAME' não existe"
    fi

    echo ""
}

################################################################################
# Backend
################################################################################

start_backend() {
    log_section "Iniciando Backend"

    # Verificar se já está rodando
    if is_process_running "$BACKEND_PID"; then
        log_warn "Backend já está rodando (PID: $(cat "$BACKEND_PID"))"
        return 0
    fi

    # Verificar se porta está em uso
    if check_port "$BACKEND_PORT"; then
        log_error "Porta $BACKEND_PORT já está em uso"
        return 1
    fi

    # Definir variáveis de ambiente
    export APP_DATABASE_PASSWORD="${APP_DATABASE_PASSWORD:-postgres}"
    export APP_JWT_SECRET_KEY="${APP_JWT_SECRET_KEY:-dev_secret_key_minimum_32_characters_required}"
    export APP_SERVER_PORT="${BACKEND_PORT}"
    export APP_DATABASE_HOST="${DB_HOST}"
    export APP_DATABASE_PORT="${DB_PORT}"
    export APP_DATABASE_NAME="${DB_NAME}"
    export APP_DATABASE_USER="${DB_USER}"
    export APP_ENV="${APP_ENV:-development}"

    log_info "Iniciando servidor na porta $BACKEND_PORT..."
    log_info "  DB: $DB_USER@$DB_HOST:$DB_PORT/$DB_NAME"

    cd "$BACKEND_DIR"

    go run cmd/server/main.go > "$LOGS_DIR/backend.log" 2>&1 &
    local backend_pid=$!
    echo "$backend_pid" > "$BACKEND_PID"

    sleep 2

    if is_process_running "$BACKEND_PID"; then
        log_success "Backend iniciado (PID: $backend_pid)"
        log_info "Logs: $LOGS_DIR/backend.log"
        return 0
    else
        log_error "Falha ao iniciar backend"
        log_info "Verifique os logs: tail -f $LOGS_DIR/backend.log"
        return 1
    fi
}

stop_backend() {
    log_section "Parando Backend"

    if is_process_running "$BACKEND_PID"; then
        local pid=$(<"$BACKEND_PID")
        log_info "Parando processo (PID: $pid)..."
        kill "$pid" 2>/dev/null || true
        sleep 1
        log_success "Backend parado"
    else
        log_warn "Backend não está rodando"
    fi

    clean_pid "$BACKEND_PID"
}

################################################################################
# Frontend
################################################################################

start_frontend() {
    log_section "Iniciando Frontend"

    # Verificar se já está rodando
    if is_process_running "$FRONTEND_PID"; then
        log_warn "Frontend já está rodando (PID: $(cat "$FRONTEND_PID"))"
        return 0
    fi

    # Verificar se tem dependências
    if [ ! -d "$FRONTEND_DIR/node_modules" ]; then
        log_info "Instalando dependências do frontend..."
        cd "$FRONTEND_DIR"
        npm install --silent
    fi

    log_info "Iniciando servidor Vite..."
    cd "$FRONTEND_DIR"

    npm run dev > "$LOGS_DIR/frontend.log" 2>&1 &
    local frontend_pid=$!
    echo "$frontend_pid" > "$FRONTEND_PID"

    sleep 3

    if is_process_running "$FRONTEND_PID"; then
        log_success "Frontend iniciado (PID: $frontend_pid)"
        log_info "Logs: $LOGS_DIR/frontend.log"
        return 0
    else
        log_error "Falha ao iniciar frontend"
        log_info "Verifique os logs: tail -f $LOGS_DIR/frontend.log"
        return 1
    fi
}

stop_frontend() {
    log_section "Parando Frontend"

    if is_process_running "$FRONTEND_PID"; then
        local pid=$(<"$FRONTEND_PID")
        log_info "Parando processo (PID: $pid)..."
        kill "$pid" 2>/dev/null || true
        sleep 1
        log_success "Frontend parado"
    else
        log_warn "Frontend não está rodando"
    fi

    clean_pid "$FRONTEND_PID"
}

################################################################################
# Operações Gerais
################################################################################

start_all() {
    print_header

    log_section "Iniciando $PROJECT_NAME"

    setup_directories

    # 1. Verificar e iniciar banco de dados
    log_info "Configurando banco de dados..."
    if ! check_postgres_running; then
        log_warn "PostgreSQL não está rodando, tentando iniciar..."
        if ! postgres_start; then
            log_error "Não foi possível iniciar PostgreSQL"
            return 1
        fi
    fi

    sleep 1

    # Inicializar banco se não existir
    if ! psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -lqt 2>/dev/null | cut -d \| -f 1 | grep -qw "$DB_NAME"; then
        if ! db_init; then
            log_error "Falha ao inicializar banco de dados"
            return 1
        fi
    fi

    sleep 2

    # 2. Iniciar backend
    if ! start_backend; then
        log_error "Falha ao iniciar backend"
        return 1
    fi

    sleep 2

    # 3. Iniciar frontend
    if ! start_frontend; then
        log_error "Falha ao iniciar frontend"
        return 1
    fi

    # Exibir informações
    log_section "✓ Tudo Iniciado!"

    echo -e "${GREEN}Serviços rodando:${NC}"
    echo "  Frontend:  ${CYAN}http://localhost:5173${NC} (Vite dev server)"
    echo "  Backend:   ${CYAN}http://localhost:3000${NC} (Go API)"
    echo "  Database:  ${CYAN}$DB_HOST:$DB_PORT${NC} (PostgreSQL)"
    echo ""
    echo -e "${GREEN}Banco de dados:${NC}"
    echo "  Nome: $DB_NAME"
    echo "  Usuário: $DB_USER"
    echo "  Senha: (será alterada na primeira execução)"
    echo ""
    echo -e "${GREEN}Próximos passos:${NC}"
    echo "  1. Abra ${CYAN}http://localhost:5173${NC} no navegador"
    echo "  2. Complete o wizard de inicialização"
    echo "  3. Customize banco de dados, portas, usuários, etc"
    echo "  4. Faça login com usuário 'root'"
    echo ""
    echo -e "${GREEN}Comandos úteis:${NC}"
    echo "  Ver logs:       ./deploy-monolith.sh logs"
    echo "  Parar:          ./deploy-monolith.sh stop"
    echo "  Reiniciar:      ./deploy-monolith.sh restart"
    echo "  Status:         ./deploy-monolith.sh status"
    echo ""
}

stop_all() {
    log_section "Parando $PROJECT_NAME"

    stop_frontend
    stop_backend

    log_success "Todos os serviços parados"
}

restart_all() {
    stop_all
    sleep 2
    start_all
}

show_status() {
    print_header

    echo -e "${MAGENTA}Backend:${NC}"
    if is_process_running "$BACKEND_PID"; then
        echo -e "  Status: ${GREEN}✓ Rodando${NC} (PID: $(cat "$BACKEND_PID"))"
        echo -e "  URL: ${CYAN}http://localhost:$BACKEND_PORT${NC}"
    else
        echo -e "  Status: ${RED}✗ Parado${NC}"
    fi

    echo ""
    echo -e "${MAGENTA}Frontend:${NC}"
    if is_process_running "$FRONTEND_PID"; then
        echo -e "  Status: ${GREEN}✓ Rodando${NC} (PID: $(cat "$FRONTEND_PID"))"
        echo -e "  URL: ${CYAN}http://localhost:5173${NC}"
    else
        echo -e "  Status: ${RED}✗ Parado${NC}"
    fi

    echo ""
    echo -e "${MAGENTA}Database (PostgreSQL):${NC}"
    if check_postgres_running; then
        echo -e "  Status: ${GREEN}✓ Rodando${NC}"
        echo -e "  Host: ${CYAN}$DB_HOST:$DB_PORT${NC}"
        echo -e "  Database: ${CYAN}$DB_NAME${NC}"
    else
        echo -e "  Status: ${RED}✗ Parado${NC}"
    fi

    echo ""
}

show_logs() {
    log_section "Logs em Tempo Real"

    echo "Mostrando logs de backend e frontend..."
    echo "Use Ctrl+C para sair"
    echo ""

    tail -f "$LOGS_DIR/backend.log" "$LOGS_DIR/frontend.log" 2>/dev/null || true
}

clean() {
    log_section "Limpando Arquivos Temporários"

    log_info "Removendo arquivos de log..."
    rm -rf "$LOGS_DIR"

    log_success "Limpeza concluída"
}

show_help() {
    cat << EOF
${CYAN}Contract Manager - Monolith Deployment${NC}

${MAGENTA}Uso:${NC}
  ./deploy-monolith.sh [comando]

${MAGENTA}Comandos:${NC}
  start              Inicia tudo (padrão)
  stop               Para tudo
  restart            Reinicia tudo
  backend            Inicia apenas o backend
  frontend           Inicia apenas o frontend
  db init            Inicializa banco de dados
  db start           Inicia PostgreSQL
  db stop            Para PostgreSQL
  db status          Ver status do banco
  db reset           Apaga e recria banco (CUIDADO!)
  logs               Mostra logs em tempo real
  status             Ver status de todos os serviços
  clean              Remove arquivos temporários
  help               Mostra esta mensagem

${MAGENTA}Exemplos:${NC}
  ./deploy-monolith.sh                # Inicia tudo
  ./deploy-monolith.sh backend        # Apenas backend
  ./deploy-monolith.sh db init        # Setup do banco
  ./deploy-monolith.sh logs           # Ver logs
  ./deploy-monolith.sh stop           # Para tudo

${MAGENTA}Variáveis de Ambiente:${NC}
  DB_HOST                 Host do PostgreSQL (padrão: localhost)
  DB_PORT                 Porta do PostgreSQL (padrão: 5432)
  DB_NAME                 Nome do banco (padrão: contracts_manager)
  DB_USER                 Usuário do banco (padrão: postgres)
  DB_PASSWORD             Senha do banco (padrão: postgres)
  BACKEND_PORT            Porta do backend (padrão: 3000)
  FRONTEND_PORT           Porta do frontend (padrão: 5173)
  APP_DATABASE_PASSWORD   Senha do banco após inicialização
  APP_JWT_SECRET_KEY      JWT secret após inicialização

${MAGENTA}Exemplos com variáveis:${NC}
  export DB_PORT=5433
  export BACKEND_PORT=3001
  export DB_NAME=meu_banco
  ./deploy-monolith.sh start

${MAGENTA}Notas:${NC}
  • Variáveis de ambiente são usadas na inicialização
  • Após primeira execução, customize tudo no painel do frontend
  • setup-db.sh foi integrado a este script
  • Não precisa mais de script separado para banco de dados

EOF
}

################################################################################
# Main
################################################################################

main() {
    local command="${1:-start}"

    case "$command" in
        start)
            start_all
            ;;
        stop)
            stop_all
            ;;
        restart)
            restart_all
            ;;
        backend)
            setup_directories
            postgres_start 2>/dev/null || true
            sleep 2
            start_backend
            ;;
        frontend)
            setup_directories
            start_frontend
            ;;
        db)
            setup_directories
            local db_cmd="${2:-init}"
            case "$db_cmd" in
                init)
                    db_init
                    ;;
                start)
                    postgres_start
                    ;;
                stop)
                    postgres_stop
                    ;;
                reset)
                    db_reset
                    ;;
                status)
                    db_status
                    ;;
                *)
                    log_error "Comando de banco desconhecido: $db_cmd"
                    echo "Use: init, start, stop, reset, status"
                    exit 1
                    ;;
            esac
            ;;
        logs)
            show_logs
            ;;
        status)
            show_status
            ;;
        clean)
            clean
            ;;
        help|--help|-h)
            show_help
            ;;
        *)
            log_error "Comando desconhecido: $command"
            echo ""
            show_help
            exit 1
            ;;
    esac
}

# Executar
main "$@"
