#!/usr/bin/env python3
"""
backend/tools/populate.py

Python migration of backend/tools/populate.sh

Populates the database with realistic test data using the official APIs.
This script creates:
  - 30 Categories
  - 75 Subcategories (2-3 per category)
  - 120 Clients (with distributed birthdays, including today's)
  - 0-5 Affiliates per client
  - 0-5 Contracts per client (mixed statuses, with financial auto-created)
  - Installments for each contract's financial
  - Some installments marked as paid
  - Users and roles (admin, operador, visualizador)
  - Archived clients
  - Contracts expiring soon (using today)

Usage:
  python3 backend/tools/populate.py [--dry-run] [--verbose]

Environment Variables:
  SERVER_URL        Server base URL (default: http://localhost:3000)
  BASE_URL          API base URL (default: http://localhost:3000/api)
  API_USERNAME      Login username (default: root)
  API_PASSWORD      Login password (default: THIS_IS_A_DEV_ENVIRONMENT_PASSWORD!123abc)
  DB_USER           Database user (default: chopuser_dev)
  DB_PASSWORD       Database password (default: THIS_IS_A_DEV_ENVIRONMENT_PASSWORD!123abc)
"""

import os
import sys
import time
import uuid
import json
import random
import argparse
import subprocess
from datetime import datetime, timedelta, timezone

try:
    import requests
except ImportError:
    requests = None


################################################################################
# Configuration
################################################################################

SERVER_URL = os.getenv("SERVER_URL", "http://localhost:3000")
BASE_URL = os.getenv("BASE_URL", "http://localhost:3000/api")
API_USERNAME = os.getenv("API_USERNAME", "root")
API_PASSWORD = os.getenv("API_PASSWORD", "THIS_IS_A_DEV_ENVIRONMENT_PASSWORD!123abc")
DB_USER = os.getenv("DB_USER", "chopuser_dev")
DB_PASSWORD = os.getenv("DB_PASSWORD", "THIS_IS_A_DEV_ENVIRONMENT_PASSWORD!123abc")
TIMESTAMP = str(int(time.time()))

DRY_RUN = False
VERBOSE = False

# Colors
RED = "\033[0;31m"
GREEN = "\033[0;32m"
YELLOW = "\033[1;33m"
BLUE = "\033[0;34m"
CYAN = "\033[0;36m"
NC = "\033[0m"  # No Color

# Counters
CREATED_CATEGORIES = 0
CREATED_SUBCATEGORIES = 0
CREATED_CLIENTS = 0
CREATED_AFFILIATES = 0
CREATED_CONTRACTS = 0
CREATED_INSTALLMENTS = 0
MARKED_PAID = 0
FAILED_REQUESTS = 0

# Arrays to store IDs
CATEGORY_IDS = []
SUBCATEGORY_IDS = []
CLIENT_IDS = []
AFFILIATE_IDS = []
CLIENT_AFFILIATES_LIST = []  # Cada posição corresponde ao índice do cliente em CLIENT_IDS, valor é string de afiliados separados por vírgula
CONTRACT_IDS = []
FINANCIAL_IDS = []
USER_IDS = []

TOKEN = None


################################################################################
# Logging Functions
################################################################################

def log_info(msg):
    print(f"{BLUE}ℹ️{NC}  {msg}")


def log_success(msg):
    print(f"{GREEN}✅{NC} {msg}")


def log_warning(msg):
    print(f"{YELLOW}⚠️{NC}  {msg}")


def log_error(msg):
    print(f"{RED}❌{NC} {msg}", file=sys.stderr)


def log_debug(msg):
    if VERBOSE:
        print(f"{CYAN}🔍{NC} {msg}")


def log_progress(msg):
    sys.stdout.write(f"\r{BLUE}⏳{NC} {msg}")
    sys.stdout.flush()


def log_trace(msg):
    if VERBOSE:
        print(f"{CYAN}TRACE: {msg}{NC}", file=sys.stderr)


################################################################################
# Utility Functions
################################################################################

def today():
    """Return today's date in YYYY-MM-DD format."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def rand_between(min_v, max_v):
    """Return a random integer between min_v and max_v (inclusive)."""
    return random.randint(min_v, max_v)


def date_with_offset(offset_days, fallback=None):
    """
    Return a date string with offset from today.
    Format: YYYY-MM-DDTHH:MM:SSZ
    """
    try:
        dt = datetime.now(timezone.utc) + timedelta(days=int(offset_days))
        return dt.strftime("%Y-%m-%dT00:00:00Z")
    except Exception:
        return fallback or datetime.now(timezone.utc).strftime("%Y-%m-%dT00:00:00Z")


################################################################################
# API Functions
################################################################################

def api_call(method, endpoint, data=None):
    """
    Perform a JSON API call to BASE_URL + endpoint.
    Returns dict response or {} on error. Updates FAILED_REQUESTS on error.
    In DRY_RUN, returns a simulated response with a generated id.
    """
    global FAILED_REQUESTS, TOKEN

    url = BASE_URL + endpoint
    headers = {"Content-Type": "application/json"}
    if TOKEN:
        headers["Authorization"] = f"Bearer {TOKEN}"

    if DRY_RUN:
        log_debug(f"DRY-RUN: {method} {endpoint}")
        return {"data": {"id": f"dry-run-id-{random.randint(1000, 9999)}"}}

    if requests is None:
        log_error("requests library not installed. Install with `pip install requests` or run in DRY-RUN.")
        FAILED_REQUESTS += 1
        return {}

    try:
        if method.upper() == "GET":
            r = requests.get(url, headers=headers, timeout=30)
        elif method.upper() == "POST":
            r = requests.post(url, headers=headers, json=data, timeout=30)
        elif method.upper() == "PUT":
            r = requests.put(url, headers=headers, json=data, timeout=30)
        else:
            r = requests.request(method, url, headers=headers, json=data, timeout=30)

        log_trace(f"{method} {endpoint} -> HTTP {r.status_code}")

        if not (200 <= r.status_code < 300):
            log_trace(f"Response body: {r.text}")
            log_debug(f"API Error ({r.status_code}): {method} {endpoint}")
            FAILED_REQUESTS += 1
            return {}

        return r.json()
    except Exception as e:
        log_trace(f"API request failed: {e}")
        log_debug(f"API Error: {method} {endpoint} - {e}")
        FAILED_REQUESTS += 1
        return {}


def extract_id(response):
    """Extract ID from API response."""
    try:
        return (response.get("data") or {}).get("id") or ""
    except Exception:
        return ""


################################################################################
# Database Functions
################################################################################

def ensure_db_user():
    """Ensure database user exists."""
    log_info("Ensuring database user exists...")

    if DRY_RUN:
        log_debug("DRY-RUN: would run sudo -u postgres psql -c 'CREATE USER ...'")
        log_warning("DRY-RUN: DB user creation simulated")
        return

    try:
        cmd = [
            "sudo", "-u", "postgres", "psql", "-c",
            f"CREATE USER {DB_USER} WITH PASSWORD '{DB_PASSWORD}' SUPERUSER;"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0:
            log_success("Database user created")
        else:
            log_warning("Database user already exists (or creation failed)")
    except Exception as e:
        log_warning(f"Unable to ensure DB user: {e}")


################################################################################
# Server Functions
################################################################################

def check_server():
    """Check server health."""
    log_info(f"Checking server health at {SERVER_URL}...")

    if DRY_RUN:
        log_debug("DRY-RUN: skipping actual health check")
        log_success("Server is healthy (DRY-RUN)")
        return

    if requests is None:
        log_error("requests library not installed.")
        sys.exit(1)

    try:
        r = requests.get(f"{SERVER_URL}/health", timeout=10)
        if r.status_code != 200:
            log_error(f"Server is not responding at {SERVER_URL}")
            log_error("Make sure the server is running: make start")
            sys.exit(1)
        log_success("Server is healthy")
    except Exception:
        log_error(f"Server is not responding at {SERVER_URL}")
        log_error("Make sure the server is running: make start")
        sys.exit(1)


def login():
    """Login and get token."""
    global TOKEN

    log_info(f"Logging in as {API_USERNAME}...")

    if DRY_RUN:
        TOKEN = f"dry-run-token-{uuid.uuid4().hex[:8]}"
        log_success("DRY-RUN: Logged in successfully")
        return

    if requests is None:
        log_error("requests library not installed.")
        sys.exit(1)

    try:
        r = requests.post(
            f"{BASE_URL}/login",
            headers={"Content-Type": "application/json"},
            json={"username": API_USERNAME, "password": API_PASSWORD},
            timeout=30
        )
        response = r.json()
        TOKEN = (response.get("data") or {}).get("token", "")

        if not TOKEN:
            log_error("Login failed!")
            log_error(f"Response: {response}")
            log_error(f"Make sure user '{API_USERNAME}' exists and password is correct")
            sys.exit(1)

        log_success("Logged in successfully")
    except Exception as e:
        log_error(f"Login failed: {e}")
        sys.exit(1)


################################################################################
# Data Creation Functions
################################################################################

def create_roles():
    """Create roles if needed (admin, operador, visualizador)."""
    log_info("Ensuring roles exist...")

    roles = [
        ("admin", "Administrador", "Acesso administrativo"),
        ("operador", "Operador", "Acesso operacional"),
        ("visualizador", "Visualizador", "Acesso somente leitura"),
    ]

    for name, display_name, description in roles:
        response = api_call("POST", "/roles", {
            "name": name,
            "display_name": display_name,
            "description": description
        })
        log_debug(f"Role {name}: {response}")

    log_success("Roles ensured (admin, operador, visualizador)")


def create_users():
    """Create users and assign roles."""
    global USER_IDS

    log_info("Creating users...")

    users = [
        ("admin", "Administrador", "Admin123!@#", "admin"),
        ("operador", "Operador", "Operador123!@#", "operador"),
        ("visual", "Visualizador", "Visual123!@#", "visualizador"),
    ]

    USER_IDS = []

    for username, display_name, password, role in users:
        response = api_call("POST", "/users", {
            "username": username,
            "display_name": display_name,
            "password": password,
            "role": role,
            "email": f"{username}@example.com"
        })
        uid = extract_id(response)
        if uid:
            USER_IDS.append(uid)
            log_debug(f"Created user: {username} ({uid})")
        else:
            log_debug(f"Failed to create user: {username}")

    log_success("Created users (admin, operador, visualizador)")


def create_categories():
    """Create categories."""
    global CREATED_CATEGORIES, CATEGORY_IDS

    log_info("Creating 30 categories...")

    categories = [
        "Software", "Hardware", "Infraestrutura", "Cloud Computing", "Segurança da Informação",
        "Redes", "Banco de Dados", "ERP", "CRM", "Business Intelligence",
        "Desenvolvimento Mobile", "Desenvolvimento Web", "Desktop", "DevOps", "Suporte Técnico",
        "Consultoria TI", "Treinamento", "Manutenção", "Licenciamento", "SaaS",
        "Telecomunicações", "IoT", "Automação Industrial", "Integração de Sistemas", "Analytics",
        "Data Science", "Machine Learning", "Backup e Recuperação", "Virtualização", "Monitoramento"
    ]

    CATEGORY_IDS = []

    for i, category in enumerate(categories):
        category_name = f"{category}-{TIMESTAMP}"
        response = api_call("POST", "/categories", {"name": category_name})
        cid = extract_id(response)

        if cid:
            CATEGORY_IDS.append(cid)
            CREATED_CATEGORIES += 1
            log_debug(f"Created category: {category_name} ({cid})")
        else:
            log_debug(f"Failed to create category: {category_name}")

        log_progress(f"Categories: {CREATED_CATEGORIES}/30")

    print()
    log_success(f"Created {CREATED_CATEGORIES} categories")


def create_subcategories():
    """Create subcategories (2-3 per category)."""
    global CREATED_SUBCATEGORIES, SUBCATEGORY_IDS

    log_info("Creating subcategories (2-3 per category)...")

    subcategory_templates = [
        "Básico", "Intermediário", "Avançado", "Enterprise", "Premium",
        "Standard", "Professional", "Ultimate", "Starter", "Growth",
        "Mensal", "Anual", "Trimestral", "Semestral", "Personalizado"
    ]

    SUBCATEGORY_IDS = []

    if not CATEGORY_IDS:
        log_error("No categories created! Cannot proceed with subcategories.")
        return

    for i, cat_id in enumerate(CATEGORY_IDS):
        subs_for_cat = 2 + (i % 2)  # 2 or 3 subcategories per category

        for j in range(subs_for_cat):
            template_idx = (i * 3 + j) % len(subcategory_templates)
            name = subcategory_templates[template_idx]

            response = api_call("POST", "/subcategories", {
                "name": name,
                "category_id": cat_id
            })
            sid = extract_id(response)

            if sid:
                SUBCATEGORY_IDS.append(sid)
                CREATED_SUBCATEGORIES += 1
                log_debug(f"Created subcategory: {name} ({sid})")

        log_progress(f"Subcategories: {CREATED_SUBCATEGORIES}")

    print()
    log_success(f"Created {CREATED_SUBCATEGORIES} subcategories")


def create_clients():
    """Create 120 clients (including archived ones)."""
    global CREATED_CLIENTS, CLIENT_IDS

    log_info("Creating 120 clients (incluindo arquivados)...")

    first_names = [
        "João", "Maria", "Pedro", "Ana", "Carlos", "Fernanda", "Lucas", "Julia", "Marcos", "Patricia",
        "Rafael", "Camila", "Bruno", "Leticia", "Diego", "Amanda", "Gustavo", "Bruna", "Felipe", "Larissa",
        "Ricardo", "Daniela", "Eduardo", "Vanessa", "Thiago"
    ]
    last_names = [
        "Silva", "Santos", "Oliveira", "Souza", "Rodrigues", "Ferreira", "Alves", "Pereira", "Lima", "Gomes",
        "Costa", "Ribeiro", "Martins", "Carvalho", "Almeida", "Lopes", "Soares", "Fernandes", "Vieira", "Barbosa",
        "Rocha", "Dias", "Nascimento", "Andrade", "Moreira"
    ]
    companies = [
        "Tech Solutions", "Inovação Digital", "Sistemas Integrados", "Data Corp", "Cloud Services",
        "Software House", "Digital Labs", "Smart Systems", "Info Tech", "Byte Solutions",
        "Net Systems", "Code Factory", "Dev House", "IT Solutions", "Cyber Systems"
    ]
    cities = [
        "São Paulo", "Rio de Janeiro", "Belo Horizonte", "Curitiba", "Porto Alegre",
        "Salvador", "Brasília", "Fortaleza", "Recife", "Manaus"
    ]

    CLIENT_IDS = []
    current_year = datetime.now(timezone.utc).year
    total_clients = 120
    today_str = today()
    today_month = int(today_str[5:7])
    today_day = int(today_str[8:10])

    for i in range(1, total_clients + 1):
        fname = random.choice(first_names)
        lname = random.choice(last_names)
        company = random.choice(companies)
        city = random.choice(cities)

        name = f"{company} - {fname} {lname}"
        phone = "11" + f"{random.randint(0, 999999999):09d}"
        notes = "Cliente criado via populate.py"

        if i % 12 == 0:
            notes += " | Aniversariante hoje"
        if i % 10 == 0:
            notes += " | VIP"

        # Generate birth date
        birth_year = current_year - 18 - random.randint(0, 44)
        birth_month = random.randint(1, 12)
        birth_day = random.randint(1, 28)

        # Some clients have birthday today
        if i % 12 == 0:
            birth_month = today_month
            birth_day = today_day

        birth_date = f"{birth_year:04d}-{birth_month:02d}-{birth_day:02d}T00:00:00Z"

        # 10% of clients will be archived
        archived_at = None
        if i % 10 == 1:
            archived_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT00:00:00Z")

        payload = {
            "name": name,
            "nickname": f"{fname} {lname}",
            "email": f"client{i}_{TIMESTAMP}@example.com",
            "phone": phone,
            "address": f"Rua das Empresas, {i}00 - {city}",
            "birth_date": birth_date,
            "notes": notes
        }

        if archived_at:
            payload["archived_at"] = archived_at

        response = api_call("POST", "/clients", payload)
        cid = extract_id(response)

        if cid:
            CLIENT_IDS.append(cid)
            CREATED_CLIENTS += 1
            log_debug(f"Created client: {name} ({cid})")
        else:
            log_debug(f"Failed to create client: {name}")

        log_progress(f"Clients: {CREATED_CLIENTS}/{total_clients}")

    print()
    log_success(f"Created {CREATED_CLIENTS} clients (incluindo arquivados)")


def create_affiliates():
    """Create affiliates (0 to 5 per client)."""
    global CREATED_AFFILIATES, AFFILIATE_IDS, CLIENT_AFFILIATES_LIST

    log_info("Creating affiliates (0 a 5 por cliente)...")

    affiliate_types = ["Matriz", "Filial", "Escritório", "Unidade", "Departamento", "Setor", "Centro", "Polo"]
    cities = [
        "São Paulo", "Rio de Janeiro", "Belo Horizonte", "Curitiba", "Porto Alegre",
        "Salvador", "Brasília", "Fortaleza", "Recife", "Campinas"
    ]

    AFFILIATE_IDS = []
    CLIENT_AFFILIATES_LIST = []
    current_year = datetime.now(timezone.utc).year

    for i, client_id in enumerate(CLIENT_IDS):
        num_affiliates = random.randint(0, 5)  # 0 to 5 affiliates per client
        client_affiliates = []

        for j in range(1, num_affiliates + 1):
            aff_type = random.choice(affiliate_types)
            city = random.choice(cities)
            name = f"{aff_type} {city} {j}"
            phone = "11" + f"{random.randint(0, 999999999):09d}"

            birth_year = current_year - 25 - (i % 30)
            birth_month = ((i + j) % 12) + 1
            birth_day = ((i + j) % 28) + 1
            birth_date = f"{birth_year:04d}-{birth_month:02d}-{birth_day:02d}T00:00:00Z"

            payload = {
                "name": name,
                "description": f"{aff_type} localizada em {city}",
                "email": f"affiliate{i}_{j}_{TIMESTAMP}@example.com",
                "phone": phone,
                "address": f"Av. Principal, {i}{j}0 - {city}",
                "birth_date": birth_date
            }

            response = api_call("POST", f"/clients/{client_id}/affiliates", payload)
            aid = extract_id(response)

            if aid:
                AFFILIATE_IDS.append(aid)
                client_affiliates.append(aid)
                CREATED_AFFILIATES += 1
                log_debug(f"Created affiliate: {name} ({aid})")
            else:
                log_debug(f"Failed to create affiliate: {name} - skipping this one")

        CLIENT_AFFILIATES_LIST.append(",".join(client_affiliates))
        log_progress(f"Affiliates: {CREATED_AFFILIATES}")

    print()
    log_success(f"Created {CREATED_AFFILIATES} affiliates")


def create_contracts():
    """Create contracts with varied counts per client."""
    global CREATED_CONTRACTS, CONTRACT_IDS, FINANCIAL_IDS

    log_info("Creating contracts with varied counts per client...")

    models = [
        "Contrato de Serviço", "Contrato de Suporte", "Contrato de Licença",
        "Contrato de Manutenção", "Contrato de Consultoria", "Contrato SLA",
        "Contrato de Desenvolvimento", "Contrato de Hospedagem",
        "Contrato de Monitoramento", "Contrato de Backup", "Contrato de Segurança"
    ]

    if not SUBCATEGORY_IDS:
        log_error("No subcategories created! Cannot proceed with contracts.")
        return

    CONTRACT_IDS = []
    FINANCIAL_IDS = []
    current_date = datetime.now(timezone.utc).strftime("%Y-%m-%dT00:00:00Z")

    for i, client_id in enumerate(CLIENT_IDS):
        sub_idx = random.randint(0, len(SUBCATEGORY_IDS) - 1)
        subcategory_id = SUBCATEGORY_IDS[sub_idx]

        # Select affiliate (mixed: 50% chance to have affiliate)
        affiliate_id = None
        client_affiliates_raw = CLIENT_AFFILIATES_LIST[i] if i < len(CLIENT_AFFILIATES_LIST) else ""
        client_affiliates = [a for a in client_affiliates_raw.split(",") if a]

        if client_affiliates and random.randint(0, 1) == 0:
            affiliate_id = random.choice(client_affiliates)

        # Determine number of contracts for this client
        if (i + 1) % 20 == 0:
            contracts_for_client = 0
        elif (i + 1) % 15 == 0:
            contracts_for_client = 5
        else:
            contracts_for_client = 1 + random.randint(0, 3)

        # Ensure at least 10 contracts expiring soon (first 10 clients)
        expiring_soon = 1 if i < 10 else 0

        if contracts_for_client == 0:
            log_debug(f"Client {client_id} with 0 contracts")
            continue

        for c in range(1, contracts_for_client + 1):
            model = random.choice(models)
            item_key = f"CTR-{(i + 1):04d}-{c:02d}-{TIMESTAMP}"

            status_roll = random.randint(0, 99)

            if expiring_soon:
                start_offset = -rand_between(120, 360)
                # Expires soon: between today+3 and today+15
                end_offset = rand_between(3, 15)
            elif status_roll < 30:
                start_offset = -rand_between(365, 900)
                end_offset = -rand_between(30, 180)
            elif status_roll < 75:
                start_offset = -rand_between(120, 360)
                end_offset = rand_between(30, 360)
            else:
                start_offset = rand_between(30, 180)
                end_offset = start_offset + rand_between(90, 540)

            start_date = date_with_offset(start_offset, current_date)
            end_date = date_with_offset(end_offset, "2026-12-31T00:00:00Z")

            payload = {
                "client_id": client_id,
                "subcategory_id": subcategory_id,
                "model": model,
                "item_key": item_key,
                "start_date": start_date,
                "end_date": end_date
            }

            if affiliate_id:
                payload["affiliate_id"] = affiliate_id

            response = api_call("POST", "/contracts", payload)
            contract_id = extract_id(response)

            if contract_id:
                CONTRACT_IDS.append(contract_id)
                CREATED_CONTRACTS += 1
                log_debug(f"Created contract: {item_key} ({contract_id})")

                # Get financial for the contract
                financial_response = api_call("GET", f"/contracts/{contract_id}/financial")
                financial_id = extract_id(financial_response)

                if financial_id:
                    FINANCIAL_IDS.append(financial_id)
                    log_debug(f"Contract {contract_id} has financial {financial_id}")
                else:
                    FINANCIAL_IDS.append("")
                    log_debug(f"Contract {contract_id} has no financial")
            else:
                log_debug(f"Failed to create contract: {item_key}")
                FINANCIAL_IDS.append("")

            log_progress(f"Contracts: {CREATED_CONTRACTS}")

    print()
    log_success(f"Created {CREATED_CONTRACTS} contracts")


def create_financials_with_installments():
    """Create financial records with installments."""
    global CREATED_INSTALLMENTS, MARKED_PAID, FINANCIAL_IDS

    log_info("Creating financial records with installments...")

    recurrence_types = ["mensal", "trimestral", "semestral", "anual"]

    for i, contract_id in enumerate(CONTRACT_IDS):
        if not contract_id:
            continue

        # Determine financial type (mix of unico, personalizado, recorrente)
        type_roll = random.randint(0, 99)
        if type_roll < 35:
            financial_type = "unico"
        elif type_roll < 70:
            financial_type = "personalizado"
        else:
            financial_type = "recorrente"

        base_value = 300 + random.randint(0, 39) * 50
        description = f"Plano de Pagamento - Contrato {i + 1}"

        if financial_type == "unico":
            client_value = base_value
            received_value = client_value * 80 // 100

            payload = {
                "contract_id": contract_id,
                "financial_type": financial_type,
                "client_value": client_value,
                "received_value": received_value,
                "description": description
            }

            response = api_call("POST", "/financial", payload)
            financial_id = extract_id(response)

            if financial_id:
                FINANCIAL_IDS.append(financial_id)
                log_debug(f"Created financial (unico): {description} ({financial_id})")
            else:
                log_debug(f"Failed to create financial (unico) for contract {contract_id}")

        elif financial_type == "recorrente":
            client_value = base_value
            received_value = client_value * 80 // 100
            recurrence_type = random.choice(recurrence_types)
            due_day = random.randint(1, 28)

            payload = {
                "contract_id": contract_id,
                "financial_type": financial_type,
                "recurrence_type": recurrence_type,
                "due_day": due_day,
                "client_value": client_value,
                "received_value": received_value,
                "description": description
            }

            response = api_call("POST", "/financial", payload)
            financial_id = extract_id(response)

            if financial_id:
                FINANCIAL_IDS.append(financial_id)
                log_debug(f"Created financial (recorrente): {description} ({financial_id})")
            else:
                log_debug(f"Failed to create financial (recorrente) for contract {contract_id}")

        else:  # personalizado
            num_installments = rand_between(3, 12)
            installments = []
            base_due_offset = -120 + random.randint(0, 89)

            for inst in range(num_installments):
                if inst == 0:
                    label = "Entrada"
                else:
                    label = f"Parcela {inst}"

                client_value = base_value + (inst * 40)
                received_value = client_value * 80 // 100
                jitter = random.randint(-3, 3)
                due_offset = base_due_offset + inst * 30 + jitter
                due_date = date_with_offset(due_offset, "2025-02-01T00:00:00Z")

                installments.append({
                    "installment_number": inst,
                    "client_value": client_value,
                    "received_value": received_value,
                    "installment_label": label,
                    "due_date": due_date,
                    "notes": f"Parcela {inst}"
                })

            payload = {
                "contract_id": contract_id,
                "financial_type": financial_type,
                "description": description,
                "installments": installments
            }

            response = api_call("POST", "/financial", payload)
            financial_id = extract_id(response)

            if financial_id:
                FINANCIAL_IDS.append(financial_id)
                CREATED_INSTALLMENTS += num_installments
                log_debug(f"Created financial (personalizado) with {num_installments} installments ({financial_id})")

                # Mark some past due installments as paid (stat-only)
                for inst in range(num_installments):
                    due_offset = base_due_offset + inst * 30
                    if due_offset < -30 and random.randint(0, 9) < 6:
                        MARKED_PAID += 1
            else:
                log_debug(f"Failed to create financial (personalizado) for contract {contract_id}")

        log_progress(f"Financial: {len(FINANCIAL_IDS)} (Installments: {CREATED_INSTALLMENTS}, Paid: ~{MARKED_PAID})")

    print()
    log_success(f"Created {len(FINANCIAL_IDS)} financials with {CREATED_INSTALLMENTS} total installments")


################################################################################
# Summary Functions
################################################################################

def print_summary():
    """Print summary of created records."""
    print()
    print("╔════════════════════════════════════════════════════════════════╗")
    print("║              Database Population Summary                       ║")
    print("╚════════════════════════════════════════════════════════════════╝")
    print()
    print("  📊 Created Records:")
    print(f"    ├─ Categories:      {CREATED_CATEGORIES}")
    print(f"    ├─ Subcategories:   {CREATED_SUBCATEGORIES}")
    print(f"    ├─ Clients:         {CREATED_CLIENTS}")
    print(f"    ├─ Affiliates:      {CREATED_AFFILIATES}")
    print(f"    ├─ Contracts:       {CREATED_CONTRACTS}")
    print(f"    ├─ Installments:    {CREATED_INSTALLMENTS}")
    print(f"    └─ Paid:            {MARKED_PAID}")
    print()

    if FAILED_REQUESTS > 0:
        print(f"  ⚠️  Failed Requests:   {FAILED_REQUESTS}")
        print()

    if DRY_RUN:
        log_warning("This was a DRY-RUN. No data was actually created.")
        print()

    print("  ✅ Population complete!")
    print()


def usage():
    """Print usage information."""
    print("""
Usage: python3 populate.py [OPTIONS]

Populates the database with realistic test data using the official APIs.

Options:
  --dry-run         Show what would be created without actually creating
  --verbose         Show verbose debug output
  --help            Show this help message

Environment Variables:
  SERVER_URL        Server base URL (default: http://localhost:3000)
  BASE_URL          API base URL (default: http://localhost:3000/api)
  API_USERNAME      Login username (default: root)
  API_PASSWORD      Login password (default: THIS_IS_A_DEV_ENVIRONMENT_PASSWORD!123abc)
  DB_USER           Database user for ensure_db_user (default: chopuser_dev)
  DB_PASSWORD       Database password (default: THIS_IS_A_DEV_ENVIRONMENT_PASSWORD!123abc)

Data Created:
  - 30 Categories
  - ~75 Subcategories (2-3 per category)
  - 120 Clients (with distributed birthdays, including today's)
  - 0-5 Affiliates per client
  - 0-5 Contracts per client
  - 3-12 Installments per contract (for personalizado type)
  - ~60% of past due installments marked as paid (stat only)

Examples:
  # Populate with defaults
  python3 populate.py

  # Dry run to see what would be created
  python3 populate.py --dry-run

  # Verbose output
  python3 populate.py --verbose

  # Custom server URL
  SERVER_URL=http://api.example.com:3000 BASE_URL=http://api.example.com:3000/api python3 populate.py
""")


################################################################################
# Main Script
################################################################################

def parse_args():
    """Parse command line arguments."""
    global DRY_RUN, VERBOSE

    parser = argparse.ArgumentParser(
        description="Populate the database using the HTTP API.",
        add_help=False
    )
    parser.add_argument("--dry-run", action="store_true", help="Show what would be created")
    parser.add_argument("--verbose", action="store_true", help="Verbose debug output")
    parser.add_argument("--help", "-h", action="store_true", help="Show help message")

    args = parser.parse_args()

    if args.help:
        usage()
        sys.exit(0)

    DRY_RUN = args.dry_run
    VERBOSE = args.verbose


def main():
    """Main entry point."""
    parse_args()

    print()
    print("╔════════════════════════════════════════════════════════════════╗")
    print("║         Client Hub - Database Population Script               ║")
    print("╚════════════════════════════════════════════════════════════════╝")
    print()

    if DRY_RUN:
        log_warning("Running in DRY-RUN mode - no data will be created")
        print()

    log_info(f"Server URL: {SERVER_URL}")
    log_info(f"API URL: {BASE_URL}")
    log_info(f"Timestamp: {TIMESTAMP}")
    print()

    # Step 1: Ensure database user exists
    ensure_db_user()
    print()

    # Step 2: Check server health
    check_server()
    print()

    # Step 3: Login
    login()
    print()

    # Step 4: Create all data
    create_roles()
    print()

    create_users()
    print()

    create_categories()
    print()

    create_subcategories()
    print()

    create_clients()
    print()

    create_affiliates()
    print()

    create_contracts()
    print()

    create_financials_with_installments()
    print()

    # Step 5: Print summary
    print_summary()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print()
        log_warning("Interrupted by user")
        sys.exit(130)
    except Exception as e:
        log_error(f"Script failed: {e}")
        sys.exit(1)
