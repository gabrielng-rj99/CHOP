# =============================================================================
# Client Hub Open Project
# Copyright (C) 2025 Client Hub Contributors
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
# =============================================================================

import pytest
import requests
import time
import os
from typing import Dict, Optional

# Configuração base - usando portas de teste
# Configuração base - usando portas de teste
raw_url = os.getenv("TEST_API_URL", "http://localhost:63000")
BASE_URL = raw_url.rstrip("/")
if BASE_URL.endswith("/api"):
    BASE_URL = BASE_URL[:-4]

API_URL = f"{BASE_URL}/api"

# Armazenamento de tokens e usuários criados
test_data = {
    "tokens": {},
    "users": {},
    "clients": [],
    "contracts": [],
    "categories": [],
    "subcategories": []
}

# Senhas padrão para testes
DEFAULT_ROOT_PASSWORD = os.getenv(
    "TEST_ROOT_PASSWORD",
    "RootPass123!@#456789%%0321654987+-7dfgacvds"
)
DEFAULT_STRONG_PASSWORD = "ValidPass123!@#abc"


@pytest.fixture(scope="session")
def base_url():
    return BASE_URL


@pytest.fixture(scope="session")
def api_url():
    return API_URL


@pytest.fixture(scope="session")
def http_client():
    session = requests.Session()
    session.headers.update({"Content-Type": "application/json"})
    session.timeout = 30
    return session


@pytest.fixture(scope="session")
def root_user(http_client, api_url):
    """Cria ou usa usuário root existente"""
    # Tentar criar root admin (só funciona se banco vazio)
    data = {
        "username": "root",
        "display_name": "Root Admin",
        "password": DEFAULT_ROOT_PASSWORD
    }

    response = http_client.post(f"{api_url}/initialize/admin", json=data)

    if response.status_code == 200:
        result = response.json()
        test_data["users"]["root"] = {
            "username": result.get("admin_username", "root"),
            "password": data["password"],
            "id": result.get("admin_id"),
            "role": "root"
        }
    else:
        # Root já existe, usar credenciais padrão
        test_data["users"]["root"] = {
            "username": "root",
            "password": DEFAULT_ROOT_PASSWORD,
            "role": "root"
        }

    # Fazer login
    login_response = http_client.post(f"{api_url}/login", json={
        "username": test_data["users"]["root"]["username"],
        "password": test_data["users"]["root"]["password"]
    })

    if login_response.status_code == 200:
        tokens = login_response.json()
        # Suporta ambos os formatos de resposta
        access_token = tokens.get("token") or tokens.get("access_token") or tokens.get("data", {}).get("token")
        test_data["tokens"]["root"] = access_token
        test_data["users"]["root"]["token"] = access_token
        test_data["users"]["root"]["id"] = tokens.get("user_id") or tokens.get("data", {}).get("user_id")
    else:
        # Se login falhou, tenta com senha alternativa
        alt_passwords = [
            "RootPass123!@#",
            DEFAULT_STRONG_PASSWORD,
        ]
        for alt_pass in alt_passwords:
            login_response = http_client.post(f"{api_url}/login", json={
                "username": "root",
                "password": alt_pass
            })
            if login_response.status_code == 200:
                tokens = login_response.json()
                access_token = tokens.get("token") or tokens.get("access_token") or tokens.get("data", {}).get("token")
                test_data["tokens"]["root"] = access_token
                test_data["users"]["root"]["token"] = access_token
                test_data["users"]["root"]["password"] = alt_pass
                break

    return test_data["users"]["root"]


@pytest.fixture(scope="session")
def admin_user(http_client, api_url, root_user):
    """Cria usuário admin"""
    if not root_user or "token" not in root_user:
        return None

    headers = {"Authorization": f"Bearer {root_user['token']}"}

    admin_username = f"admin_test_{int(time.time())}"
    data = {
        "username": admin_username,
        "display_name": "Admin Test User",
        "password": DEFAULT_STRONG_PASSWORD,
        "role": "admin"
    }

    response = http_client.post(f"{api_url}/users", json=data, headers=headers)

    if response.status_code in [200, 201]:
        result = response.json()
        user_data = {
            "username": data["username"],
            "password": data["password"],
            "id": result.get("id") or result.get("data", {}).get("id"),
            "role": "admin"
        }

        # Fazer login
        login_response = http_client.post(f"{api_url}/login", json={
            "username": user_data["username"],
            "password": user_data["password"]
        })

        if login_response.status_code == 200:
            tokens = login_response.json()
            access_token = tokens.get("token") or tokens.get("access_token") or tokens.get("data", {}).get("token")
            user_data["token"] = access_token
            test_data["tokens"]["admin"] = access_token
            test_data["users"]["admin"] = user_data

        return user_data

    return None


@pytest.fixture(scope="session")
def regular_user(http_client, api_url, root_user):
    """Cria usuário comum"""
    if not root_user or "token" not in root_user:
        return None

    headers = {"Authorization": f"Bearer {root_user['token']}"}

    user_username = f"user_test_{int(time.time())}"
    data = {
        "username": user_username,
        "display_name": "Regular Test User",
        "password": DEFAULT_STRONG_PASSWORD,
        "role": "user"
    }

    response = http_client.post(f"{api_url}/users", json=data, headers=headers)

    if response.status_code in [200, 201]:
        result = response.json()
        user_data = {
            "username": data["username"],
            "password": data["password"],
            "id": result.get("id") or result.get("data", {}).get("id"),
            "role": "user"
        }

        # Fazer login
        login_response = http_client.post(f"{api_url}/login", json={
            "username": user_data["username"],
            "password": user_data["password"]
        })

        if login_response.status_code == 200:
            tokens = login_response.json()
            access_token = tokens.get("token") or tokens.get("access_token") or tokens.get("data", {}).get("token")
            user_data["token"] = access_token
            test_data["tokens"]["user"] = access_token
            test_data["users"]["user"] = user_data

        return user_data

    return None


@pytest.fixture
def timer():
    """Fixture para medir tempo de testes"""
    start = time.time()
    yield
    duration = time.time() - start
    print(f"\n⏱️  Test duration: {duration:.3f}s")


@pytest.fixture(scope="function")
def test_timing(request):
    """Hook para registrar timing de cada teste"""
    start = time.time()
    yield
    duration = time.time() - start
    # Armazena timing no item do teste para relatórios
    request.node.user_properties.append(("duration", duration))


def pytest_configure(config):
    """Configuração inicial do pytest"""
    config.addinivalue_line(
        "markers", "security: marca testes de segurança"
    )
    config.addinivalue_line(
        "markers", "jwt: marca testes de JWT"
    )
    config.addinivalue_line(
        "markers", "sql_injection: marca testes de SQL injection"
    )
    config.addinivalue_line(
        "markers", "xss: marca testes de XSS"
    )
    config.addinivalue_line(
        "markers", "authorization: marca testes de autorização"
    )
    config.addinivalue_line(
        "markers", "api: marca testes de API"
    )
    config.addinivalue_line(
        "markers", "slow: marca testes lentos"
    )
    config.addinivalue_line(
        "markers", "password: marca testes de validação de senha"
    )
    config.addinivalue_line(
        "markers", "validation: marca testes de validação de entrada"
    )
    config.addinivalue_line(
        "markers", "login_blocking: marca testes de bloqueio de login"
    )
    config.addinivalue_line(
        "markers", "rate_limiting: marca testes de rate limiting"
    )
    config.addinivalue_line(
        "markers", "data_leakage: marca testes de vazamento de dados"
    )
    config.addinivalue_line(
        "markers", "initialization: marca testes de inicialização do sistema"
    )
    config.addinivalue_line(
        "markers", "cors: marca testes de CORS security"
    )
    config.addinivalue_line(
        "markers", "headers: marca testes de HTTP security headers"
    )
    config.addinivalue_line(
        "markers", "concurrency: marca testes de concorrência/race conditions"
    )
    config.addinivalue_line(
        "markers", "database: marca testes de resiliência de banco de dados"
    )
    config.addinivalue_line(
        "markers", "rate_limiting: marca testes de rate limiting"
    )
    config.addinivalue_line(
        "markers", "compliance: marca testes de conformidade AGPL"
    )
    config.addinivalue_line(
        "markers", "input_validation: marca testes de validação de entrada"
    )


def pytest_collection_modifyitems(config, items):
    """Adiciona marcadores automaticamente baseado no nome do arquivo/teste"""
    for item in items:
        # Marcadores baseados no nome do arquivo
        if "test_jwt" in item.nodeid:
            item.add_marker(pytest.mark.jwt)
            item.add_marker(pytest.mark.security)
        if "test_sql" in item.nodeid:
            item.add_marker(pytest.mark.sql_injection)
            item.add_marker(pytest.mark.security)
        if "test_xss" in item.nodeid:
            item.add_marker(pytest.mark.xss)
            item.add_marker(pytest.mark.security)
        if "test_auth" in item.nodeid or "authorization" in item.nodeid:
            item.add_marker(pytest.mark.authorization)
            item.add_marker(pytest.mark.security)
        if "test_password" in item.nodeid:
            item.add_marker(pytest.mark.password)
            item.add_marker(pytest.mark.security)
        if "test_input" in item.nodeid or "test_validation" in item.nodeid:
            item.add_marker(pytest.mark.validation)
        if "test_login_blocking" in item.nodeid:
            item.add_marker(pytest.mark.login_blocking)
            item.add_marker(pytest.mark.security)
        if "test_data_leakage" in item.nodeid:
            item.add_marker(pytest.mark.data_leakage)
            item.add_marker(pytest.mark.security)
        if "test_api" in item.nodeid:
            item.add_marker(pytest.mark.api)
        if "test_initialization" in item.nodeid:
            item.add_marker(pytest.mark.initialization)
            item.add_marker(pytest.mark.security)
        if "cors" in item.nodeid.lower():
            item.add_marker(pytest.mark.cors)
            item.add_marker(pytest.mark.security)
        if "headers" in item.nodeid.lower():
            item.add_marker(pytest.mark.headers)
            item.add_marker(pytest.mark.security)
        if "concurrency" in item.nodeid.lower():
            item.add_marker(pytest.mark.concurrency)
        if "rate_limiting" in item.nodeid.lower():
            item.add_marker(pytest.mark.rate_limiting)
            item.add_marker(pytest.mark.security)


def pytest_terminal_summary(terminalreporter, exitstatus, config):
    """Adiciona sumário customizado ao final dos testes"""
    terminalreporter.write_sep("=", "Test Timing Summary")

    # Coletar timings
    timings = []
    for report in terminalreporter.stats.get("passed", []):
        for prop in report.user_properties:
            if prop[0] == "duration":
                timings.append((report.nodeid, prop[1]))

    for report in terminalreporter.stats.get("failed", []):
        for prop in report.user_properties:
            if prop[0] == "duration":
                timings.append((report.nodeid, prop[1]))

    if timings:
        # Ordenar por duração (mais lentos primeiro)
        timings.sort(key=lambda x: x[1], reverse=True)

        terminalreporter.write_line("\nTop 10 slowest tests:")
        for nodeid, duration in timings[:10]:
            terminalreporter.write_line(f"  {duration:.3f}s - {nodeid}")

        total = sum(t[1] for t in timings)
        terminalreporter.write_line(f"\nTotal measured time: {total:.2f}s")


@pytest.fixture(scope="session", autouse=True)
def setup_teardown(http_client, api_url):
    """Setup e teardown da suite de testes"""
    print(f"\n{'='*70}")
    print(f"🚀 INICIANDO SUITE DE TESTES")
    print(f"{'='*70}")
    print(f"📍 Backend URL: {BASE_URL}")
    print(f"📍 API URL: {api_url}")
    print(f"🔧 Test Environment Ports:")
    print(f"   - Database: 65432")
    print(f"   - Backend: 63000")
    print(f"   - Frontend: 65080")
    print(f"{'='*70}\n")

    # Verificar se backend está online
    try:
        health_response = http_client.get(f"{BASE_URL}/health", timeout=5)
        if health_response.status_code == 200:
            print(f"✅ Backend está online")
        else:
            print(f"⚠️  Backend respondeu com status {health_response.status_code}")
    except Exception as e:
        print(f"❌ Backend não está acessível: {e}")
        print(f"   Certifique-se de que o ambiente de teste está rodando:")
        print(f"   cd tests && docker-compose -f docker-compose.test.yml up -d")

    yield

    print(f"\n{'='*70}")
    print(f"🧹 FINALIZANDO SUITE DE TESTES")
    print(f"{'='*70}\n")


# Fixtures de tokens para testes de segurança
@pytest.fixture(scope="session")
def root_token(root_user):
    """Token do usuário root."""
    if root_user and "token" in root_user:
        return root_user["token"]
    return None


@pytest.fixture(scope="session")
def admin_token(admin_user):
    """Token do usuário admin."""
    if admin_user and "token" in admin_user:
        return admin_user["token"]
    return None


@pytest.fixture(scope="session")
def user_token(regular_user):
    """Token do usuário comum."""
    if regular_user and "token" in regular_user:
        return regular_user["token"]
    return None


# Funções utilitárias para os testes
def get_valid_token(http_client, api_url, username, password):
    """Obtém um token válido para um usuário"""
    response = http_client.post(f"{api_url}/login", json={
        "username": username,
        "password": password
    })
    if response.status_code == 200:
        data = response.json()
        return data.get("token") or data.get("access_token") or data.get("data", {}).get("token")
    return None


def create_test_user(http_client, api_url, admin_token, username, role="user"):
    """Cria um usuário de teste"""
    headers = {"Authorization": f"Bearer {admin_token}"}
    response = http_client.post(f"{api_url}/users", json={
        "username": username,
        "display_name": f"Test {username}",
        "password": DEFAULT_STRONG_PASSWORD,
        "role": role
    }, headers=headers)

    if response.status_code in [200, 201]:
        data = response.json()
        return {
            "id": data.get("id") or data.get("data", {}).get("id"),
            "username": username,
            "password": DEFAULT_STRONG_PASSWORD,
            "role": role
        }
    return None
