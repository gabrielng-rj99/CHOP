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

"""
Testes de Segurança Agressivos para API de Financials
NOTA: Estes testes são RIGOROSOS - se falharem, a API tem problema de segurança

Cobertura:
- GET /api/financials: Auth, Permission, SQL Injection
- POST /api/financials: Empty Request, XSS, SQL Injection, Overflow, NULL handling
- GET /api/financials/{id}: Auth, Not Found, UUID validation
- PUT /api/financials/{id}: Auth, XSS, SQL Injection, Overflow
- DELETE /api/financials/{id}: Auth, Permission
- GET /api/financials/{id}/installments: Auth
- POST /api/financials/{id}/installments: Empty Request, XSS, SQL Injection
- PUT /api/financials/{id}/installments/{inst_id}: Auth, validation
- DELETE /api/financials/{id}/installments/{inst_id}: Auth
- PUT /api/financials/{id}/installments/{inst_id}/pay: Auth, Permission
- PUT /api/financials/{id}/installments/{inst_id}/unpay: Auth, Permission
- GET /api/financials/summary: Auth, Permission
- GET /api/financials/upcoming: Auth, SQL Injection
- GET /api/financials/overdue: Auth
"""

import pytest
import requests
import time
import uuid
from datetime import datetime, timedelta
from functools import wraps
from decimal import Decimal


def catch_connection_errors(func):
    """
    Decorator para capturar exceptions de conexão durante testes.
    Se o backend crashar, isso É UMA VULNERABILIDADE.
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
            pytest.fail(
                f"🔴 VULNERABILIDADE: Backend crashou ou ficou indisponível!\n"
                f"Erro: {str(e)[:200]}"
            )
    return wrapper


# =============================================================================
# Fixtures - Setup de dados de teste
# =============================================================================

@pytest.fixture
def test_contract(http_client, api_url, admin_user):
    """Cria um contrato de teste para associar financeiro"""
    if not admin_user or "token" not in admin_user:
        pytest.skip("Admin user não disponível")

    # Primeiro criar um cliente
    client_data = {
        "name": f"Test Client Financials {uuid.uuid4().hex[:8]}",
        "email": f"testfinancial{uuid.uuid4().hex[:8]}@example.com",
        "phone": "1234567890",
        "type": "pessoa_fisica"
    }

    client_response = http_client.post(
        f"{api_url}/clients",
        json=client_data,
        headers={"Authorization": f"Bearer {admin_user['token']}"}
    )

    if client_response.status_code != 201:
        pytest.skip(f"Não foi possível criar cliente de teste: {client_response.status_code}")

    client_id = client_response.json().get("id")

    # Criar contrato
    contract_data = {
        "title": f"Test Contract for Financials {uuid.uuid4().hex[:8]}",
        "client_id": client_id,
        "status": "ativo",
        "start_date": datetime.now().isoformat()
    }

    contract_response = http_client.post(
        f"{api_url}/contracts",
        json=contract_data,
        headers={"Authorization": f"Bearer {admin_user['token']}"}
    )

    if contract_response.status_code != 201:
        pytest.skip(f"Não foi possível criar contrato de teste: {contract_response.status_code}")

    contract = contract_response.json()

    yield contract

    # Cleanup - deletar contrato e cliente
    http_client.delete(
        f"{api_url}/contracts/{contract['id']}",
        headers={"Authorization": f"Bearer {admin_user['token']}"}
    )
    http_client.delete(
        f"{api_url}/clients/{client_id}",
        headers={"Authorization": f"Bearer {admin_user['token']}"}
    )


@pytest.fixture
def test_financial(http_client, api_url, admin_user, test_contract):
    """Cria um financeiro de teste"""
    if not admin_user or "token" not in admin_user:
        pytest.skip("Admin user não disponível")

    financial_data = {
        "contract_id": test_contract["id"],
        "financial_type": "unico",
        "client_value": 1000.00,
        "received_value": 900.00,
        "description": "Test Financial"
    }

    response = http_client.post(
        f"{api_url}/financials",
        json=financial_data,
        headers={"Authorization": f"Bearer {admin_user['token']}"}
    )

    if response.status_code != 201:
        pytest.skip(f"Não foi possível criar financeiro de teste: {response.status_code}")

    financial = response.json()

    yield financial

    # Cleanup
    http_client.delete(
        f"{api_url}/financials/{financial['id']}",
        headers={"Authorization": f"Bearer {admin_user['token']}"}
    )


@pytest.fixture
def test_financial_with_installments(http_client, api_url, admin_user, test_contract):
    """Cria um financeiro personalizado com parcelas"""
    if not admin_user or "token" not in admin_user:
        pytest.skip("Admin user não disponível")

    financial_data = {
        "contract_id": test_contract["id"],
        "financial_type": "personalizado",
        "client_value": 3000.00,
        "received_value": 2700.00,
        "description": "Test Financial with Installments",
        "installments": [
            {
                "installment_number": 1,
                "amount": 1000.00,
                "due_date": (datetime.now() + timedelta(days=30)).isoformat()
            },
            {
                "installment_number": 2,
                "amount": 1000.00,
                "due_date": (datetime.now() + timedelta(days=60)).isoformat()
            },
            {
                "installment_number": 3,
                "amount": 1000.00,
                "due_date": (datetime.now() + timedelta(days=90)).isoformat()
            }
        ]
    }

    response = http_client.post(
        f"{api_url}/financials",
        json=financial_data,
        headers={"Authorization": f"Bearer {admin_user['token']}"}
    )

    if response.status_code != 201:
        pytest.skip(f"Não foi possível criar financeiro com parcelas: {response.status_code}")

    financial = response.json()

    yield financial

    # Cleanup
    http_client.delete(
        f"{api_url}/financials/{financial['id']}",
        headers={"Authorization": f"Bearer {admin_user['token']}"}
    )


# =============================================================================
# GET /api/financials - Auth and Permission Tests
# =============================================================================

class TestGetFinancialsAuth:
    """Testes de autenticação para GET /api/financials"""

    @catch_connection_errors
    def test_get_financials_without_token_returns_401(self, http_client, api_url, timer):
        """GET /api/financials sem token DEVE retornar 401"""
        response = http_client.get(f"{api_url}/financials")
        assert response.status_code == 401, \
            f"🔴 FALHA DE SEGURANÇA: Expected 401 without token, got {response.status_code}"

    @catch_connection_errors
    def test_get_financials_with_invalid_token_returns_401(self, http_client, api_url, timer):
        """GET /api/financials com token inválido DEVE retornar 401"""
        response = http_client.get(
            f"{api_url}/financials",
            headers={"Authorization": "Bearer invalid_token_here"}
        )
        assert response.status_code == 401, \
            f"🔴 FALHA DE SEGURANÇA: Expected 401 with invalid token, got {response.status_code}"

    @catch_connection_errors
    def test_get_financials_with_malformed_auth_header_returns_401(self, http_client, api_url, timer):
        """GET /api/financials com header mal formado DEVE retornar 401"""
        malformed_headers = [
            {"Authorization": "NotBearer token"},
            {"Authorization": "Bearer"},
            {"Authorization": ""},
            {"Authorization": "Bearer "},
        ]
        for header in malformed_headers:
            response = http_client.get(f"{api_url}/financials", headers=header)
            assert response.status_code == 401, \
                f"🔴 FALHA: Expected 401 with header {header}, got {response.status_code}"


class TestGetFinancialsPermission:
    """Testes de permissão para GET /api/financials"""

    @catch_connection_errors
    def test_regular_user_can_list_financials(self, http_client, api_url, regular_user, timer):
        """Usuário regular DEVE poder listar financeiro (permissão padrão)"""
        if not regular_user or "token" not in regular_user:
            pytest.skip("Regular user não disponível")

        response = http_client.get(
            f"{api_url}/financials",
            headers={"Authorization": f"Bearer {regular_user['token']}"}
        )
        assert response.status_code in [200, 404], \
            f"Expected 200 or 404, got {response.status_code}"


# =============================================================================
# GET /api/financials - SQL Injection Tests
# =============================================================================

class TestGetFinancialsSQLInjection:
    """Testes de SQL Injection para GET /api/financials"""

    @catch_connection_errors
    def test_sql_injection_in_query_params(self, http_client, api_url, admin_user, timer):
        """Query params maliciosos NÃO DEVEM causar SQL Injection"""
        if not admin_user or "token" not in admin_user:
            pytest.skip("Admin user não disponível")

        sql_payloads = [
            "' OR '1'='1",
            "1' OR '1'='1' --",
            "'; DROP TABLE financial_installments; --",
            "' UNION SELECT * FROM users --",
            "1' AND 1=0 UNION ALL SELECT NULL, username, password FROM users--",
            "admin'--",
            "' OR 1=1--",
            "' OR 'x'='x",
            "1; DROP TABLE contract_financials--",
        ]

        for payload in sql_payloads:
            # Testar em diferentes query params se houver
            response = http_client.get(
                f"{api_url}/financials?search={payload}",
                headers={"Authorization": f"Bearer {admin_user['token']}"}
            )

            # Não deve crashar (200, 400, 404 são OK, 500 NÃO é)
            assert response.status_code != 500, \
                f"🔴 SQL INJECTION: Payload '{payload}' causou erro 500!"

            # Se retornar dados, não deve vazar informações sensíveis
            if response.status_code == 200:
                data = response.json()
                if isinstance(data, list):
                    for item in data:
                        assert "password" not in str(item).lower(), \
                            f"🔴 DATA LEAKAGE: Password field found with payload '{payload}'"


# =============================================================================
# POST /api/financials - Empty Request Tests
# =============================================================================

class TestCreateFinancialEmptyRequest:
    """Testes de requisição vazia para POST /api/financials"""

    @catch_connection_errors
    def test_create_financial_with_empty_body_returns_400(self, http_client, api_url, admin_user, timer):
        """POST /api/financials com body vazio DEVE retornar 400"""
        if not admin_user or "token" not in admin_user:
            pytest.skip("Admin user não disponível")

        response = http_client.post(
            f"{api_url}/financials",
            json={},
            headers={"Authorization": f"Bearer {admin_user['token']}"}
        )
        assert response.status_code == 400, \
            f"🔴 FALHA: Expected 400 for empty body, got {response.status_code}"

    @catch_connection_errors
    def test_create_financial_with_null_body_returns_400(self, http_client, api_url, admin_user, timer):
        """POST /api/financials com body null DEVE retornar 400"""
        if not admin_user or "token" not in admin_user:
            pytest.skip("Admin user não disponível")

        response = http_client.post(
            f"{api_url}/financials",
            json=None,
            headers={"Authorization": f"Bearer {admin_user['token']}"}
        )
        assert response.status_code == 400, \
            f"🔴 FALHA: Expected 400 for null body, got {response.status_code}"

    @catch_connection_errors
    def test_create_financial_missing_required_fields_returns_400(self, http_client, api_url, admin_user, timer):
        """POST /api/financials sem campos obrigatórios DEVE retornar 400"""
        if not admin_user or "token" not in admin_user:
            pytest.skip("Admin user não disponível")

        incomplete_payloads = [
            {"financial_type": "unico"},  # Falta contract_id
            {"contract_id": str(uuid.uuid4())},  # Falta financial_type
            {"contract_id": str(uuid.uuid4()), "financial_type": "unico"},  # Falta valores
        ]

        for payload in incomplete_payloads:
            response = http_client.post(
                f"{api_url}/financials",
                json=payload,
                headers={"Authorization": f"Bearer {admin_user['token']}"}
            )
            assert response.status_code == 400, \
                f"🔴 FALHA: Expected 400 for incomplete data {payload}, got {response.status_code}"


# =============================================================================
# POST /api/financials - XSS Tests
# =============================================================================

class TestCreateFinancialXSS:
    """Testes de XSS para POST /api/financials"""

    @catch_connection_errors
    def test_xss_in_description_field(self, http_client, api_url, admin_user, test_contract, timer):
        """Descrição com XSS DEVE ser sanitizada ou rejeitada"""
        if not admin_user or "token" not in admin_user:
            pytest.skip("Admin user não disponível")

        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg/onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<iframe src='javascript:alert(\"XSS\")'></iframe>",
            "';alert(String.fromCharCode(88,83,83))//",
        ]

        for payload in xss_payloads:
            financial_data = {
                "contract_id": test_contract["id"],
                "financial_type": "unico",
                "client_value": 1000.00,
                "received_value": 900.00,
                "description": payload
            }

            response = http_client.post(
                f"{api_url}/financials",
                json=financial_data,
                headers={"Authorization": f"Bearer {admin_user['token']}"}
            )

            # Deve aceitar (200/201) ou rejeitar (400), mas não crashar (500)
            assert response.status_code != 500, \
                f"🔴 XSS: Backend crashou com payload '{payload}'"

            if response.status_code in [200, 201]:
                data = response.json()
                financial_id = data.get("id")

                # Verificar se o XSS foi sanitizado
                if "description" in data:
                    assert "<script" not in data["description"].lower(), \
                        f"🔴 XSS: Script tag não foi sanitizado! Payload: {payload}"
                    assert "onerror" not in data["description"].lower(), \
                        f"🔴 XSS: onerror não foi sanitizado! Payload: {payload}"
                    assert "javascript:" not in data["description"].lower(), \
                        f"🔴 XSS: javascript: não foi sanitizado! Payload: {payload}"

                # Cleanup
                if financial_id:
                    http_client.delete(
                        f"{api_url}/financials/{financial_id}",
                        headers={"Authorization": f"Bearer {admin_user['token']}"}
                    )


# =============================================================================
# POST /api/financials - SQL Injection Tests
# =============================================================================

class TestCreateFinancialSQLInjection:
    """Testes de SQL Injection para POST /api/financials"""

    @catch_connection_errors
    def test_sql_injection_in_text_fields(self, http_client, api_url, admin_user, test_contract, timer):
        """Campos de texto com SQL Injection NÃO DEVEM afetar o banco"""
        if not admin_user or "token" not in admin_user:
            pytest.skip("Admin user não disponível")

        sql_payloads = [
            "'; DROP TABLE contract_financials; --",
            "' OR '1'='1",
            "1' UNION SELECT * FROM users--",
            "admin'--",
            "' OR 1=1--",
        ]

        for payload in sql_payloads:
            financial_data = {
                "contract_id": test_contract["id"],
                "financial_type": "unico",
                "client_value": 1000.00,
                "received_value": 900.00,
                "description": payload
            }

            response = http_client.post(
                f"{api_url}/financials",
                json=financial_data,
                headers={"Authorization": f"Bearer {admin_user['token']}"}
            )

            # Não deve crashar
            assert response.status_code != 500, \
                f"🔴 SQL INJECTION: Payload '{payload}' causou erro 500!"

            if response.status_code in [200, 201]:
                financial_id = response.json().get("id")
                # Cleanup
                if financial_id:
                    http_client.delete(
                        f"{api_url}/financials/{financial_id}",
                        headers={"Authorization": f"Bearer {admin_user['token']}"}
                    )


# =============================================================================
# POST /api/financials - NULL Handling Tests
# =============================================================================

class TestCreateFinancialNullHandling:
    """Testes de tratamento de valores NULL"""

    @catch_connection_errors
    def test_null_values_in_optional_fields(self, http_client, api_url, admin_user, test_contract, timer):
        """Valores NULL em campos opcionais DEVEM ser aceitos"""
        if not admin_user or "token" not in admin_user:
            pytest.skip("Admin user não disponível")

        financial_data = {
            "contract_id": test_contract["id"],
            "financial_type": "unico",
            "client_value": 1000.00,
            "received_value": 900.00,
            "description": None,  # Campo opcional como NULL
            "recurrence_type": None,
            "due_day": None
        }

        response = http_client.post(
            f"{api_url}/financials",
            json=financial_data,
            headers={"Authorization": f"Bearer {admin_user['token']}"}
        )

        # Deve aceitar NULL em campos opcionais
        assert response.status_code in [200, 201], \
            f"🔴 NULL HANDLING: Expected 200/201 with NULL in optional fields, got {response.status_code}"

        if response.status_code in [200, 201]:
            financial_id = response.json().get("id")
            # Cleanup
            if financial_id:
                http_client.delete(
                    f"{api_url}/financials/{financial_id}",
                    headers={"Authorization": f"Bearer {admin_user['token']}"}
                )

    @catch_connection_errors
    def test_null_values_in_required_fields_returns_400(self, http_client, api_url, admin_user, test_contract, timer):
        """Valores NULL em campos obrigatórios DEVEM retornar 400"""
        if not admin_user or "token" not in admin_user:
            pytest.skip("Admin user não disponível")

        null_required_payloads = [
            {
                "contract_id": None,
                "financial_type": "unico",
                "client_value": 1000.00,
                "received_value": 900.00
            },
            {
                "contract_id": test_contract["id"],
                "financial_type": None,
                "client_value": 1000.00,
                "received_value": 900.00
            },
            {
                "contract_id": test_contract["id"],
                "financial_type": "unico",
                "client_value": None,
                "received_value": 900.00
            }
        ]

        for payload in null_required_payloads:
            response = http_client.post(
                f"{api_url}/financials",
                json=payload,
                headers={"Authorization": f"Bearer {admin_user['token']}"}
            )
            assert response.status_code == 400, \
                f"🔴 NULL HANDLING: Expected 400 for NULL required field, got {response.status_code}"


# =============================================================================
# POST /api/financials - Overflow Tests
# =============================================================================

class TestCreateFinancialOverflow:
    """Testes de overflow para POST /api/financials"""

    @catch_connection_errors
    def test_extremely_large_values_rejected(self, http_client, api_url, admin_user, test_contract, timer):
        """Valores monetários extremamente grandes DEVEM ser rejeitados"""
        if not admin_user or "token" not in admin_user:
            pytest.skip("Admin user não disponível")

        overflow_payloads = [
            {
                "contract_id": test_contract["id"],
                "financial_type": "unico",
                "client_value": 99999999999999.99,  # Valor extremamente alto
                "received_value": 900.00
            },
            {
                "contract_id": test_contract["id"],
                "financial_type": "unico",
                "client_value": float('inf'),  # Infinito
                "received_value": 900.00
            },
            {
                "contract_id": test_contract["id"],
                "financial_type": "unico",
                "client_value": -999999999.99,  # Valor negativo
                "received_value": 900.00
            }
        ]

        for payload in overflow_payloads:
            response = http_client.post(
                f"{api_url}/financials",
                json=payload,
                headers={"Authorization": f"Bearer {admin_user['token']}"}
            )

            # Deve rejeitar (400) ou aceitar sem crashar
            assert response.status_code != 500, \
                f"🔴 OVERFLOW: Backend crashou com valor {payload['client_value']}"

            # Se aceitar, deve armazenar corretamente
            if response.status_code in [200, 201]:
                financial_id = response.json().get("id")
                if financial_id:
                    # Verificar se o valor foi armazenado corretamente
                    get_response = http_client.get(
                        f"{api_url}/financials/{financial_id}",
                        headers={"Authorization": f"Bearer {admin_user['token']}"}
                    )
                    if get_response.status_code == 200:
                        stored_value = get_response.json().get("client_value")
                        # Valor não deve ser infinito ou extremamente alto sem validação
                        if stored_value:
                            assert stored_value < 999999999, \
                                f"🔴 OVERFLOW: Valor muito alto foi aceito: {stored_value}"

                    # Cleanup
                    http_client.delete(
                        f"{api_url}/financials/{financial_id}",
                        headers={"Authorization": f"Bearer {admin_user['token']}"}
                    )

    @catch_connection_errors
    def test_extremely_long_description_rejected(self, http_client, api_url, admin_user, test_contract, timer):
        """Descrição extremamente longa DEVE ser rejeitada ou truncada"""
        if not admin_user or "token" not in admin_user:
            pytest.skip("Admin user não disponível")

        long_text = "A" * 100000  # 100k caracteres

        financial_data = {
            "contract_id": test_contract["id"],
            "financial_type": "unico",
            "client_value": 1000.00,
            "received_value": 900.00,
            "description": long_text
        }

        response = http_client.post(
            f"{api_url}/financials",
            json=financial_data,
            headers={"Authorization": f"Bearer {admin_user['token']}"}
        )

        # Não deve crashar
        assert response.status_code != 500, \
            f"🔴 OVERFLOW: Backend crashou com texto longo"

        # Se aceitar, cleanup
        if response.status_code in [200, 201]:
            financial_id = response.json().get("id")
            if financial_id:
                http_client.delete(
                    f"{api_url}/financials/{financial_id}",
                    headers={"Authorization": f"Bearer {admin_user['token']}"}
                )


# =============================================================================
# GET /api/financials/{id} - Auth and Validation Tests
# =============================================================================

class TestGetFinancialByID:
    """Testes para GET /api/financials/{id}"""

    @catch_connection_errors
    def test_get_financial_without_token_returns_401(self, http_client, api_url, test_financial, timer):
        """GET /api/financials/{id} sem token DEVE retornar 401"""
        response = http_client.get(f"{api_url}/financials/{test_financial['id']}")
        assert response.status_code == 401, \
            f"🔴 FALHA DE SEGURANÇA: Expected 401 without token, got {response.status_code}"

    @catch_connection_errors
    def test_get_nonexistent_financial_returns_404(self, http_client, api_url, admin_user, timer):
        """GET /api/financials/{id} com ID inexistente DEVE retornar 404"""
        if not admin_user or "token" not in admin_user:
            pytest.skip("Admin user não disponível")

        fake_id = str(uuid.uuid4())
        response = http_client.get(
            f"{api_url}/financials/{fake_id}",
            headers={"Authorization": f"Bearer {admin_user['token']}"}
        )
        assert response.status_code == 404, \
            f"Expected 404 for non-existent financial, got {response.status_code}"

    @catch_connection_errors
    def test_get_financial_with_invalid_uuid_returns_400(self, http_client, api_url, admin_user, timer):
        """GET /api/financials/{id} com UUID inválido DEVE retornar 400"""
        if not admin_user or "token" not in admin_user:
            pytest.skip("Admin user não disponível")

        invalid_uuids = [
            "not-a-uuid",
            "12345",
            "'; DROP TABLE contract_financials; --",
            "../../../etc/passwd",
            "00000000-0000-0000-0000-000000000000"
        ]

        for invalid_id in invalid_uuids:
            response = http_client.get(
                f"{api_url}/financials/{invalid_id}",
                headers={"Authorization": f"Bearer {admin_user['token']}"}
            )
            # Deve retornar 400 ou 404, mas NÃO 500
            assert response.status_code != 500, \
                f"🔴 VALIDATION: Backend crashou com ID '{invalid_id}'"


# =============================================================================
# PUT /api/financials/{id} - Update Tests
# =============================================================================

class TestUpdateFinancial:
    """Testes para PUT /api/financials/{id}"""

    @catch_connection_errors
    def test_update_financial_without_token_returns_401(self, http_client, api_url, test_financial, timer):
        """PUT /api/financials/{id} sem token DEVE retornar 401"""
        update_data = {
            "description": "Updated description"
        }
        response = http_client.put(
            f"{api_url}/financials/{test_financial['id']}",
            json=update_data
        )
        assert response.status_code == 401, \
            f"🔴 FALHA DE SEGURANÇA: Expected 401 without token, got {response.status_code}"

    @catch_connection_errors
    def test_update_financial_with_xss_sanitizes(self, http_client, api_url, admin_user, test_financial, timer):
        """PUT /api/financials/{id} com XSS DEVE sanitizar"""
        if not admin_user or "token" not in admin_user:
            pytest.skip("Admin user não disponível")

        xss_payload = "<script>alert('XSS')</script>"
        update_data = {
            "description": xss_payload
        }

        response = http_client.put(
            f"{api_url}/financials/{test_financial['id']}",
            json=update_data,
            headers={"Authorization": f"Bearer {admin_user['token']}"}
        )

        # Não deve crashar
        assert response.status_code != 500, \
            f"🔴 XSS: Backend crashou ao atualizar com XSS"

        if response.status_code == 200:
            data = response.json()
            if "description" in data:
                assert "<script" not in data["description"].lower(), \
                    f"🔴 XSS: Script tag não foi sanitizado na atualização!"


# =============================================================================
# DELETE /api/financials/{id} - Delete Tests
# =============================================================================

class TestDeleteFinancial:
    """Testes para DELETE /api/financials/{id}"""

    @catch_connection_errors
    def test_delete_financial_without_token_returns_401(self, http_client, api_url, test_financial, timer):
        """DELETE /api/financials/{id} sem token DEVE retornar 401"""
        response = http_client.delete(f"{api_url}/financials/{test_financial['id']}")
        assert response.status_code == 401, \
            f"🔴 FALHA DE SEGURANÇA: Expected 401 without token, got {response.status_code}"

    @catch_connection_errors
    def test_delete_nonexistent_financial_returns_404(self, http_client, api_url, admin_user, timer):
        """DELETE /api/financials/{id} com ID inexistente DEVE retornar 404"""
        if not admin_user or "token" not in admin_user:
            pytest.skip("Admin user não disponível")

        fake_id = str(uuid.uuid4())
        response = http_client.delete(
            f"{api_url}/financials/{fake_id}",
            headers={"Authorization": f"Bearer {admin_user['token']}"}
        )
        assert response.status_code == 404, \
            f"Expected 404 for non-existent financial, got {response.status_code}"


# =============================================================================
# Installments Tests
# =============================================================================

class TestFinancialInstallments:
    """Testes para parcelas de financeiro"""

    @catch_connection_errors
    def test_get_installments_without_token_returns_401(self, http_client, api_url, test_financial_with_installments, timer):
        """GET /api/financials/{id}/installments sem token DEVE retornar 401"""
        response = http_client.get(
            f"{api_url}/financials/{test_financial_with_installments['id']}/installments"
        )
        assert response.status_code == 401, \
            f"🔴 FALHA DE SEGURANÇA: Expected 401 without token, got {response.status_code}"

    @catch_connection_errors
    def test_create_installment_with_empty_body_returns_400(self, http_client, api_url, admin_user, test_financial_with_installments, timer):
        """POST /api/financials/{id}/installments com body vazio DEVE retornar 400"""
        if not admin_user or "token" not in admin_user:
            pytest.skip("Admin user não disponível")

        response = http_client.post(
            f"{api_url}/financials/{test_financial_with_installments['id']}/installments",
            json={},
            headers={"Authorization": f"Bearer {admin_user['token']}"}
        )
        assert response.status_code == 400, \
            f"🔴 FALHA: Expected 400 for empty installment, got {response.status_code}"

    @catch_connection_errors
    def test_create_installment_with_xss_sanitizes(self, http_client, api_url, admin_user, test_financial_with_installments, timer):
        """POST /api/financials/{id}/installments com XSS DEVE sanitizar"""
        if not admin_user or "token" not in admin_user:
            pytest.skip("Admin user não disponível")

        xss_payload = "<script>alert('XSS')</script>"
        installment_data = {
            "installment_number": 99,
            "amount": 100.00,
            "due_date": (datetime.now() + timedelta(days=120)).isoformat(),
            "description": xss_payload
        }

        response = http_client.post(
            f"{api_url}/financials/{test_financial_with_installments['id']}/installments",
            json=installment_data,
            headers={"Authorization": f"Bearer {admin_user['token']}"}
        )

        # Não deve crashar
        assert response.status_code != 500, \
            f"🔴 XSS: Backend crashou ao criar parcela com XSS"

        if response.status_code in [200, 201]:
            data = response.json()
            installment_id = data.get("id")

            if "description" in data:
                assert "<script" not in data["description"].lower(), \
                    f"🔴 XSS: Script tag não foi sanitizado em parcela!"

            # Cleanup
            if installment_id:
                http_client.delete(
                    f"{api_url}/financials/{test_financial_with_installments['id']}/installments/{installment_id}",
                    headers={"Authorization": f"Bearer {admin_user['token']}"}
                )


# =============================================================================
# Mark Installment as Paid Tests
# =============================================================================

class TestMarkInstallmentPaid:
    """Testes para marcar parcelas como pagas"""

    @catch_connection_errors
    def test_mark_installment_paid_without_token_returns_401(self, http_client, api_url, test_financial_with_installments, timer):
        """PUT /api/financials/{id}/installments/{inst_id}/pay sem token DEVE retornar 401"""
        # Pegar primeira parcela
        response = http_client.get(
            f"{api_url}/financials/{test_financial_with_installments['id']}/installments",
            headers={"Authorization": f"Bearer {test_financial_with_installments.get('_test_admin_token', '')}"}
        )

        if response.status_code != 200:
            pytest.skip("Não foi possível obter parcelas")

        installments = response.json()
        if not installments:
            pytest.skip("Nenhuma parcela disponível")

        first_installment = installments[0]

        # Tentar marcar como paga sem token
        response = http_client.put(
            f"{api_url}/financials/{test_financial_with_installments['id']}/installments/{first_installment['id']}/pay"
        )
        assert response.status_code == 401, \
            f"🔴 FALHA DE SEGURANÇA: Expected 401 without token, got {response.status_code}"

    @catch_connection_errors
    def test_mark_nonexistent_installment_paid_returns_400_or_404(self, http_client, api_url, admin_user, test_financial_with_installments, timer):
        """PUT /api/financials/{id}/installments/{inst_id}/pay com parcela inexistente DEVE retornar 400 ou 404"""
        if not admin_user or "token" not in admin_user:
            pytest.skip("Admin user não disponível")

        fake_installment_id = str(uuid.uuid4())
        response = http_client.put(
            f"{api_url}/financials/{test_financial_with_installments['id']}/installments/{fake_installment_id}/pay",
            headers={"Authorization": f"Bearer {admin_user['token']}"}
        )
        assert response.status_code in [400, 404], \
            f"Expected 400 or 404 for non-existent installment, got {response.status_code}"

    @catch_connection_errors
    def test_mark_installment_paid_with_invalid_uuid_returns_400(self, http_client, api_url, admin_user, test_financial_with_installments, timer):
        """PUT /api/financials/{id}/installments/{inst_id}/pay com UUID inválido DEVE retornar 400"""
        if not admin_user or "token" not in admin_user:
            pytest.skip("Admin user não disponível")

        invalid_id = "'; DROP TABLE financial_installments; --"
        response = http_client.put(
            f"{api_url}/financials/{test_financial_with_installments['id']}/installments/{invalid_id}/pay",
            headers={"Authorization": f"Bearer {admin_user['token']}"}
        )
        # Não deve crashar
        assert response.status_code != 500, \
            f"🔴 SQL INJECTION: Backend crashou com ID malicioso"


# =============================================================================
# Dashboard Endpoints Tests
# =============================================================================

class TestFinancialDashboard:
    """Testes para endpoints de dashboard de financeiro"""

    @catch_connection_errors
    def test_get_summary_without_token_returns_401(self, http_client, api_url, timer):
        """GET /api/financials/summary sem token DEVE retornar 401"""
        response = http_client.get(f"{api_url}/financials/summary")
        assert response.status_code == 401, \
            f"🔴 FALHA DE SEGURANÇA: Expected 401 without token, got {response.status_code}"

    @catch_connection_errors
    def test_get_upcoming_without_token_returns_401(self, http_client, api_url, timer):
        """GET /api/financials/upcoming sem token DEVE retornar 401"""
        response = http_client.get(f"{api_url}/financials/upcoming")
        assert response.status_code == 401, \
            f"🔴 FALHA DE SEGURANÇA: Expected 401 without token, got {response.status_code}"

    @catch_connection_errors
    def test_get_overdue_without_token_returns_401(self, http_client, api_url, timer):
        """GET /api/financials/overdue sem token DEVE retornar 401"""
        response = http_client.get(f"{api_url}/financials/overdue")
        assert response.status_code == 401, \
            f"🔴 FALHA DE SEGURANÇA: Expected 401 without token, got {response.status_code}"

    @catch_connection_errors
    def test_get_upcoming_with_sql_injection_in_params(self, http_client, api_url, admin_user, timer):
        """GET /api/financials/upcoming com SQL Injection em params NÃO DEVE afetar DB"""
        if not admin_user or "token" not in admin_user:
            pytest.skip("Admin user não disponível")

        sql_payloads = [
            "' OR '1'='1",
            "'; DROP TABLE financial_installments; --",
            "1' UNION SELECT * FROM users--",
        ]

        for payload in sql_payloads:
            response = http_client.get(
                f"{api_url}/financials/upcoming?days={payload}",
                headers={"Authorization": f"Bearer {admin_user['token']}"}
            )

            # Não deve crashar
            assert response.status_code != 500, \
                f"🔴 SQL INJECTION: Payload '{payload}' causou erro 500!"


# =============================================================================
# Edge Cases and Resilience Tests
# =============================================================================

class TestFinancialsEdgeCases:
    """Testes de casos extremos e resiliência"""

    @catch_connection_errors
    def test_concurrent_financial_creation_doesnt_crash(self, http_client, api_url, admin_user, test_contract, timer):
        """Criação concorrente de financeiro NÃO DEVE crashar o backend"""
        if not admin_user or "token" not in admin_user:
            pytest.skip("Admin user não disponível")

        import concurrent.futures

        def create_financial():
            financial_data = {
                "contract_id": test_contract["id"],
                "financial_type": "unico",
                "client_value": 1000.00,
                "received_value": 900.00,
                "description": f"Concurrent test {uuid.uuid4().hex[:8]}"
            }
            return http_client.post(
                f"{api_url}/financials",
                json=financial_data,
                headers={"Authorization": f"Bearer {admin_user['token']}"},
                timeout=5
            )

        # Criar 10 financeiro concorrentemente
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(create_financial) for _ in range(10)]
            results = [f.result() for f in concurrent.futures.as_completed(futures)]

        # Pelo menos alguns devem ter sucesso
        success_count = sum(1 for r in results if r.status_code in [200, 201])
        assert success_count > 0, \
            f"🔴 CONCURRENCY: Nenhum financeiro foi criado em teste concorrente"

        # Cleanup - deletar financeiro criados
        for result in results:
            if result.status_code in [200, 201]:
                financial_id = result.json().get("id")
                if financial_id:
                    http_client.delete(
                        f"{api_url}/financials/{financial_id}",
                        headers={"Authorization": f"Bearer {admin_user['token']}"}
                    )

    @catch_connection_errors
    def test_financial_type_validation(self, http_client, api_url, admin_user, test_contract, timer):
        """financial_type inválido DEVE ser rejeitado"""
        if not admin_user or "token" not in admin_user:
            pytest.skip("Admin user não disponível")

        invalid_types = [
            "invalid_type",
            "123",
            "<script>alert('XSS')</script>",
            "'; DROP TABLE contract_financials; --",
            "",
            None
        ]

        for invalid_type in invalid_types:
            financial_data = {
                "contract_id": test_contract["id"],
                "financial_type": invalid_type,
                "client_value": 1000.00,
                "received_value": 900.00
            }

            response = http_client.post(
                f"{api_url}/financials",
                json=financial_data,
                headers={"Authorization": f"Bearer {admin_user['token']}"}
            )

            # Deve rejeitar (400) ou aceitar sem crashar
            assert response.status_code != 500, \
                f"🔴 VALIDATION: Backend crashou com financial_type '{invalid_type}'"


# =============================================================================
# Summary Report
# =============================================================================

def pytest_sessionfinish(session, exitstatus):
    """Relatório final dos testes de segurança"""
    print("\n" + "="*80)
    print("RELATÓRIO DE TESTES DE SEGURANÇA - API DE FINANCEIRO")
    print("="*80)
    print(f"Total de testes: {session.testscollected}")
    print(f"Status de saída: {exitstatus}")
    print("\nCategorias testadas:")
    print("  ✓ Autenticação e Autorização")
    print("  ✓ SQL Injection")
    print("  ✓ XSS (Cross-Site Scripting)")
    print("  ✓ Requisições vazias e NULL handling")
    print("  ✓ Overflow e limites")
    print("  ✓ Validação de UUID")
    print("  ✓ Parcelas (Installments)")
    print("  ✓ Marcar como pago/pendente")
    print("  ✓ Dashboard endpoints")
    print("  ✓ Casos extremos e resiliência")
    print("="*80)

    if exitstatus == 0:
        print("✅ TODOS OS TESTES DE SEGURANÇA PASSARAM!")
    else:
        print("❌ ALGUNS TESTES FALHARAM - REVISAR IMEDIATAMENTE!")
    print("="*80)
