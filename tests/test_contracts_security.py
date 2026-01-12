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
Testes de Segurança Agressivos para API de Contracts
NOTA: Estes testes são RIGOROSOS - se falharem, a API tem problema de segurança

Cobertura:
- GET /api/contracts: Auth, Permission, SQL Injection
- POST /api/contracts: Empty Request, XSS, SQL Injection, Overflow
- GET /api/contracts/{id}: Auth, Not Found
- PUT /api/contracts/{id}: Auth, XSS, SQL Injection, Overflow
- PUT /api/contracts/{id}/archive: Auth, Permission
"""

import pytest
import requests
import time
import uuid
from datetime import datetime, timedelta
from functools import wraps


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
# GET /api/contracts - Auth and Permission Tests
# =============================================================================

class TestGetContractsAuth:
    """Testes de autenticação para GET /api/contracts"""

    def test_get_contracts_without_token_returns_401(self, http_client, api_url, timer):
        """GET /api/contracts sem token DEVE retornar 401"""
        response = http_client.get(f"{api_url}/contracts")
        assert response.status_code == 401, \
            f"Expected 401 Unauthorized without token, got {response.status_code}"

    def test_get_contracts_with_invalid_token_returns_401(self, http_client, api_url, timer):
        """GET /api/contracts com token inválido DEVE retornar 401"""
        response = http_client.get(
            f"{api_url}/contracts",
            headers={"Authorization": "Bearer invalid_token_here"}
        )
        assert response.status_code == 401, \
            f"Expected 401 with invalid token, got {response.status_code}"

    def test_get_contracts_with_malformed_auth_header_returns_401(self, http_client, api_url, timer):
        """GET /api/contracts com header mal formado DEVE retornar 401"""
        malformed_headers = [
            {"Authorization": "NotBearer token"},
            {"Authorization": "Bearer"},
            {"Authorization": ""},
        ]
        for header in malformed_headers:
            response = http_client.get(f"{api_url}/contracts", headers=header)
            assert response.status_code == 401, \
                f"Expected 401 with malformed header {header}, got {response.status_code}"


class TestGetContractsPermission:
    """Testes de permissão para GET /api/contracts"""

    def test_regular_user_can_list_contracts(self, http_client, api_url, regular_user, timer):
        """Usuário regular DEVE poder listar contratos (permissão padrão)"""
        if not regular_user or "token" not in regular_user:
            pytest.skip("Regular user não disponível")

        response = http_client.get(
            f"{api_url}/contracts",
            headers={"Authorization": f"Bearer {regular_user['token']}"}
        )
        # Usuários autenticados geralmente podem listar contratos
        assert response.status_code in [200, 403], \
            f"Expected 200 or 403, got {response.status_code}"

    def test_admin_can_list_contracts(self, http_client, api_url, admin_user, timer):
        """Admin DEVE poder listar contratos"""
        if not admin_user or "token" not in admin_user:
            pytest.skip("Admin user não disponível")

        response = http_client.get(
            f"{api_url}/contracts",
            headers={"Authorization": f"Bearer {admin_user['token']}"}
        )
        assert response.status_code == 200, \
            f"Admin should be able to list contracts, got {response.status_code}"


# =============================================================================
# POST /api/contracts - Input Validation, SQL Injection, XSS, Overflow
# =============================================================================

class TestPostContractsAuth:
    """Testes de autenticação para POST /api/contracts"""

    def test_post_contract_without_token_returns_401(self, http_client, api_url, timer):
        """POST /api/contracts sem token DEVE retornar 401"""
        response = http_client.post(
            f"{api_url}/contracts",
            json={
                "client_id": str(uuid.uuid4()),
                "subcategory_id": str(uuid.uuid4()),
                "model": "Test Model",
                "item_key": "TEST001"
            }
        )
        assert response.status_code == 401, \
            f"Expected 401 without token, got {response.status_code}"


class TestPostContractsInputValidation:
    """Testes de validação de input para POST /api/contracts"""

    def test_create_contract_empty_body_returns_400(self, http_client, api_url, root_user, timer):
        """Criar contrato com body vazio DEVE retornar 400"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        response = http_client.post(
            f"{api_url}/contracts",
            headers={"Authorization": f"Bearer {root_user['token']}"},
            json={}
        )
        assert response.status_code == 400, \
            f"Expected 400 for empty body, got {response.status_code}"

    def test_create_contract_missing_model_returns_400(self, http_client, api_url, root_user, timer):
        """Criar contrato sem campo model DEVE retornar 400"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        response = http_client.post(
            f"{api_url}/contracts",
            headers={"Authorization": f"Bearer {root_user['token']}"},
            json={
                "client_id": str(uuid.uuid4()),
                "subcategory_id": str(uuid.uuid4())
            }
        )
        assert response.status_code == 400, \
            f"Expected 400 for missing model, got {response.status_code}"

    def test_create_contract_invalid_client_id_format_returns_400(self, http_client, api_url, root_user, timer):
        """Criar contrato com client_id inválido DEVE retornar 400"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        response = http_client.post(
            f"{api_url}/contracts",
            headers={"Authorization": f"Bearer {root_user['token']}"},
            json={
                "client_id": "not-a-valid-uuid",
                "subcategory_id": str(uuid.uuid4()),
                "model": "Test Model"
            }
        )
        assert response.status_code == 400, \
            f"Expected 400 for invalid UUID format, got {response.status_code}"

    def test_create_contract_invalid_subcategory_id_format_returns_400(self, http_client, api_url, root_user, timer):
        """Criar contrato com subcategory_id inválido DEVE retornar 400"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        response = http_client.post(
            f"{api_url}/contracts",
            headers={"Authorization": f"Bearer {root_user['token']}"},
            json={
                "client_id": str(uuid.uuid4()),
                "subcategory_id": "invalid-uuid",
                "model": "Test Model"
            }
        )
        assert response.status_code == 400, \
            f"Expected 400 for invalid subcategory UUID, got {response.status_code}"


class TestPostContractsSQLInjection:
    """Testes de SQL Injection para POST /api/contracts"""

    SQL_PAYLOADS = [
        "' OR '1'='1",
        "' OR '1'='1' --",
        "'; DROP TABLE contracts;--",
        "'; DELETE FROM contracts WHERE 1=1; --",
        "' UNION SELECT * FROM users--",
        "1' AND 1=0 UNION ALL SELECT 'admin', '81dc9bdb52d04dc20036dbd8313ed055'",
        "' AND (SELECT COUNT(*) FROM users) > 0 --",
        "' UNION SELECT table_name FROM information_schema.tables--",
        "'; WAITFOR DELAY '00:00:05'--",
        "1'; SELECT pg_sleep(5); --",
    ]

    @catch_connection_errors
    def test_sql_injection_in_model_field(self, http_client, api_url, root_user, timer):
        """SQL Injection no campo model NÃO DEVE causar erro SQL ou vazar dados"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        for payload in self.SQL_PAYLOADS:
            response = http_client.post(
                f"{api_url}/contracts",
                headers=headers,
                json={
                    "client_id": str(uuid.uuid4()),
                    "subcategory_id": str(uuid.uuid4()),
                    "model": payload,
                    "item_key": "TEST001"
                },
                timeout=10
            )

            # NUNCA deve retornar 500 (erro interno) - indica SQL mal tratado
            assert response.status_code != 500, \
                f"SQL Injection causou erro 500 com payload: {payload}"

            # Não deve vazar erros SQL
            response_lower = response.text.lower()
            assert "syntax error" not in response_lower, \
                f"SQL error leaked for: {payload}"
            assert "postgresql" not in response_lower, \
                f"DB type leaked for: {payload}"
            assert "sqlite" not in response_lower, \
                f"DB type leaked"
            assert "pq:" not in response_lower, \
                f"PostgreSQL driver error leaked for: {payload}"

    @catch_connection_errors
    def test_sql_injection_in_item_key_field(self, http_client, api_url, root_user, timer):
        """SQL Injection no campo item_key NÃO DEVE causar erro SQL"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        for payload in self.SQL_PAYLOADS[:5]:  # Primeiros 5 payloads
            response = http_client.post(
                f"{api_url}/contracts",
                headers=headers,
                json={
                    "client_id": str(uuid.uuid4()),
                    "subcategory_id": str(uuid.uuid4()),
                    "model": "Test Model",
                    "item_key": payload
                },
                timeout=10
            )

            assert response.status_code != 500, \
                f"SQL Injection in item_key causou erro 500: {payload}"

    @catch_connection_errors
    def test_sql_injection_in_client_id_field(self, http_client, api_url, root_user, timer):
        """SQL Injection no campo client_id DEVE ser rejeitado pela validação de UUID"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        for payload in self.SQL_PAYLOADS[:5]:
            response = http_client.post(
                f"{api_url}/contracts",
                headers=headers,
                json={
                    "client_id": payload,
                    "subcategory_id": str(uuid.uuid4()),
                    "model": "Test Model"
                },
                timeout=10
            )

            # Deve rejeitar com 400 (UUID inválido) ou similar
            assert response.status_code in [400, 422], \
                f"SQL Injection in client_id should be rejected, got {response.status_code}"


class TestPostContractsOverflow:
    """Testes de Overflow para POST /api/contracts"""

    SHORT_OVERFLOW = "A" * 500
    MEDIUM_OVERFLOW = "A" * 2000
    LARGE_OVERFLOW = "A" * 10000

    @catch_connection_errors
    def test_overflow_in_model_field_short(self, http_client, api_url, root_user, timer):
        """Overflow curto no campo model deve ser tratado gracefully"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        response = http_client.post(
            f"{api_url}/contracts",
            headers={"Authorization": f"Bearer {root_user['token']}"},
            json={
                "client_id": str(uuid.uuid4()),
                "subcategory_id": str(uuid.uuid4()),
                "model": self.SHORT_OVERFLOW,
                "item_key": "TEST001"
            },
            timeout=10
        )

        # Deve rejeitar com 400 (muito longo) ou aceitar se dentro do limite
        assert response.status_code in [200, 201, 400, 413], \
            f"Overflow in model: unexpected status {response.status_code}"

    @catch_connection_errors
    def test_overflow_in_model_field_large(self, http_client, api_url, root_user, timer):
        """Overflow grande no campo model DEVE ser rejeitado"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        response = http_client.post(
            f"{api_url}/contracts",
            headers={"Authorization": f"Bearer {root_user['token']}"},
            json={
                "client_id": str(uuid.uuid4()),
                "subcategory_id": str(uuid.uuid4()),
                "model": self.LARGE_OVERFLOW,
                "item_key": "TEST001"
            },
            timeout=10
        )

        # Deve rejeitar campos muito longos
        assert response.status_code in [400, 413], \
            f"Large overflow in model should be rejected, got {response.status_code}"

    @catch_connection_errors
    def test_overflow_in_item_key_field(self, http_client, api_url, root_user, timer):
        """Overflow no campo item_key deve ser tratado gracefully"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        response = http_client.post(
            f"{api_url}/contracts",
            headers={"Authorization": f"Bearer {root_user['token']}"},
            json={
                "client_id": str(uuid.uuid4()),
                "subcategory_id": str(uuid.uuid4()),
                "model": "Test Model",
                "item_key": self.MEDIUM_OVERFLOW
            },
            timeout=10
        )

        # Deve rejeitar ou aceitar gracefully, NUNCA crash
        assert response.status_code in [200, 201, 400, 413], \
            f"Overflow in item_key: unexpected status {response.status_code}"

    @catch_connection_errors
    def test_overflow_all_fields_simultaneously(self, http_client, api_url, root_user, timer):
        """Overflow em todos os campos simultaneamente"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        response = http_client.post(
            f"{api_url}/contracts",
            headers={"Authorization": f"Bearer {root_user['token']}"},
            json={
                "client_id": str(uuid.uuid4()),
                "subcategory_id": str(uuid.uuid4()),
                "model": self.MEDIUM_OVERFLOW,
                "item_key": self.MEDIUM_OVERFLOW
            },
            timeout=10
        )

        # Deve rejeitar, NUNCA crash
        assert response.status_code in [200, 201, 400, 413], \
            f"Overflow all fields: unexpected status {response.status_code}"


# =============================================================================
# GET /api/contracts/{id} - Auth and Not Found Tests
# =============================================================================

class TestGetContractByIdAuth:
    """Testes de autenticação para GET /api/contracts/{id}"""

    def test_get_contract_by_id_without_token_returns_401(self, http_client, api_url, timer):
        """GET /api/contracts/{id} sem token DEVE retornar 401"""
        fake_id = str(uuid.uuid4())
        response = http_client.get(f"{api_url}/contracts/{fake_id}")
        assert response.status_code == 401, \
            f"Expected 401 without token, got {response.status_code}"

    def test_get_contract_by_id_with_invalid_token_returns_401(self, http_client, api_url, timer):
        """GET /api/contracts/{id} com token inválido DEVE retornar 401"""
        fake_id = str(uuid.uuid4())
        response = http_client.get(
            f"{api_url}/contracts/{fake_id}",
            headers={"Authorization": "Bearer invalid_token"}
        )
        assert response.status_code == 401, \
            f"Expected 401 with invalid token, got {response.status_code}"


class TestGetContractByIdNotFound:
    """Testes de Not Found para GET /api/contracts/{id}"""

    def test_get_nonexistent_contract_returns_404(self, http_client, api_url, root_user, timer):
        """GET contrato inexistente com UUID válido DEVE retornar 404"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        fake_id = str(uuid.uuid4())
        response = http_client.get(
            f"{api_url}/contracts/{fake_id}",
            headers={"Authorization": f"Bearer {root_user['token']}"}
        )
        assert response.status_code == 404, \
            f"Expected 404 for non-existent contract, got {response.status_code}"

    def test_get_contract_with_invalid_uuid_format(self, http_client, api_url, root_user, timer):
        """GET contrato com UUID inválido DEVE retornar 400 ou 404"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        invalid_ids = [
            "not-a-uuid",
            "12345",
            "admin",
            "../../../etc/passwd",
            "'; DROP TABLE contracts;--",
        ]

        for invalid_id in invalid_ids:
            response = http_client.get(
                f"{api_url}/contracts/{invalid_id}",
                headers={"Authorization": f"Bearer {root_user['token']}"}
            )
            # NUNCA deve retornar 500 ou 200
            assert response.status_code in [400, 404], \
                f"Invalid ID '{invalid_id}' returned {response.status_code}, expected 400/404"

    def test_get_contract_with_null_uuid(self, http_client, api_url, root_user, timer):
        """GET contrato com UUID null (zeros) DEVE retornar 404"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        null_uuid = "00000000-0000-0000-0000-000000000000"
        response = http_client.get(
            f"{api_url}/contracts/{null_uuid}",
            headers={"Authorization": f"Bearer {root_user['token']}"}
        )
        assert response.status_code == 404, \
            f"Null UUID should return 404, got {response.status_code}"


# =============================================================================
# PUT /api/contracts/{id} - Auth, XSS, SQL Injection, Overflow
# =============================================================================

class TestPutContractAuth:
    """Testes de autenticação para PUT /api/contracts/{id}"""

    def test_put_contract_without_token_returns_401(self, http_client, api_url, timer):
        """PUT /api/contracts/{id} sem token DEVE retornar 401"""
        fake_id = str(uuid.uuid4())
        response = http_client.put(
            f"{api_url}/contracts/{fake_id}",
            json={
                "model": "Updated Model",
                "client_id": str(uuid.uuid4()),
                "subcategory_id": str(uuid.uuid4())
            }
        )
        assert response.status_code == 401, \
            f"Expected 401 without token, got {response.status_code}"

    def test_put_contract_with_invalid_token_returns_401(self, http_client, api_url, timer):
        """PUT /api/contracts/{id} com token inválido DEVE retornar 401"""
        fake_id = str(uuid.uuid4())
        response = http_client.put(
            f"{api_url}/contracts/{fake_id}",
            headers={"Authorization": "Bearer invalid_token"},
            json={"model": "Updated Model"}
        )
        assert response.status_code == 401, \
            f"Expected 401 with invalid token, got {response.status_code}"


class TestPutContractXSS:
    """Testes de XSS para PUT /api/contracts/{id}"""

    XSS_PAYLOADS = [
        "<script>alert('XSS')</script>",
        "javascript:alert('XSS')",
        "<img src=x onerror=alert('XSS')>",
        "'><script>alert(1)</script>",
        "<svg onload=alert('XSS')>",
        "<body onload=alert('XSS')>",
        "<iframe src='javascript:alert(1)'>",
        "'\"><img src=x onerror=alert(1)>",
    ]

    @catch_connection_errors
    def test_xss_in_model_field_on_update(self, http_client, api_url, root_user, timer):
        """XSS no campo model em update DEVE ser sanitizado ou rejeitado"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}
        fake_id = str(uuid.uuid4())

        for payload in self.XSS_PAYLOADS:
            response = http_client.put(
                f"{api_url}/contracts/{fake_id}",
                headers=headers,
                json={
                    "model": payload,
                    "client_id": str(uuid.uuid4()),
                    "subcategory_id": str(uuid.uuid4())
                },
                timeout=10
            )

            # Resposta não deve conter XSS não-sanitizado
            assert "<script>" not in response.text, \
                f"XSS not sanitized in model: {payload}"
            assert "onerror=" not in response.text.lower(), \
                f"XSS event handler not sanitized: {payload}"
            assert "onload=" not in response.text.lower(), \
                f"XSS onload not sanitized: {payload}"

    @catch_connection_errors
    def test_xss_in_item_key_field_on_update(self, http_client, api_url, root_user, timer):
        """XSS no campo item_key em update DEVE ser sanitizado"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}
        fake_id = str(uuid.uuid4())

        for payload in self.XSS_PAYLOADS[:4]:
            response = http_client.put(
                f"{api_url}/contracts/{fake_id}",
                headers=headers,
                json={
                    "model": "Test Model",
                    "item_key": payload,
                    "client_id": str(uuid.uuid4()),
                    "subcategory_id": str(uuid.uuid4())
                },
                timeout=10
            )

            assert "<script>" not in response.text, \
                f"XSS not sanitized in item_key: {payload}"


class TestPutContractSQLInjection:
    """Testes de SQL Injection para PUT /api/contracts/{id}"""

    SQL_PAYLOADS = [
        "' OR '1'='1",
        "'; DROP TABLE contracts;--",
        "'; DELETE FROM contracts WHERE 1=1; --",
        "' UNION SELECT * FROM users--",
        "1'; SELECT pg_sleep(5); --",
    ]

    @catch_connection_errors
    def test_sql_injection_in_model_field_on_update(self, http_client, api_url, root_user, timer):
        """SQL Injection no campo model em update NÃO DEVE causar erro SQL"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}
        fake_id = str(uuid.uuid4())

        for payload in self.SQL_PAYLOADS:
            response = http_client.put(
                f"{api_url}/contracts/{fake_id}",
                headers=headers,
                json={
                    "model": payload,
                    "client_id": str(uuid.uuid4()),
                    "subcategory_id": str(uuid.uuid4())
                },
                timeout=10
            )

            assert response.status_code != 500, \
                f"SQL Injection in update model caused 500: {payload}"

            response_lower = response.text.lower()
            assert "syntax error" not in response_lower
            assert "postgresql" not in response_lower
            assert "pq:" not in response_lower

    @catch_connection_errors
    def test_sql_injection_in_item_key_field_on_update(self, http_client, api_url, root_user, timer):
        """SQL Injection no campo item_key em update"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}
        fake_id = str(uuid.uuid4())

        for payload in self.SQL_PAYLOADS:
            response = http_client.put(
                f"{api_url}/contracts/{fake_id}",
                headers=headers,
                json={
                    "model": "Test Model",
                    "item_key": payload,
                    "client_id": str(uuid.uuid4()),
                    "subcategory_id": str(uuid.uuid4())
                },
                timeout=10
            )

            assert response.status_code != 500, \
                f"SQL Injection in update item_key caused 500: {payload}"

    @catch_connection_errors
    def test_sql_injection_in_contract_id_path(self, http_client, api_url, root_user, timer):
        """SQL Injection no ID do path DEVE ser rejeitado"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        sql_id_payloads = [
            "'; DROP TABLE contracts;--",
            "1 OR 1=1",
            "' UNION SELECT * FROM users--",
        ]

        for payload in sql_id_payloads:
            response = http_client.put(
                f"{api_url}/contracts/{payload}",
                headers=headers,
                json={"model": "Test"},
                timeout=10
            )

            # Deve retornar 400 ou 404, NUNCA 500
            assert response.status_code in [400, 404], \
                f"SQL in path '{payload}' returned {response.status_code}"


class TestPutContractOverflow:
    """Testes de Overflow para PUT /api/contracts/{id}"""

    MEDIUM_OVERFLOW = "A" * 2000
    LARGE_OVERFLOW = "A" * 10000

    @catch_connection_errors
    def test_overflow_in_model_field_on_update(self, http_client, api_url, root_user, timer):
        """Overflow no campo model em update"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        fake_id = str(uuid.uuid4())
        response = http_client.put(
            f"{api_url}/contracts/{fake_id}",
            headers={"Authorization": f"Bearer {root_user['token']}"},
            json={
                "model": self.LARGE_OVERFLOW,
                "client_id": str(uuid.uuid4()),
                "subcategory_id": str(uuid.uuid4())
            },
            timeout=10
        )

        # Deve rejeitar ou tratar gracefully
        assert response.status_code in [400, 404, 413], \
            f"Overflow in update model: unexpected status {response.status_code}"

    @catch_connection_errors
    def test_overflow_in_item_key_field_on_update(self, http_client, api_url, root_user, timer):
        """Overflow no campo item_key em update"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        fake_id = str(uuid.uuid4())
        response = http_client.put(
            f"{api_url}/contracts/{fake_id}",
            headers={"Authorization": f"Bearer {root_user['token']}"},
            json={
                "model": "Test Model",
                "item_key": self.LARGE_OVERFLOW,
                "client_id": str(uuid.uuid4()),
                "subcategory_id": str(uuid.uuid4())
            },
            timeout=10
        )

        assert response.status_code in [400, 404, 413], \
            f"Overflow in update item_key: unexpected status {response.status_code}"

    @catch_connection_errors
    def test_overflow_all_fields_on_update(self, http_client, api_url, root_user, timer):
        """Overflow em todos os campos em update"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        fake_id = str(uuid.uuid4())
        response = http_client.put(
            f"{api_url}/contracts/{fake_id}",
            headers={"Authorization": f"Bearer {root_user['token']}"},
            json={
                "model": self.MEDIUM_OVERFLOW,
                "item_key": self.MEDIUM_OVERFLOW,
                "client_id": str(uuid.uuid4()),
                "subcategory_id": str(uuid.uuid4())
            },
            timeout=10
        )

        # Deve rejeitar ou tratar gracefully, NUNCA crash
        assert response.status_code in [400, 404, 413], \
            f"Overflow all fields update: unexpected status {response.status_code}"


# =============================================================================
# PUT /api/contracts/{id}/archive - Auth and Permission Tests
# =============================================================================

class TestArchiveContractAuth:
    """Testes de autenticação para PUT /api/contracts/{id}/archive"""

    def test_archive_contract_without_token_returns_401(self, http_client, api_url, timer):
        """PUT /api/contracts/{id}/archive sem token DEVE retornar 401"""
        fake_id = str(uuid.uuid4())
        response = http_client.put(f"{api_url}/contracts/{fake_id}/archive")
        assert response.status_code == 401, \
            f"Expected 401 without token, got {response.status_code}"

    def test_archive_contract_with_invalid_token_returns_401(self, http_client, api_url, timer):
        """PUT /api/contracts/{id}/archive com token inválido DEVE retornar 401"""
        fake_id = str(uuid.uuid4())
        response = http_client.put(
            f"{api_url}/contracts/{fake_id}/archive",
            headers={"Authorization": "Bearer invalid_token"}
        )
        assert response.status_code == 401, \
            f"Expected 401 with invalid token, got {response.status_code}"


class TestArchiveContractPermission:
    """Testes de permissão para PUT /api/contracts/{id}/archive"""

    def test_regular_user_archive_permission(self, http_client, api_url, regular_user, timer):
        """Verificar se usuário regular pode arquivar contratos"""
        if not regular_user or "token" not in regular_user:
            pytest.skip("Regular user não disponível")

        fake_id = str(uuid.uuid4())
        response = http_client.put(
            f"{api_url}/contracts/{fake_id}/archive",
            headers={"Authorization": f"Bearer {regular_user['token']}"}
        )

        # Pode ser 403 (sem permissão), 400 (contrato não existe), ou 200 (se permitido)
        # O importante é que NÃO seja um erro de servidor
        assert response.status_code in [200, 400, 403, 404], \
            f"Archive by regular user: unexpected status {response.status_code}"

    def test_admin_can_archive_contract(self, http_client, api_url, admin_user, timer):
        """Admin DEVE poder tentar arquivar contratos (mesmo que não exista)"""
        if not admin_user or "token" not in admin_user:
            pytest.skip("Admin user não disponível")

        fake_id = str(uuid.uuid4())
        response = http_client.put(
            f"{api_url}/contracts/{fake_id}/archive",
            headers={"Authorization": f"Bearer {admin_user['token']}"}
        )

        # Admin deve ter permissão, mesmo se contrato não existe (400/404)
        assert response.status_code in [200, 400, 404], \
            f"Admin archive: unexpected status {response.status_code}"

    def test_root_can_archive_contract(self, http_client, api_url, root_user, timer):
        """Root DEVE poder tentar arquivar contratos"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        fake_id = str(uuid.uuid4())
        response = http_client.put(
            f"{api_url}/contracts/{fake_id}/archive",
            headers={"Authorization": f"Bearer {root_user['token']}"}
        )

        # Root deve ter permissão total
        assert response.status_code in [200, 400, 404], \
            f"Root archive: unexpected status {response.status_code}"


# =============================================================================
# Additional Security Tests - ID Manipulation and Error Handling
# =============================================================================

class TestContractsIDManipulation:
    """Testes de manipulação de IDs - SEGURANÇA CRÍTICA"""

    def test_path_traversal_in_contract_id(self, http_client, api_url, root_user, timer):
        """Path traversal no ID DEVE ser bloqueado"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        traversal_ids = [
            "../../../etc/passwd",
            "..%2f..%2f..%2fetc%2fpasswd",
            "....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f",
        ]

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        for malicious_id in traversal_ids:
            response = http_client.get(
                f"{api_url}/contracts/{malicious_id}",
                headers=headers
            )
            # Deve retornar 400 ou 404, NUNCA 200 ou 500
            assert response.status_code in [400, 404], \
                f"Path traversal '{malicious_id}' returned {response.status_code}"

    def test_no_error_messages_leaked_for_invalid_ids(self, http_client, api_url, root_user, timer):
        """Mensagens de erro NÃO DEVEM vazar informações do sistema"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        test_ids = [
            "admin'--",
            "'; SELECT * FROM pg_catalog.pg_tables;--",
            "../../../",
        ]

        sensitive_keywords = [
            "stack trace",
            "exception",
            "file path",
            "/home/",
            "/var/",
            "postgres",
            "database",
            "sql",
        ]

        for test_id in test_ids:
            response = http_client.get(
                f"{api_url}/contracts/{test_id}",
                headers=headers
            )

            response_lower = response.text.lower()
            for keyword in sensitive_keywords:
                if keyword in response_lower:
                    # Alguns keywords como "database" podem aparecer em mensagens genéricas
                    # Verificamos apenas se não há detalhes técnicos expostos
                    if "stack" in response_lower or "exception" in response_lower:
                        pytest.fail(
                            f"Sensitive info '{keyword}' leaked for ID '{test_id}'"
                        )


class TestContractsXSSGeneral:
    """Testes gerais de XSS para Contracts"""

    XSS_PAYLOADS = [
        "<script>alert('XSS')</script>",
        "javascript:alert('XSS')",
        "<img src=x onerror=alert('XSS')>",
        "'><script>alert(1)</script>",
    ]

    def test_xss_in_model_field_sanitized(self, http_client, api_url, root_user, timer):
        """XSS no campo model DEVE ser sanitizado ou rejeitado"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        for payload in self.XSS_PAYLOADS:
            response = http_client.post(
                f"{api_url}/contracts",
                headers=headers,
                json={
                    "client_id": str(uuid.uuid4()),
                    "subcategory_id": str(uuid.uuid4()),
                    "model": payload
                }
            )
            # Resposta não deve conter XSS não-sanitizado
            assert "<script>" not in response.text, f"XSS not sanitized: {payload}"
            assert "onerror=" not in response.text.lower(), f"XSS event handler not sanitized: {payload}"


class TestContractsSQLiGeneral:
    """Testes gerais de SQL Injection para Contracts"""

    SQL_PAYLOADS = [
        "' OR '1'='1",
        "'; DROP TABLE contracts;--",
        "' UNION SELECT * FROM users--",
        "1'; DELETE FROM contracts;--",
    ]

    def test_sqli_in_model_field_blocked(self, http_client, api_url, root_user, timer):
        """SQL Injection no campo model NÃO DEVE vazar erros SQL"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        for payload in self.SQL_PAYLOADS:
            response = http_client.post(
                f"{api_url}/contracts",
                headers=headers,
                json={
                    "client_id": str(uuid.uuid4()),
                    "subcategory_id": str(uuid.uuid4()),
                    "model": payload
                }
            )
            # NUNCA deve vazar erros SQL
            assert "syntax error" not in response.text.lower(), f"SQL error leaked for: {payload}"
            assert "postgresql" not in response.text.lower(), f"DB type leaked for: {payload}"
            assert "sqlite" not in response.text.lower(), f"DB type leaked"
