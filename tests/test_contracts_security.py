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
"""

import pytest
import requests
import time
import uuid
from datetime import datetime, timedelta


class TestContractsAPIAuth:
    """Testes de autenticação para API de Contracts"""

    def test_get_contracts_requires_auth(self, http_client, api_url, timer):
        """GET /api/contracts sem token DEVE retornar 401"""
        response = http_client.get(f"{api_url}/contracts")
        assert response.status_code == 401, f"Expected 401, got {response.status_code}"

    def test_post_contract_requires_auth(self, http_client, api_url, timer):
        """POST /api/contracts sem token DEVE retornar 401"""
        response = http_client.post(
            f"{api_url}/contracts",
            json={
                "client_id": str(uuid.uuid4()),
                "subcategory_id": str(uuid.uuid4()),
                "model": "Test",
                "item_key": "TEST001"
            }
        )
        assert response.status_code == 401, f"Expected 401, got {response.status_code}"

    def test_get_contract_by_id_requires_auth(self, http_client, api_url, timer):
        """GET /api/contracts/{id} sem token DEVE retornar 401"""
        fake_id = str(uuid.uuid4())
        response = http_client.get(f"{api_url}/contracts/{fake_id}")
        assert response.status_code == 401, f"Expected 401, got {response.status_code}"


class TestContractsInputValidation:
    """Testes de validação de input para Contracts"""

    def test_create_contract_empty_body(self, http_client, api_url, root_user, timer):
        """Criar contrato com body vazio DEVE retornar 400"""
        response = http_client.post(
            f"{api_url}/contracts",
            headers={"Authorization": f"Bearer {root_user['token']}"},
            json={}
        )
        assert response.status_code == 400, f"Expected 400, got {response.status_code}"

    def test_create_contract_missing_model(self, http_client, api_url, root_user, timer):
        """Criar contrato sem modelo DEVE retornar 400"""
        response = http_client.post(
            f"{api_url}/contracts",
            headers={"Authorization": f"Bearer {root_user['token']}"},
            json={
                "client_id": str(uuid.uuid4()),
                "subcategory_id": str(uuid.uuid4())
            }
        )
        assert response.status_code == 400, f"Expected 400, got {response.status_code}"

    def test_create_contract_invalid_client_id_format(self, http_client, api_url, root_user, timer):
        """Criar contrato com client_id em formato inválido DEVE retornar 400"""
        response = http_client.post(
            f"{api_url}/contracts",
            headers={"Authorization": f"Bearer {root_user['token']}"},
            json={
                "client_id": "not-a-uuid",
                "subcategory_id": str(uuid.uuid4()),
                "model": "Test"
            }
        )
        assert response.status_code == 400, f"Expected 400 for invalid UUID format, got {response.status_code}"

    def test_get_contract_not_found(self, http_client, api_url, root_user, timer):
        """GET contrato inexistente DEVE retornar 404"""
        fake_id = str(uuid.uuid4())
        response = http_client.get(
            f"{api_url}/contracts/{fake_id}",
            headers={"Authorization": f"Bearer {root_user['token']}"}
        )
        assert response.status_code == 404, f"Expected 404 for non-existent contract, got {response.status_code}"


class TestContractsIDManipulation:
    """Testes de manipulação de IDs - SEGURANÇA CRÍTICA"""

    def test_invalid_uuid_format_rejected(self, http_client, api_url, root_user, timer):
        """ID em formato inválido DEVE retornar 400 ou 404, NUNCA 500"""
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
            # NUNCA deve retornar 500 (erro interno) ou 200 (sucesso)
            assert response.status_code in [400, 404], \
                f"Invalid ID '{invalid_id}' returned {response.status_code}, expected 400/404"
            # Não deve vazar erros SQL
            assert "sql" not in response.text.lower(), f"SQL error leaked for ID: {invalid_id}"
            assert "syntax" not in response.text.lower(), f"Syntax error leaked for ID: {invalid_id}"

    def test_null_uuid_returns_404(self, http_client, api_url, root_user, timer):
        """UUID null (zeros) DEVE retornar 404"""
        null_uuid = "00000000-0000-0000-0000-000000000000"
        response = http_client.get(
            f"{api_url}/contracts/{null_uuid}",
            headers={"Authorization": f"Bearer {root_user['token']}"}
        )
        assert response.status_code == 404, f"Null UUID returned {response.status_code}, expected 404"


class TestContractsXSSandSQLi:
    """Testes de XSS e SQL Injection para Contracts"""

    XSS_PAYLOADS = [
        "<script>alert('XSS')</script>",
        "javascript:alert('XSS')",
        "<img src=x onerror=alert('XSS')>",
        "'><script>alert(1)</script>",
    ]

    SQL_PAYLOADS = [
        "' OR '1'='1",
        "'; DROP TABLE contracts;--",
        "' UNION SELECT * FROM users--",
        "1'; DELETE FROM contracts;--",
    ]

    def test_xss_in_model_field_sanitized(self, http_client, api_url, root_user, timer):
        """XSS no campo model DEVE ser sanitizado ou rejeitado"""
        for payload in self.XSS_PAYLOADS:
            response = http_client.post(
                f"{api_url}/contracts",
                headers={"Authorization": f"Bearer {root_user['token']}"},
                json={
                    "client_id": str(uuid.uuid4()),
                    "subcategory_id": str(uuid.uuid4()),
                    "model": payload
                }
            )
            # Resposta não deve conter XSS não-sanitizado
            assert "<script>" not in response.text, f"XSS not sanitized: {payload}"
            assert "onerror=" not in response.text.lower(), f"XSS event handler not sanitized: {payload}"

    def test_sqli_in_model_field_blocked(self, http_client, api_url, root_user, timer):
        """SQL Injection no campo model NÃO DEVE vazar erros SQL"""
        for payload in self.SQL_PAYLOADS:
            response = http_client.post(
                f"{api_url}/contracts",
                headers={"Authorization": f"Bearer {root_user['token']}"},
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


class TestContractsPermissions:
    """Testes de permissões para Contracts"""

    def test_user_without_permission_denied(self, http_client, api_url, regular_user, timer):
        """Usuário SEM permissão contracts:create NÃO pode criar contratos"""
        response = http_client.post(
            f"{api_url}/contracts",
            headers={"Authorization": f"Bearer {regular_user['token']}"},
            json={
                "client_id": str(uuid.uuid4()),
                "subcategory_id": str(uuid.uuid4()),
                "model": "Test"
            }
        )
        # Deve retornar 403 (sem permissão) ou 400 (validação)
        assert response.status_code in [400, 403], \
            f"User without permission got {response.status_code}, expected 403"
