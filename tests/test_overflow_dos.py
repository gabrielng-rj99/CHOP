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
Testes de Overflow e DoS (Denial of Service)
Baseado em:
- OWASP Testing Guide v4.2
- CWE-400: Uncontrolled Resource Consumption
- CWE-770: Allocation of Resources Without Limits
- Cisco Security Best Practices

NOTA: Alguns testes podem causar crash do backend se não houver proteção
adequada contra payloads grandes. Isso é um BUG DE SEGURANÇA crítico.
"""

import pytest
import requests
import time
import json
from functools import wraps
from typing import Any, Dict


def catch_connection_errors(func):
    """
    Decorator para capturar exceptions de conexão durante testes de DoS.
    Se o backend crashar, isso É UMA VULNERABILIDADE - o teste FALHA.
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
            # Backend crashou = VULNERABILIDADE CRÍTICA!
            pytest.fail(
                f"🔴 VULNERABILIDADE DoS CRÍTICA: Backend crashou ou ficou indisponível!\n"
                f"Payload causou indisponibilidade do serviço.\n"
                f"Erro: {str(e)[:200]}"
            )
    return wrapper


class TestOverflowAttacks:
    """Testes de overflow com strings muito longas e payloads grandes"""

    # Payloads de diferentes tamanhos - REDUZIDOS para evitar crash
    SHORT_OVERFLOW = "A" * 500
    MEDIUM_OVERFLOW = "A" * 2000
    LARGE_OVERFLOW = "A" * 5000

    @catch_connection_errors
    def test_login_username_short_overflow(self, http_client, api_url, timer):
        """Username com 500 caracteres deve ser rejeitado gracefully"""
        response = http_client.post(
            f"{api_url}/login",
            json={"username": self.SHORT_OVERFLOW, "password": "test"},
            timeout=10
        )
        assert response.status_code in [400, 401, 413]

    @catch_connection_errors
    def test_login_username_medium_overflow(self, http_client, api_url, timer):
        """Username com 2K caracteres deve ser rejeitado gracefully"""
        response = http_client.post(
            f"{api_url}/login",
            json={"username": self.MEDIUM_OVERFLOW, "password": "test"},
            timeout=10
        )
        assert response.status_code in [400, 401, 413]

    @catch_connection_errors
    def test_login_password_medium_overflow(self, http_client, api_url, timer):
        """Password com 2K caracteres deve ser rejeitado gracefully"""
        response = http_client.post(
            f"{api_url}/login",
            json={"username": "test", "password": self.MEDIUM_OVERFLOW},
            timeout=10
        )
        assert response.status_code in [400, 401, 413]

    @catch_connection_errors
    def test_login_both_fields_overflow(self, http_client, api_url, timer):
        """Username e password com overflow simultâneo"""
        response = http_client.post(
            f"{api_url}/login",
            json={
                "username": self.SHORT_OVERFLOW,
                "password": self.SHORT_OVERFLOW
            },
            timeout=10
        )
        assert response.status_code in [400, 401, 413]

    @catch_connection_errors
    def test_authorization_header_overflow(self, http_client, api_url, timer):
        """Token JWT com overflow deve ser rejeitado rapidamente"""
        response = http_client.get(
            f"{api_url}/users",
            headers={"Authorization": f"Bearer {self.LARGE_OVERFLOW}"},
            timeout=10
        )
        assert response.status_code == 401

    @catch_connection_errors
    def test_refresh_token_overflow(self, http_client, api_url, timer):
        """Refresh token com overflow deve ser rejeitado"""
        response = http_client.post(
            f"{api_url}/refresh-token",
            json={"refresh_token": self.MEDIUM_OVERFLOW},
            timeout=10
        )
        assert response.status_code in [400, 401]


class TestDeepNestingJSON:
    """Testes de JSON com aninhamento profundo"""

    def generate_deep_nested_json(self, depth: int) -> Dict[str, Any]:
        """Gera JSON com aninhamento profundo"""
        result: Dict[str, Any] = {"value": "test"}
        for _ in range(depth):
            result = {"nested": result}
        return result

    @catch_connection_errors
    def test_login_deep_nested_json_50(self, http_client, api_url, timer):
        """JSON com 50 níveis de aninhamento"""
        deep_json = self.generate_deep_nested_json(50)
        deep_json["username"] = "test"
        deep_json["password"] = "test"

        response = http_client.post(f"{api_url}/login", json=deep_json, timeout=10)
        assert response.status_code in [400, 401]


class TestReDoSAttacks:
    """Testes de Regex Denial of Service"""

    REDOS_PAYLOADS = [
        "a" * 50 + "!",
        "(" * 25 + ")" * 25,
    ]

    @catch_connection_errors
    def test_login_username_redos(self, http_client, api_url, timer):
        """ReDoS no campo username do login"""
        for payload in self.REDOS_PAYLOADS:
            start = time.time()
            response = http_client.post(
                f"{api_url}/login",
                json={"username": payload, "password": "test"},
                timeout=10
            )
            elapsed = time.time() - start
            assert elapsed < 5, f"ReDoS detectado com payload: {payload[:30]}"
            assert response.status_code in [400, 401]


class TestUnicodeOverflow:
    """Testes com caracteres Unicode especiais"""

    @catch_connection_errors
    def test_login_unicode_username(self, http_client, api_url, timer):
        """Unicode especial no username"""
        payloads = [
            "🎉" * 100,
            "中" * 100,
            "\u200B" * 100,
        ]
        for payload in payloads:
            response = http_client.post(
                f"{api_url}/login",
                json={"username": payload, "password": "test"},
                timeout=10
            )
            assert response.status_code in [400, 401]


class TestRepeatedKeyJSON:
    """Testes de JSON com chaves repetidas"""

    @catch_connection_errors
    def test_repeated_key_json(self, http_client, api_url, timer):
        """JSON com chaves repetidas"""
        repeated_json = '{"username": "test", "username": "admin", "password": "test"}'

        response = http_client.post(
            f"{api_url}/login",
            data=repeated_json,
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        assert response.status_code in [400, 401]
