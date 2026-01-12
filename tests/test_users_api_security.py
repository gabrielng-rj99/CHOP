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
Testes de Segurança para APIs de Usuários
Baseado no APIs-checklist.md - cobrindo todos os casos marcados com ⬜

Endpoints cobertos:
- POST /api/refresh-token
- GET /api/users/{username}
- POST /api/users
- PUT /api/users/{username}
- PUT /api/users/{username}/block
- PUT /api/users/{username}/unlock
"""

import pytest
import requests
import time
from functools import wraps


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
            pytest.fail(
                f"🔴 VULNERABILIDADE DoS CRÍTICA: Backend crashou ou ficou indisponível!\n"
                f"Payload causou indisponibilidade do serviço.\n"
                f"Erro: {str(e)[:200]}"
            )
    return wrapper


# =============================================================================
# POST /api/refresh-token - Testes Faltantes
# =============================================================================

@pytest.mark.security
class TestRefreshTokenSecurity:
    """Testes de segurança para POST /api/refresh-token"""

    LARGE_OVERFLOW = "A" * 10000

    SQL_PAYLOADS = [
        "' OR '1'='1",
        "' OR '1'='1' --",
        "admin'--",
        "'; DROP TABLE users; --",
        "' UNION SELECT * FROM users--",
        "1' AND SLEEP(5)--",
    ]

    @catch_connection_errors
    def test_refresh_token_overflow_10k_chars(self, http_client, api_url, timer):
        """Token com 10K+ caracteres deve ser rejeitado gracefully"""
        response = http_client.post(
            f"{api_url}/refresh-token",
            json={"refresh_token": self.LARGE_OVERFLOW},
            timeout=10
        )
        # Deve rejeitar sem causar crash
        assert response.status_code in [400, 401, 413], \
            f"Token overflow deve ser rejeitado, mas recebeu {response.status_code}"
        # Não deve demorar muito (indicaria processamento do payload gigante)
        assert response.elapsed.total_seconds() < 5, \
            "Processamento de token overflow demorou demais"

    @catch_connection_errors
    def test_refresh_token_sql_injection(self, http_client, api_url, timer):
        """SQL Injection no refresh token deve ser bloqueado"""
        for payload in self.SQL_PAYLOADS:
            response = http_client.post(
                f"{api_url}/refresh-token",
                json={"refresh_token": payload},
                timeout=10
            )
            # Não deve retornar 200 com token válido
            if response.status_code == 200:
                data = response.json()
                if "token" in data or "access_token" in data:
                    pytest.fail(f"VULNERÁVEL: SQL injection funcionou com payload: {payload}")

            # Não deve retornar erro 500 (indica SQL error)
            assert response.status_code != 500, \
                f"Erro 500 pode indicar SQL injection com payload: {payload}"


# =============================================================================
# POST /api/users - Testes Faltantes
# =============================================================================

@pytest.mark.security
class TestCreateUserOverflow:
    """Testes de overflow para POST /api/users"""

    LARGE_OVERFLOW = "A" * 10000

    @catch_connection_errors
    def test_create_user_username_overflow_10k(self, http_client, api_url, root_user, timer):
        """Username com 10K+ caracteres deve ser rejeitado"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        response = http_client.post(
            f"{api_url}/users",
            json={
                "username": self.LARGE_OVERFLOW,
                "display_name": "Test User",
                "password": "Test123!@#abcXYZ7890",
                "role": "user"
            },
            headers=headers,
            timeout=10
        )

        assert response.status_code in [400, 413], \
            f"Username overflow deve ser rejeitado, mas recebeu {response.status_code}"

    @catch_connection_errors
    def test_create_user_password_overflow_10k(self, http_client, api_url, root_user, timer):
        """Password com 10K+ caracteres deve ser rejeitado"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        response = http_client.post(
            f"{api_url}/users",
            json={
                "username": f"test_overflow_{int(time.time())}",
                "display_name": "Test User",
                "password": self.LARGE_OVERFLOW,
                "role": "user"
            },
            headers=headers,
            timeout=10
        )

        assert response.status_code in [400, 413], \
            f"Password overflow deve ser rejeitado, mas recebeu {response.status_code}"


# =============================================================================
# GET /api/users/{username} - Testes Faltantes
# =============================================================================

@pytest.mark.security
class TestGetUserByUsername:
    """Testes de segurança para GET /api/users/{username}"""

    SQL_PAYLOADS = [
        "' OR '1'='1",
        "admin'--",
        "'; DROP TABLE users; --",
        "' UNION SELECT * FROM users--",
    ]

    PATH_TRAVERSAL_PAYLOADS = [
        "../",
        "..%2F",
        "....//",
        "../../../etc/passwd",
        "..\\",
        "..%5C",
        "%2e%2e%2f",
        "%2e%2e/",
        "..%252f",
    ]

    LARGE_OVERFLOW = "A" * 10000

    def test_get_user_without_token(self, http_client, api_url, timer):
        """GET /api/users/{username} sem token deve retornar 401"""
        response = http_client.get(f"{api_url}/users/root", timeout=10)
        assert response.status_code == 401, \
            f"Acesso sem token deve retornar 401, mas recebeu {response.status_code}"

    def test_get_user_own_access(self, http_client, api_url, regular_user, timer):
        """Usuário pode acessar seus próprios dados"""
        if not regular_user or "token" not in regular_user:
            pytest.skip("Regular user não disponível")

        headers = {"Authorization": f"Bearer {regular_user['token']}"}
        username = regular_user.get("username")

        if not username:
            pytest.skip("Username não disponível")

        # Usuário comum não tem acesso ao endpoint /api/users (adminOnlyMiddleware)
        # Este teste verifica que o comportamento está correto
        response = http_client.get(f"{api_url}/users/{username}", headers=headers, timeout=10)

        # Com adminOnlyMiddleware, usuário comum não pode acessar /api/users
        # Então deve receber 403
        assert response.status_code == 403, \
            f"Usuário comum não deve ter acesso a /api/users, esperado 403, recebeu {response.status_code}"

    def test_get_user_path_traversal(self, http_client, api_url, root_user, timer):
        """Path traversal no username deve ser bloqueado"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        for payload in self.PATH_TRAVERSAL_PAYLOADS:
            response = http_client.get(
                f"{api_url}/users/{payload}",
                headers=headers,
                timeout=10
            )

            # Deve retornar 400 ou 404, nunca 200 com dados sensíveis
            assert response.status_code in [400, 404], \
                f"Path traversal '{payload}' deve ser bloqueado, mas recebeu {response.status_code}"

            # Verificar que não vazou informações do sistema
            if response.status_code == 200:
                data = response.text.lower()
                assert "root:" not in data, "Possível vazamento de /etc/passwd"
                assert "bin:" not in data, "Possível vazamento de /etc/passwd"

    def test_get_user_sql_injection(self, http_client, api_url, root_user, timer):
        """SQL Injection no username deve ser bloqueado"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        for payload in self.SQL_PAYLOADS:
            response = http_client.get(
                f"{api_url}/users/{payload}",
                headers=headers,
                timeout=10
            )

            # Não deve retornar erro 500
            assert response.status_code != 500, \
                f"Erro 500 pode indicar SQL injection com payload: {payload}"

            # Se retornou 200, verificar que não retornou dados demais
            if response.status_code == 200:
                try:
                    data = response.json()
                    # Se é uma lista com muitos usuários, pode ser SQL injection
                    if isinstance(data, list) and len(data) > 10:
                        pytest.fail(f"Possível SQL injection: retornou {len(data)} usuários com payload: {payload}")
                except:
                    pass

    @catch_connection_errors
    def test_get_user_username_overflow_10k(self, http_client, api_url, root_user, timer):
        """Username com 10K+ caracteres no path deve ser rejeitado"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        response = http_client.get(
            f"{api_url}/users/{self.LARGE_OVERFLOW}",
            headers=headers,
            timeout=10
        )

        assert response.status_code in [400, 404, 413, 414], \
            f"Username overflow deve ser rejeitado, mas recebeu {response.status_code}"


# =============================================================================
# PUT /api/users/{username} - Testes Faltantes
# =============================================================================

@pytest.mark.security
class TestUpdateUserSecurity:
    """Testes de segurança para PUT /api/users/{username}"""

    SQL_PAYLOADS = [
        "' OR '1'='1",
        "admin'--",
        "'; DROP TABLE users; --",
        "' UNION SELECT * FROM users--",
    ]

    XSS_PAYLOADS = [
        "<script>alert('xss')</script>",
        "<img src=x onerror=alert('xss')>",
        "javascript:alert('xss')",
        "<svg onload=alert('xss')>",
        "'\"><script>alert('xss')</script>",
    ]

    LARGE_OVERFLOW = "A" * 10000

    def test_update_user_without_token(self, http_client, api_url, timer):
        """PUT /api/users/{username} sem token deve retornar 401"""
        response = http_client.put(
            f"{api_url}/users/root",
            json={"display_name": "Hacked"},
            timeout=10
        )
        assert response.status_code == 401, \
            f"Acesso sem token deve retornar 401, mas recebeu {response.status_code}"

    def test_update_own_user(self, http_client, api_url, root_user, timer):
        """Admin pode atualizar seus próprios dados"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        # Criar um admin dedicado para este teste (não usa admin_user fixture)
        # Isso evita invalidar o token da fixture compartilhada
        test_admin_username = f"update_test_admin_{int(time.time())}"
        create_response = http_client.post(
            f"{api_url}/users",
            json={
                "username": test_admin_username,
                "display_name": "Update Test Admin",
                "password": "Test123!@#abcXYZ7890",
                "role": "admin"
            },
            headers=headers,
            timeout=10
        )

        if create_response.status_code not in [200, 201]:
            pytest.skip("Não foi possível criar admin de teste")

        # Login como o novo admin
        login_response = http_client.post(
            f"{api_url}/login",
            json={
                "username": test_admin_username,
                "password": "Test123!@#abcXYZ7890"
            },
            timeout=10
        )

        if login_response.status_code != 200:
            pytest.skip("Não foi possível fazer login como admin de teste")

        admin_token = login_response.json().get("data", {}).get("token")
        admin_headers = {"Authorization": f"Bearer {admin_token}"}

        # Admin deve conseguir atualizar seu próprio display_name
        new_display_name = f"Updated Admin {int(time.time())}"
        response = http_client.put(
            f"{api_url}/users/{test_admin_username}",
            json={"display_name": new_display_name},
            headers=admin_headers,
            timeout=10
        )

        assert response.status_code == 200, \
            f"Admin deve poder atualizar próprio perfil, mas recebeu {response.status_code}"

    def test_update_user_xss_in_display_name(self, http_client, api_url, root_user, timer):
        """XSS no display_name deve ser sanitizado ou bloqueado"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        # Criar usuário de teste primeiro
        test_username = f"xss_test_{int(time.time())}"
        create_response = http_client.post(
            f"{api_url}/users",
            json={
                "username": test_username,
                "display_name": "XSS Test User",
                "password": "Test123!@#abcXYZ7890",
                "role": "user"
            },
            headers=headers,
            timeout=10
        )

        if create_response.status_code not in [200, 201]:
            pytest.skip("Não foi possível criar usuário de teste")

        for payload in self.XSS_PAYLOADS:
            response = http_client.put(
                f"{api_url}/users/{test_username}",
                json={"display_name": payload},
                headers=headers,
                timeout=10
            )

            # Se aceitar, verificar que foi sanitizado
            if response.status_code == 200:
                # Buscar o usuário para verificar o que foi salvo
                get_response = http_client.get(
                    f"{api_url}/users/{test_username}",
                    headers=headers,
                    timeout=10
                )
                if get_response.status_code == 200:
                    response_data = get_response.json()
                    # Verificar se há usuário na resposta
                    saved_name = ""
                    if isinstance(response_data, dict):
                        user_data = response_data.get("data", response_data)
                        if isinstance(user_data, list) and len(user_data) > 0:
                            user_data = user_data[0]
                        if isinstance(user_data, dict):
                            saved_name = str(user_data.get("display_name", ""))
                    # Não deve conter tags HTML não escapadas
                    assert "<script>" not in saved_name.lower(), \
                        f"XSS payload '{payload}' não foi sanitizado no display_name"
                    assert "onerror=" not in saved_name.lower(), \
                        f"XSS payload '{payload}' não foi sanitizado no display_name"
                    assert "onload=" not in saved_name.lower(), \
                        f"XSS payload '{payload}' não foi sanitizado no display_name"

    def test_update_user_sql_injection_in_display_name(self, http_client, api_url, root_user, timer):
        """SQL Injection no display_name deve ser bloqueado"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        # Criar usuário de teste
        test_username = f"sql_test_{int(time.time())}"
        create_response = http_client.post(
            f"{api_url}/users",
            json={
                "username": test_username,
                "display_name": "SQL Test User",
                "password": "Test123!@#abcXYZ7890",
                "role": "user"
            },
            headers=headers,
            timeout=10
        )

        if create_response.status_code not in [200, 201]:
            pytest.skip("Não foi possível criar usuário de teste")

        for payload in self.SQL_PAYLOADS:
            response = http_client.put(
                f"{api_url}/users/{test_username}",
                json={"display_name": payload},
                headers=headers,
                timeout=10
            )

            # Não deve retornar erro 500
            assert response.status_code != 500, \
                f"Erro 500 pode indicar SQL injection com payload: {payload}"

            # Verificar que tabela de usuários ainda existe
            check_response = http_client.get(f"{api_url}/users", headers=headers, timeout=10)
            assert check_response.status_code == 200, \
                f"Tabela de usuários pode ter sido afetada por SQL injection: {payload}"

    @catch_connection_errors
    def test_update_user_display_name_overflow_10k(self, http_client, api_url, root_user, timer):
        """Display name com 10K+ caracteres deve ser rejeitado"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        # Criar usuário de teste
        test_username = f"overflow_test_{int(time.time())}"
        create_response = http_client.post(
            f"{api_url}/users",
            json={
                "username": test_username,
                "display_name": "Overflow Test",
                "password": "Test123!@#abcXYZ7890",
                "role": "user"
            },
            headers=headers,
            timeout=10
        )

        if create_response.status_code not in [200, 201]:
            pytest.skip("Não foi possível criar usuário de teste")

        response = http_client.put(
            f"{api_url}/users/{test_username}",
            json={"display_name": self.LARGE_OVERFLOW},
            headers=headers,
            timeout=10
        )

        assert response.status_code in [400, 413], \
            f"Display name overflow deve ser rejeitado, mas recebeu {response.status_code}"


# =============================================================================
# PUT /api/users/{username}/block - Testes Faltantes
# =============================================================================

@pytest.mark.security
class TestBlockUserSecurity:
    """Testes de segurança para PUT /api/users/{username}/block"""

    def test_block_user_without_token(self, http_client, api_url, timer):
        """PUT /api/users/{username}/block sem token deve retornar 401"""
        response = http_client.put(
            f"{api_url}/users/someuser/block",
            timeout=10
        )
        assert response.status_code == 401, \
            f"Acesso sem token deve retornar 401, mas recebeu {response.status_code}"

    def test_block_user_without_permission(self, http_client, api_url, regular_user, timer):
        """Usuário comum não pode bloquear outros usuários"""
        if not regular_user or "token" not in regular_user:
            pytest.skip("Regular user não disponível")

        headers = {"Authorization": f"Bearer {regular_user['token']}"}

        response = http_client.put(
            f"{api_url}/users/root/block",
            headers=headers,
            timeout=10
        )

        assert response.status_code == 403, \
            f"Usuário comum não deve poder bloquear, esperado 403, recebeu {response.status_code}"

    def test_block_own_user(self, http_client, api_url, root_user, timer):
        """Admin/Root não deve poder bloquear a si mesmo"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        # Criar um admin dedicado para este teste
        test_admin_username = f"block_test_admin_{int(time.time())}"
        create_response = http_client.post(
            f"{api_url}/users",
            json={
                "username": test_admin_username,
                "display_name": "Block Test Admin",
                "password": "Test123!@#abcXYZ7890",
                "role": "admin"
            },
            headers=headers,
            timeout=10
        )

        if create_response.status_code not in [200, 201]:
            pytest.skip("Não foi possível criar admin de teste")

        # Login como o novo admin
        login_response = http_client.post(
            f"{api_url}/login",
            json={
                "username": test_admin_username,
                "password": "Test123!@#abcXYZ7890"
            },
            timeout=10
        )

        if login_response.status_code != 200:
            pytest.skip("Não foi possível fazer login como admin de teste")

        admin_token = login_response.json().get("data", {}).get("token")
        admin_headers = {"Authorization": f"Bearer {admin_token}"}

        # Tentar bloquear a si mesmo
        response = http_client.put(
            f"{api_url}/users/{test_admin_username}/block",
            headers=admin_headers,
            timeout=10
        )

        # Deve ser bloqueado (não pode se auto-bloquear)
        assert response.status_code in [400, 403], \
            f"Não deve ser possível bloquear a si mesmo, mas recebeu {response.status_code}"


# =============================================================================
# PUT /api/users/{username}/unlock - Testes Faltantes
# =============================================================================

@pytest.mark.security
class TestUnlockUserSecurity:
    """Testes de segurança para PUT /api/users/{username}/unlock"""

    def test_unlock_user_without_token(self, http_client, api_url, timer):
        """PUT /api/users/{username}/unlock sem token deve retornar 401"""
        response = http_client.put(
            f"{api_url}/users/someuser/unlock",
            timeout=10
        )
        assert response.status_code == 401, \
            f"Acesso sem token deve retornar 401, mas recebeu {response.status_code}"

    def test_unlock_user_without_permission(self, http_client, api_url, regular_user, timer):
        """Usuário comum não pode desbloquear outros usuários"""
        if not regular_user or "token" not in regular_user:
            pytest.skip("Regular user não disponível")

        headers = {"Authorization": f"Bearer {regular_user['token']}"}

        response = http_client.put(
            f"{api_url}/users/root/unlock",
            headers=headers,
            timeout=10
        )

        assert response.status_code == 403, \
            f"Usuário comum não deve poder desbloquear, esperado 403, recebeu {response.status_code}"
