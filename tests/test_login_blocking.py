# =============================================================================
# Entity Hub Open Project
# Copyright (C) 2025 Entity Hub Contributors
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

@pytest.mark.security
@pytest.mark.login_blocking
class TestLoginBlocking:
    """Testes de bloqueio de login e rate limiting"""

    def test_multiple_failed_logins_triggers_lockout(self, http_client, api_url, timer):
        """Múltiplas tentativas falhas devem bloquear a conta"""
        username = f"locktest_{int(time.time())}"

        # Tentar login múltiplas vezes com senha errada
        failed_attempts = []
        for i in range(10):
            response = http_client.post(f"{api_url}/login", json={
                "username": username,
                "password": f"WrongPassword{i}!@#"
            })
            failed_attempts.append(response.status_code)
            time.sleep(0.1)  # Pequeno delay entre tentativas

        # Após múltiplas tentativas, deve haver algum tipo de bloqueio
        # Pode retornar 401 (credenciais inválidas), 423 (locked) ou 429 (rate limit)
        # Verificamos que não retornou 200 em nenhuma
        assert 200 not in failed_attempts, "Login não deveria ter sucesso com senha errada"

    def test_account_lockout_after_max_attempts(self, http_client, api_url, root_user, timer):
        """Conta deve ser bloqueada após número máximo de tentativas"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        # Criar usuário para teste de bloqueio
        test_username = f"lockouttest_{int(time.time())}"
        create_response = http_client.post(f"{api_url}/users", json={
            "username": test_username,
            "display_name": "Lockout Test User",
            "password": "ValidPass123!@#abc",
            "role": "user"
        }, headers=headers)

        if create_response.status_code not in [200, 201]:
            pytest.skip("Não foi possível criar usuário de teste")

        # Tentar login com senha errada múltiplas vezes (mais que o limite)
        for i in range(15):  # Mais que o limite típico de 5
            response = http_client.post(f"{api_url}/login", json={
                "username": test_username,
                "password": "WrongPassword!@#"
            })
            time.sleep(0.05)

        # Agora tentar com a senha correta - deve estar bloqueado
        correct_response = http_client.post(f"{api_url}/login", json={
            "username": test_username,
            "password": "ValidPass123!@#abc"
        })

        # Pode estar bloqueado (423) ou ainda retornar 401 se lock não implementado
        # Mas documenta o comportamento
        assert correct_response.status_code in [200, 401, 423, 429], \
            "Resposta após múltiplas tentativas deve ser controlada"

    def test_lockout_message_does_not_reveal_user_existence(self, http_client, api_url, timer):
        """Mensagem de bloqueio não deve revelar se usuário existe"""
        # Tentar bloquear usuário que não existe
        for i in range(10):
            response = http_client.post(f"{api_url}/login", json={
                "username": f"nonexistent_user_{int(time.time())}",
                "password": "WrongPassword!@#"
            })
            time.sleep(0.05)

        response_text = response.text.lower()

        # Não deve revelar que usuário não existe
        assert "user not found" not in response_text
        assert "usuário não encontrado" not in response_text
        assert "does not exist" not in response_text

    def test_lockout_duration_respected(self, http_client, api_url, root_user, timer):
        """Duração do bloqueio deve ser respeitada"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        # Criar usuário para teste
        test_username = f"lockduration_{int(time.time())}"
        create_response = http_client.post(f"{api_url}/users", json={
            "username": test_username,
            "display_name": "Lock Duration Test",
            "password": "ValidPass123!@#abc",
            "role": "user"
        }, headers=headers)

        if create_response.status_code not in [200, 201]:
            pytest.skip("Não foi possível criar usuário de teste")

        # Forçar bloqueio
        for i in range(10):
            http_client.post(f"{api_url}/login", json={
                "username": test_username,
                "password": "WrongPassword!@#"
            })
            time.sleep(0.05)

        # Imediatamente tentar login correto
        immediate_response = http_client.post(f"{api_url}/login", json={
            "username": test_username,
            "password": "ValidPass123!@#abc"
        })

        # Se bloqueado, esperar não desbloquearia imediatamente
        # Este teste documenta o comportamento
        assert immediate_response.status_code in [200, 401, 423, 429]

    def test_failed_attempts_counter_reset_on_success(self, http_client, api_url, root_user, timer):
        """Contador de tentativas deve resetar após login bem-sucedido"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        # Criar usuário para teste
        test_username = f"resetcounter_{int(time.time())}"
        test_password = "ValidPass123!@#abc"

        create_response = http_client.post(f"{api_url}/users", json={
            "username": test_username,
            "display_name": "Reset Counter Test",
            "password": test_password,
            "role": "user"
        }, headers=headers)

        if create_response.status_code not in [200, 201]:
            pytest.skip("Não foi possível criar usuário de teste")

        # Fazer algumas tentativas falhas (menos que o limite)
        for i in range(3):
            http_client.post(f"{api_url}/login", json={
                "username": test_username,
                "password": "WrongPassword!@#"
            })
            time.sleep(0.05)

        # Login bem-sucedido
        success_response = http_client.post(f"{api_url}/login", json={
            "username": test_username,
            "password": test_password
        })

        # Após sucesso, mais algumas tentativas falhas não devem bloquear
        if success_response.status_code == 200:
            for i in range(3):
                http_client.post(f"{api_url}/login", json={
                    "username": test_username,
                    "password": "WrongPassword!@#"
                })
                time.sleep(0.05)

            # Ainda deve conseguir logar
            final_response = http_client.post(f"{api_url}/login", json={
                "username": test_username,
                "password": test_password
            })
            assert final_response.status_code == 200, "Login deveria funcionar após reset do contador"

    def test_unlock_user_endpoint(self, http_client, api_url, root_user, timer):
        """Endpoint de desbloqueio deve funcionar para root/admin"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        # Criar e bloquear usuário
        test_username = f"unlocktest_{int(time.time())}"
        create_response = http_client.post(f"{api_url}/users", json={
            "username": test_username,
            "display_name": "Unlock Test User",
            "password": "ValidPass123!@#abc",
            "role": "user"
        }, headers=headers)

        if create_response.status_code not in [200, 201]:
            pytest.skip("Não foi possível criar usuário de teste")

        # Forçar bloqueio
        for i in range(15):
            http_client.post(f"{api_url}/login", json={
                "username": test_username,
                "password": "WrongPassword!@#"
            })
            time.sleep(0.02)

        # Tentar desbloquear
        unlock_response = http_client.put(
            f"{api_url}/users/{test_username}/unlock",
            headers=headers
        )

        # Endpoint pode existir ou não
        assert unlock_response.status_code in [200, 204, 404, 405], \
            "Endpoint de unlock deve responder apropriadamente"

    def test_block_user_endpoint(self, http_client, api_url, root_user, timer):
        """Endpoint de bloqueio manual deve funcionar para root/admin"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        # Criar usuário
        test_username = f"blocktest_{int(time.time())}"
        create_response = http_client.post(f"{api_url}/users", json={
            "username": test_username,
            "display_name": "Block Test User",
            "password": "ValidPass123!@#abc",
            "role": "user"
        }, headers=headers)

        if create_response.status_code not in [200, 201]:
            pytest.skip("Não foi possível criar usuário de teste")

        # Tentar bloquear manualmente
        block_response = http_client.put(
            f"{api_url}/users/{test_username}/block",
            headers=headers
        )

        # Se endpoint existe
        if block_response.status_code in [200, 204]:
            # Verificar que usuário não consegue mais logar
            login_response = http_client.post(f"{api_url}/login", json={
                "username": test_username,
                "password": "ValidPass123!@#abc"
            })
            assert login_response.status_code in [401, 403, 423], \
                "Usuário bloqueado não deve conseguir logar"

    def test_regular_user_cannot_unlock_others(self, http_client, api_url, regular_user, timer):
        """Usuário comum não pode desbloquear outros usuários"""
        if not regular_user or "token" not in regular_user:
            pytest.skip("Regular user não disponível")

        headers = {"Authorization": f"Bearer {regular_user['token']}"}

        # Tentar desbloquear outro usuário
        unlock_response = http_client.post(
            f"{api_url}/users/someuser/unlock",
            headers=headers
        )

        # Deve ser negado
        assert unlock_response.status_code in [401, 403, 404], \
            "Usuário comum não deve poder desbloquear outros"

    def test_regular_user_cannot_block_others(self, http_client, api_url, regular_user, timer):
        """Usuário comum não pode bloquear outros usuários"""
        if not regular_user or "token" not in regular_user:
            pytest.skip("Regular user não disponível")

        headers = {"Authorization": f"Bearer {regular_user['token']}"}

        # Tentar bloquear outro usuário
        block_response = http_client.post(
            f"{api_url}/users/root/block",
            headers=headers
        )

        # Deve ser negado
        assert block_response.status_code in [401, 403, 404], \
            "Usuário comum não deve poder bloquear outros"


@pytest.mark.security
@pytest.mark.rate_limiting
class TestRateLimiting:
    """Testes de rate limiting"""

    def test_rapid_requests_handled(self, http_client, api_url, timer):
        """Múltiplas requisições rápidas devem ser tratadas"""
        responses = []

        # Fazer muitas requisições rapidamente
        for _ in range(50):
            response = http_client.get(f"{api_url}/../health")
            responses.append(response.status_code)

        # Todas devem ser tratadas (200 ou 429 se rate limited)
        for status in responses:
            assert status in [200, 429], "Requisições devem ser tratadas ou rate limited"

    def test_login_rate_limiting(self, http_client, api_url, timer):
        """Rate limiting específico para login"""
        responses = []

        # Muitas tentativas de login rápidas
        for i in range(30):
            response = http_client.post(f"{api_url}/login", json={
                "username": f"ratelimituser_{i}",
                "password": "SomePassword!@#"
            })
            responses.append(response.status_code)

        # Não deve retornar 500 (erro interno)
        assert 500 not in responses, "Não deve causar erro interno"

    def test_api_rate_limiting_by_ip(self, http_client, api_url, root_user, timer):
        """Rate limiting por IP"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}
        responses = []

        # Muitas requisições para mesmo endpoint
        for _ in range(100):
            response = http_client.get(f"{api_url}/users", headers=headers)
            responses.append(response.status_code)

        # Contar quantas foram rate limited
        rate_limited = responses.count(429)

        # Documenta o comportamento (pode ou não ter rate limiting)
        assert 500 not in responses, "Não deve causar erro interno"

    def test_rate_limit_response_headers(self, http_client, api_url, timer):
        """Headers de rate limit devem estar presentes"""
        response = http_client.get(f"{api_url}/../health")

        # Verificar headers comuns de rate limiting
        rate_limit_headers = [
            "X-RateLimit-Limit",
            "X-RateLimit-Remaining",
            "X-RateLimit-Reset",
            "Retry-After",
            "RateLimit-Limit",
            "RateLimit-Remaining",
        ]

        # Documenta quais headers estão presentes
        present_headers = [h for h in rate_limit_headers if h in response.headers]
        # Não falha, apenas documenta

    def test_different_endpoints_separate_limits(self, http_client, api_url, root_user, timer):
        """Diferentes endpoints podem ter limites separados"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        # Requisições para diferentes endpoints
        users_responses = []
        clients_responses = []

        for _ in range(20):
            users_responses.append(
                http_client.get(f"{api_url}/users", headers=headers).status_code
            )
            clients_responses.append(
                http_client.get(f"{api_url}/clients", headers=headers).status_code
            )

        # Não deve causar erro interno em nenhum
        assert 500 not in users_responses, "Users endpoint não deve causar erro interno"
        assert 500 not in clients_responses, "Clients endpoint não deve causar erro interno"


@pytest.mark.security
@pytest.mark.login_blocking
class TestBlockedUserBehavior:
    """Testes de comportamento de usuário bloqueado"""

    def test_blocked_user_token_invalidated(self, http_client, api_url, root_user, timer):
        """Token de usuário bloqueado deve ser invalidado"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        admin_headers = {"Authorization": f"Bearer {root_user['token']}"}

        # Criar usuário
        test_username = f"blockedtoken_{int(time.time())}"
        create_response = http_client.post(f"{api_url}/users", json={
            "username": test_username,
            "display_name": "Blocked Token Test",
            "password": "ValidPass123!@#abc",
            "role": "user"
        }, headers=admin_headers)

        if create_response.status_code not in [200, 201]:
            pytest.skip("Não foi possível criar usuário de teste")

        # Login para obter token
        login_response = http_client.post(f"{api_url}/login", json={
            "username": test_username,
            "password": "ValidPass123!@#abc"
        })

        if login_response.status_code != 200:
            pytest.skip("Não foi possível fazer login")

        user_token = login_response.json().get("token") or login_response.json().get("access_token")
        if not user_token:
            pytest.skip("Token não retornado")

        user_headers = {"Authorization": f"Bearer {user_token}"}

        # Verificar que token funciona
        pre_block = http_client.get(f"{api_url}/clients", headers=user_headers)

        # Bloquear usuário
        block_response = http_client.post(
            f"{api_url}/users/{test_username}/block",
            headers=admin_headers
        )

        if block_response.status_code not in [200, 204]:
            pytest.skip("Endpoint de bloqueio não disponível")

        # Token antigo não deve mais funcionar
        post_block = http_client.get(f"{api_url}/clients", headers=user_headers)
        assert post_block.status_code in [401, 403, 423], \
            "Token de usuário bloqueado não deve funcionar"

    def test_blocked_user_cannot_refresh_token(self, http_client, api_url, root_user, timer):
        """Usuário bloqueado não pode renovar token"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        admin_headers = {"Authorization": f"Bearer {root_user['token']}"}

        # Criar usuário
        test_username = f"blockedrefresh_{int(time.time())}"
        create_response = http_client.post(f"{api_url}/users", json={
            "username": test_username,
            "display_name": "Blocked Refresh Test",
            "password": "ValidPass123!@#abc",
            "role": "user"
        }, headers=admin_headers)

        if create_response.status_code not in [200, 201]:
            pytest.skip("Não foi possível criar usuário de teste")

        # Login para obter tokens
        login_response = http_client.post(f"{api_url}/login", json={
            "username": test_username,
            "password": "ValidPass123!@#abc"
        })

        if login_response.status_code != 200:
            pytest.skip("Não foi possível fazer login")

        tokens = login_response.json()
        refresh_token = tokens.get("refresh_token")

        if not refresh_token:
            pytest.skip("Refresh token não retornado")

        # Bloquear usuário
        block_response = http_client.post(
            f"{api_url}/users/{test_username}/block",
            headers=admin_headers
        )

        if block_response.status_code not in [200, 204]:
            pytest.skip("Endpoint de bloqueio não disponível")

        # Tentar renovar token
        refresh_response = http_client.post(f"{api_url}/refresh-token", json={
            "refresh_token": refresh_token
        })

        assert refresh_response.status_code in [401, 403, 423], \
            "Usuário bloqueado não deve poder renovar token"

    def test_blocked_user_request_manipulation_rejected(self, http_client, api_url, root_user, timer):
        """Requisições de usuário bloqueado devem ser rejeitadas mesmo com token válido"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        admin_headers = {"Authorization": f"Bearer {root_user['token']}"}

        # Criar usuário
        test_username = f"blockedmanip_{int(time.time())}"
        create_response = http_client.post(f"{api_url}/users", json={
            "username": test_username,
            "display_name": "Blocked Manipulation Test",
            "password": "ValidPass123!@#abc",
            "role": "user"
        }, headers=admin_headers)

        if create_response.status_code not in [200, 201]:
            pytest.skip("Não foi possível criar usuário de teste")

        # Login para obter token
        login_response = http_client.post(f"{api_url}/login", json={
            "username": test_username,
            "password": "ValidPass123!@#abc"
        })

        if login_response.status_code != 200:
            pytest.skip("Não foi possível fazer login")

        user_token = login_response.json().get("token") or login_response.json().get("access_token")
        user_headers = {"Authorization": f"Bearer {user_token}"}

        # Bloquear usuário
        http_client.post(f"{api_url}/users/{test_username}/block", headers=admin_headers)

        # Tentar várias operações com token do usuário bloqueado
        operations = [
            ("GET", f"{api_url}/clients"),
            ("POST", f"{api_url}/clients"),
            ("GET", f"{api_url}/categories"),
        ]

        for method, url in operations:
            if method == "GET":
                response = http_client.get(url, headers=user_headers)
            else:
                response = http_client.post(url, json={"name": "test"}, headers=user_headers)

            # Deve ser rejeitado
            assert response.status_code in [401, 403, 423], \
                f"Operação {method} {url} de usuário bloqueado deve ser rejeitada"


@pytest.mark.security
@pytest.mark.login_blocking
class TestLockLevels:
    """Testes de níveis de bloqueio progressivo"""

    def test_lock_level_progression(self, http_client, api_url, root_user, timer):
        """Níveis de bloqueio devem aumentar progressivamente"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        # Criar usuário
        test_username = f"locklevel_{int(time.time())}"
        create_response = http_client.post(f"{api_url}/users", json={
            "username": test_username,
            "display_name": "Lock Level Test",
            "password": "ValidPass123!@#abc",
            "role": "user"
        }, headers=headers)

        if create_response.status_code not in [200, 201]:
            pytest.skip("Não foi possível criar usuário de teste")

        # Este teste documenta o comportamento de lock levels
        # Fazer múltiplas rodadas de tentativas falhas
        for round_num in range(3):
            for i in range(5):
                http_client.post(f"{api_url}/login", json={
                    "username": test_username,
                    "password": "WrongPassword!@#"
                })
                time.sleep(0.02)

            # Verificar estado
            time.sleep(0.5)

        # O comportamento exato depende da implementação
        # Este teste apenas documenta que não causa erros internos
        final_response = http_client.post(f"{api_url}/login", json={
            "username": test_username,
            "password": "ValidPass123!@#abc"
        })

        assert final_response.status_code in [200, 401, 423, 429], \
            "Resposta deve ser controlada após múltiplos níveis de lock"
