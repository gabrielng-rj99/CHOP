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
Testes de Segurança para APIs de Roles, Permissions, Session Policies e Password Policies
Cobertura completa de todos os endpoints relacionados a RBAC
"""

import pytest
import requests
import time
import uuid


class TestRolesAPIAuth:
    """Testes de autenticação para API de Roles"""

    def test_get_roles_requires_auth(self, http_client, api_url, timer):
        """GET /api/roles sem token deve retornar 401"""
        response = http_client.get(f"{api_url}/roles")
        assert response.status_code == 401

    def test_post_roles_requires_auth(self, http_client, api_url, timer):
        """POST /api/roles sem token deve retornar 401"""
        response = http_client.post(
            f"{api_url}/roles",
            json={"name": "test", "display_name": "Test", "priority": 100}
        )
        assert response.status_code == 401

    def test_get_role_by_id_requires_auth(self, http_client, api_url, timer):
        """GET /api/roles/{id} sem token deve retornar 401"""
        fake_id = str(uuid.uuid4())
        response = http_client.get(f"{api_url}/roles/{fake_id}")
        assert response.status_code == 401

    def test_put_role_requires_auth(self, http_client, api_url, timer):
        """PUT /api/roles/{id} sem token deve retornar 401"""
        fake_id = str(uuid.uuid4())
        response = http_client.put(
            f"{api_url}/roles/{fake_id}",
            json={"display_name": "Test", "priority": 100}
        )
        assert response.status_code == 401

    def test_delete_role_requires_auth(self, http_client, api_url, timer):
        """DELETE /api/roles/{id} sem token deve retornar 401"""
        fake_id = str(uuid.uuid4())
        response = http_client.delete(f"{api_url}/roles/{fake_id}")
        assert response.status_code == 401

    def test_get_permissions_requires_auth(self, http_client, api_url, timer):
        """GET /api/permissions sem token deve retornar 401"""
        response = http_client.get(f"{api_url}/permissions")
        assert response.status_code == 401

    def test_get_role_permissions_requires_auth(self, http_client, api_url, timer):
        """GET /api/roles/{id}/permissions sem token deve retornar 401"""
        fake_id = str(uuid.uuid4())
        response = http_client.get(f"{api_url}/roles/{fake_id}/permissions")
        assert response.status_code == 401

    def test_put_role_permissions_requires_auth(self, http_client, api_url, timer):
        """PUT /api/roles/{id}/permissions sem token deve retornar 401"""
        fake_id = str(uuid.uuid4())
        response = http_client.put(
            f"{api_url}/roles/{fake_id}/permissions",
            json={"permission_ids": []}
        )
        assert response.status_code == 401


class TestRolesAPIInputValidation:
    """Testes de validação de entrada para API de Roles"""

    def test_create_role_empty_body(self, http_client, api_url, root_user, timer):
        """Criar role com body vazio deve falhar"""
        response = http_client.post(
            f"{api_url}/roles",
            headers={"Authorization": f"Bearer {root_user['token']}"},
            json={}
        )
        assert response.status_code == 400

    def test_create_role_null_name(self, http_client, api_url, root_user, timer):
        """Criar role com nome null deve falhar"""
        response = http_client.post(
            f"{api_url}/roles",
            headers={"Authorization": f"Bearer {root_user['token']}"},
            json={"name": None, "display_name": "Test", "priority": 100}
        )
        assert response.status_code == 400

    def test_create_role_empty_name(self, http_client, api_url, root_user, timer):
        """Criar role com nome vazio deve falhar"""
        response = http_client.post(
            f"{api_url}/roles",
            headers={"Authorization": f"Bearer {root_user['token']}"},
            json={"name": "", "display_name": "Test", "priority": 100}
        )
        assert response.status_code == 400

    def test_create_role_invalid_priority_type(self, http_client, api_url, root_user, timer):
        """Criar role com priority como string deve falhar"""
        response = http_client.post(
            f"{api_url}/roles",
            headers={"Authorization": f"Bearer {root_user['token']}"},
            json={"name": "test_role", "display_name": "Test", "priority": "high"}
        )
        assert response.status_code == 400

    def test_update_role_invalid_id(self, http_client, api_url, root_user, timer):
        """Atualizar role com ID inválido deve falhar"""
        response = http_client.put(
            f"{api_url}/roles/invalid-uuid",
            headers={"Authorization": f"Bearer {root_user['token']}"},
            json={"display_name": "Test", "priority": 100}
        )
        # ID inválido DEVE retornar 400 ou 404, NUNCA 500
        # 500 indica vulnerabilidade - backend não validou UUID
        assert response.status_code in [400, 404], \
            f"UUID inválido retornou {response.status_code}, esperava 400/404 (NUNCA 500!)"

    def test_put_permissions_invalid_uuid_array(self, http_client, api_url, root_user, timer):
        """PUT permissions com UUIDs inválidos deve falhar"""
        # Primeiro obter um role válido
        roles_resp = http_client.get(
            f"{api_url}/roles",
            headers={"Authorization": f"Bearer {root_user['token']}"}
        )
        if roles_resp.status_code == 200:
            roles = roles_resp.json()
            if len(roles) > 0:
                role_id = roles[0].get("id")
                if role_id:
                    response = http_client.put(
                        f"{api_url}/roles/{role_id}/permissions",
                        headers={"Authorization": f"Bearer {root_user['token']}"},
                        json={"permission_ids": ["invalid", "not-a-uuid", "12345"]}
                    )
                    assert response.status_code in [400, 404]


class TestRolesXSSandSQLi:
    """Testes de XSS e SQL Injection para Roles"""

    XSS_PAYLOADS = [
        "<script>alert('XSS')</script>",
        "javascript:alert('XSS')",
        "<img src=x onerror=alert('XSS')>",
        "';alert('XSS');//",
    ]

    SQL_PAYLOADS = [
        "' OR '1'='1",
        "'; DROP TABLE roles;--",
        "' UNION SELECT * FROM users--",
    ]

    def test_create_role_xss_in_name(self, http_client, api_url, root_user, timer):
        """XSS no nome do role deve ser sanitizado"""
        for payload in self.XSS_PAYLOADS:
            response = http_client.post(
                f"{api_url}/roles",
                headers={"Authorization": f"Bearer {root_user['token']}"},
                json={
                    "name": f"xss_test_{hash(payload) % 10000}",
                    "display_name": payload,
                    "priority": 100
                }
            )
            # Pode aceitar sanitizado ou rejeitar
            if response.status_code == 201:
                data = response.json()
                # Se aceitar, verificar que está sanitizado
                assert "<script>" not in str(data)

    def test_create_role_sqli_in_name(self, http_client, api_url, root_user, timer):
        """SQL Injection no nome do role deve ser bloqueado"""
        for payload in self.SQL_PAYLOADS:
            response = http_client.post(
                f"{api_url}/roles",
                headers={"Authorization": f"Bearer {root_user['token']}"},
                json={
                    "name": payload,
                    "display_name": "Test",
                    "priority": 100
                }
            )
            # Não deve causar erro de SQL
            assert response.status_code in [201, 400]
            assert "sql" not in response.text.lower()
            assert "syntax" not in response.text.lower()


class TestRolesSecurityEscalation:
    """Testes de escalação de privilégios via Roles"""

    def test_user_cannot_create_role(self, http_client, api_url, regular_user, timer):
        """Usuário comum não pode criar roles"""
        response = http_client.post(
            f"{api_url}/roles",
            headers={"Authorization": f"Bearer {regular_user['token']}"},
            json={"name": "hacker_role", "display_name": "Hacker", "priority": 1}
        )
        assert response.status_code == 403

    def test_user_cannot_modify_permissions(self, http_client, api_url, regular_user, timer):
        """Usuário comum não pode modificar permissões de roles"""
        fake_id = str(uuid.uuid4())
        response = http_client.put(
            f"{api_url}/roles/{fake_id}/permissions",
            headers={"Authorization": f"Bearer {regular_user['token']}"},
            json={"permission_ids": [str(uuid.uuid4())]}
        )
        assert response.status_code in [403, 404]

    def test_cannot_delete_system_role(self, http_client, api_url, root_user, timer):
        """Não deve ser possível deletar roles de sistema"""
        # Buscar roles de sistema
        roles_resp = http_client.get(
            f"{api_url}/roles",
            headers={"Authorization": f"Bearer {root_user['token']}"}
        )
        if roles_resp.status_code == 200:
            for role in roles_resp.json():
                if role.get("is_system"):
                    response = http_client.delete(
                        f"{api_url}/roles/{role['id']}",
                        headers={"Authorization": f"Bearer {root_user['token']}"}
                    )
                    # Não deve permitir deletar role de sistema
                    assert response.status_code in [400, 403]


class TestSessionPoliciesAPI:
    """Testes para API de Session Policies"""

    def test_get_session_policies_requires_auth(self, http_client, api_url, timer):
        """GET /api/roles/session-policies sem token deve retornar 401"""
        response = http_client.get(f"{api_url}/roles/session-policies")
        assert response.status_code == 401

    def test_get_session_policy_requires_auth(self, http_client, api_url, timer):
        """GET /api/roles/{id}/session-policy sem token deve retornar 401"""
        fake_id = str(uuid.uuid4())
        response = http_client.get(f"{api_url}/roles/{fake_id}/session-policy")
        assert response.status_code == 401

    def test_put_session_policy_requires_auth(self, http_client, api_url, timer):
        """PUT /api/roles/{id}/session-policy sem token deve retornar 401"""
        fake_id = str(uuid.uuid4())
        response = http_client.put(
            f"{api_url}/roles/{fake_id}/session-policy",
            json={"session_duration_minutes": 60}
        )
        assert response.status_code == 401

    def test_user_cannot_modify_session_policy(self, http_client, api_url, regular_user, timer):
        """Usuário comum não pode modificar session policies"""
        fake_id = str(uuid.uuid4())
        response = http_client.put(
            f"{api_url}/roles/{fake_id}/session-policy",
            headers={"Authorization": f"Bearer {regular_user['token']}"},
            json={"session_duration_minutes": 60}
        )
        assert response.status_code in [403, 404]

    def test_session_policy_invalid_duration(self, http_client, api_url, root_user, timer):
        """Session duration fora do range (5-1440) deve falhar"""
        # Obter um role válido
        roles_resp = http_client.get(
            f"{api_url}/roles",
            headers={"Authorization": f"Bearer {root_user['token']}"}
        )
        if roles_resp.status_code == 200 and len(roles_resp.json()) > 0:
            role_id = roles_resp.json()[0].get("id")

            # Testar valores inválidos
            invalid_values = [0, 1, 4, 1441, 10000, -1, -100]
            for val in invalid_values:
                response = http_client.put(
                    f"{api_url}/roles/{role_id}/session-policy",
                    headers={"Authorization": f"Bearer {root_user['token']}"},
                    json={
                        "session_duration_minutes": val,
                        "refresh_token_duration_minutes": 60,
                        "require_2fa": False
                    }
                )
                assert response.status_code in [400, 422]


class TestPasswordPoliciesAPI:
    """Testes para API de Password Policies"""

    def test_get_password_policies_requires_auth(self, http_client, api_url, timer):
        """GET /api/roles/password-policies sem token deve retornar 401"""
        response = http_client.get(f"{api_url}/roles/password-policies")
        assert response.status_code == 401

    def test_get_password_policy_requires_auth(self, http_client, api_url, timer):
        """GET /api/roles/{id}/password-policy sem token deve retornar 401"""
        fake_id = str(uuid.uuid4())
        response = http_client.get(f"{api_url}/roles/{fake_id}/password-policy")
        assert response.status_code == 401

    def test_put_password_policy_requires_auth(self, http_client, api_url, timer):
        """PUT /api/roles/{id}/password-policy sem token deve retornar 401"""
        fake_id = str(uuid.uuid4())
        response = http_client.put(
            f"{api_url}/roles/{fake_id}/password-policy",
            json={"min_length": 8}
        )
        assert response.status_code == 401

    def test_user_cannot_modify_password_policy(self, http_client, api_url, regular_user, timer):
        """Usuário comum não pode modificar password policies"""
        fake_id = str(uuid.uuid4())
        response = http_client.put(
            f"{api_url}/roles/{fake_id}/password-policy",
            headers={"Authorization": f"Bearer {regular_user['token']}"},
            json={"min_length": 4}  # Tentando enfraquecer
        )
        assert response.status_code in [403, 404]

    def test_password_policy_xss_in_special_chars(self, http_client, api_url, root_user, timer):
        """XSS em allowed_special_chars deve ser bloqueado"""
        roles_resp = http_client.get(
            f"{api_url}/roles",
            headers={"Authorization": f"Bearer {root_user['token']}"}
        )
        if roles_resp.status_code == 200 and len(roles_resp.json()) > 0:
            role_id = roles_resp.json()[0].get("id")

            response = http_client.put(
                f"{api_url}/roles/{role_id}/password-policy",
                headers={"Authorization": f"Bearer {root_user['token']}"},
                json={
                    "min_length": 8,
                    "max_length": 128,
                    "require_uppercase": True,
                    "require_lowercase": True,
                    "require_numbers": True,
                    "require_special": True,
                    "allowed_special_chars": "<script>alert('XSS')</script>",
                    "no_username_in_password": True,
                    "no_common_passwords": True
                }
            )
            # Pode aceitar sanitizado ou rejeitar
            if response.status_code == 200:
                assert "<script>" not in response.text


class TestUserPermissionsAPI:
    """Testes para endpoints de permissões do usuário"""

    def test_get_user_permissions_requires_auth(self, http_client, api_url, timer):
        """GET /api/user/permissions sem token deve retornar 401"""
        response = http_client.get(f"{api_url}/user/permissions")
        assert response.status_code == 401

    def test_check_permission_requires_auth(self, http_client, api_url, timer):
        """GET /api/user/check-permission sem token deve retornar 401"""
        response = http_client.get(
            f"{api_url}/user/check-permission",
            params={"resource": "users", "action": "read"}
        )
        assert response.status_code == 401

    def test_check_permission_sqli_in_resource(self, http_client, api_url, root_user, timer):
        """SQL Injection em resource param deve ser bloqueado"""
        sqli_payloads = [
            "users' OR '1'='1",
            "users; DROP TABLE permissions;--",
            "users UNION SELECT * FROM users--",
        ]

        for payload in sqli_payloads:
            response = http_client.get(
                f"{api_url}/user/check-permission",
                headers={"Authorization": f"Bearer {root_user['token']}"},
                params={"resource": payload, "action": "read"}
            )
            assert response.status_code in [200, 400]
            # Não deve vazar erro SQL
            assert "syntax" not in response.text.lower()
            assert "sql" not in response.text.lower()

    def test_check_permission_sqli_in_action(self, http_client, api_url, root_user, timer):
        """SQL Injection em action param deve ser bloqueado"""
        sqli_payloads = [
            "read' OR '1'='1",
            "read; DROP TABLE users;--",
        ]

        for payload in sqli_payloads:
            response = http_client.get(
                f"{api_url}/user/check-permission",
                headers={"Authorization": f"Bearer {root_user['token']}"},
                params={"resource": "users", "action": payload}
            )
            assert response.status_code in [200, 400]
            assert "syntax" not in response.text.lower()

    def test_user_permissions_returns_correct_structure(self, http_client, api_url, root_user, timer):
        """GET /api/user/permissions deve retornar estrutura correta"""
        response = http_client.get(
            f"{api_url}/user/permissions",
            headers={"Authorization": f"Bearer {root_user['token']}"}
        )
        assert response.status_code == 200
        data = response.json()

        # Verificar campos esperados
        assert "user_id" in data or "role" in data or "permissions" in data

        # Não deve expor dados sensíveis - verificar chaves do dict
        data_str = str(data).lower()
        # 'password' no contexto de 'password_policy' é ok
        if "password" in data_str:
            # Verificar que não é um hash ou valor real de senha
            assert "password_hash" not in data_str
            assert "$2a$" not in data_str  # bcrypt hash
        assert "secret" not in data_str or "secret_key" not in data_str
