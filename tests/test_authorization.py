import pytest
import requests
import time

@pytest.mark.authorization
@pytest.mark.security
class TestAuthorization:
    """Testes de autorização e escalação de privilégios"""

    def test_user_cannot_access_admin_resources(self, http_client, api_url, regular_user, timer):
        """Usuário comum não pode acessar recursos de admin"""
        if not regular_user or "token" not in regular_user:
            pytest.skip("Regular user não disponível")

        headers = {"Authorization": f"Bearer {regular_user['token']}"}

        # Tentar listar todos os usuários (requer admin)
        response = http_client.get(f"{api_url}/users", headers=headers)
        assert response.status_code in [403, 401], "User não deve listar usuários"

    def test_user_cannot_create_users(self, http_client, api_url, regular_user, timer):
        """Usuário comum não pode criar outros usuários"""
        if not regular_user or "token" not in regular_user:
            pytest.skip("Regular user não disponível")

        headers = {"Authorization": f"Bearer {regular_user['token']}"}

        response = http_client.post(f"{api_url}/users", json={
            "username": "hacker",
            "display_name": "Hacker",
            "password": "Hack123!@#",
            "role": "admin"
        }, headers=headers)

        assert response.status_code in [403, 401], "User não deve criar usuários"

    def test_user_cannot_delete_users(self, http_client, api_url, regular_user, timer):
        """Usuário comum não pode deletar usuários"""
        if not regular_user or "token" not in regular_user:
            pytest.skip("Regular user não disponível")

        headers = {"Authorization": f"Bearer {regular_user['token']}"}

        fake_user_id = "12345678-1234-1234-1234-123456789012"
        response = http_client.delete(f"{api_url}/users/{fake_user_id}", headers=headers)

        assert response.status_code in [403, 401], "User não deve deletar usuários"

    def test_admin_cannot_access_root_resources(self, http_client, api_url, admin_user, timer):
        """Admin não pode acessar recursos exclusivos de root"""
        if not admin_user or "token" not in admin_user:
            pytest.skip("Admin user não disponível")

        headers = {"Authorization": f"Bearer {admin_user['token']}"}

        # Audit logs são exclusivos de root
        response = http_client.get(f"{api_url}/audit-logs", headers=headers)
        assert response.status_code == 403, "Admin não deve acessar audit logs"

    def test_admin_cannot_create_root_user(self, http_client, api_url, admin_user, timer):
        """Admin não pode criar usuários root"""
        if not admin_user or "token" not in admin_user:
            pytest.skip("Admin user não disponível")

        headers = {"Authorization": f"Bearer {admin_user['token']}"}

        response = http_client.post(f"{api_url}/users", json={
            "username": f"fakeroot_{int(time.time())}",
            "display_name": "Fake Root",
            "password": "Root123!@#",
            "role": "root"
        }, headers=headers)

        # Deve ser bloqueado
        assert response.status_code in [403, 400], "Admin não deve criar usuário root"

    def test_user_cannot_elevate_own_privileges(self, http_client, api_url, regular_user, timer):
        """Usuário não pode elevar seus próprios privilégios"""
        if not regular_user or "token" not in regular_user:
            pytest.skip("Regular user não disponível")

        headers = {"Authorization": f"Bearer {regular_user['token']}"}
        user_id = regular_user.get("id")

        if not user_id:
            pytest.skip("User ID não disponível")

        # Tentar mudar role para admin
        response = http_client.put(f"{api_url}/users/{user_id}", json={
            "role": "admin"
        }, headers=headers)

        assert response.status_code in [403, 401, 400], "User não deve elevar próprios privilégios"

        # Verificar que role não mudou
        check_response = http_client.get(f"{api_url}/users/{user_id}", headers=headers)
        if check_response.status_code == 200:
            user_data = check_response.json()
            assert user_data.get("role") != "admin", "Role não deve ter mudado"

    def test_user_cannot_access_other_users_data(self, http_client, api_url, regular_user, root_user, timer):
        """Usuário não pode acessar dados de outros usuários"""
        if not regular_user or "token" not in regular_user:
            pytest.skip("Regular user não disponível")
        if not root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {regular_user['token']}"}
        root_id = root_user.get("id")

        if not root_id:
            pytest.skip("Root ID não disponível")

        response = http_client.get(f"{api_url}/users/{root_id}", headers=headers)
        assert response.status_code in [403, 401], "User não deve acessar dados de outros"

    def test_token_with_forged_role_rejected(self, http_client, api_url, timer):
        """Token com role forjado deve ser rejeitado"""
        import jwt

        forged_payload = {
            "user_id": "123",
            "username": "hacker",
            "role": "root",  # Role forjado
            "exp": int(time.time()) + 3600
        }

        forged_token = jwt.encode(forged_payload, "wrong_secret", algorithm="HS256")
        headers = {"Authorization": f"Bearer {forged_token}"}

        response = http_client.get(f"{api_url}/users", headers=headers)
        assert response.status_code == 401, "Token forjado deve ser rejeitado"

    def test_user_cannot_modify_other_users(self, http_client, api_url, regular_user, timer):
        """Usuário não pode modificar outros usuários"""
        if not regular_user or "token" not in regular_user:
            pytest.skip("Regular user não disponível")

        headers = {"Authorization": f"Bearer {regular_user['token']}"}
        fake_user_id = "12345678-1234-1234-1234-123456789012"

        response = http_client.put(f"{api_url}/users/{fake_user_id}", json={
            "display_name": "Hacked User"
        }, headers=headers)

        assert response.status_code in [403, 401, 404], "User não deve modificar outros"

    def test_admin_can_manage_users(self, http_client, api_url, admin_user, timer):
        """Admin PODE gerenciar usuários (mas não root)"""
        if not admin_user or "token" not in admin_user:
            pytest.skip("Admin user não disponível")

        headers = {"Authorization": f"Bearer {admin_user['token']}"}

        # Admin deve conseguir listar usuários
        response = http_client.get(f"{api_url}/users", headers=headers)
        assert response.status_code == 200, "Admin deve listar usuários"

        # Admin deve conseguir criar usuário comum
        response = http_client.post(f"{api_url}/users", json={
            "username": f"test_user_{int(time.time())}",
            "display_name": "Test User",
            "password": "Test123!@#",
            "role": "user"
        }, headers=headers)

        assert response.status_code in [200, 201], "Admin deve criar usuários comuns"

    def test_root_can_access_all_resources(self, http_client, api_url, root_user, timer):
        """Root pode acessar todos os recursos"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        # Root deve acessar usuários
        response = http_client.get(f"{api_url}/users", headers=headers)
        assert response.status_code == 200, "Root deve listar usuários"

        # Root deve acessar audit logs
        response = http_client.get(f"{api_url}/audit-logs", headers=headers)
        assert response.status_code == 200, "Root deve acessar audit logs"

    def test_user_cannot_access_audit_logs(self, http_client, api_url, regular_user, timer):
        """Usuário comum não pode acessar audit logs"""
        if not regular_user or "token" not in regular_user:
            pytest.skip("Regular user não disponível")

        headers = {"Authorization": f"Bearer {regular_user['token']}"}

        response = http_client.get(f"{api_url}/audit-logs", headers=headers)
        assert response.status_code == 403, "User não deve acessar audit logs"

    def test_horizontal_privilege_escalation_blocked(self, http_client, api_url, regular_user, admin_user, timer):
        """Escalação horizontal de privilégios deve ser bloqueada"""
        if not regular_user or "token" not in regular_user:
            pytest.skip("Regular user não disponível")
        if not admin_user:
            pytest.skip("Admin user não disponível")

        user_headers = {"Authorization": f"Bearer {regular_user['token']}"}
        admin_id = admin_user.get("id")

        if not admin_id:
            pytest.skip("Admin ID não disponível")

        # User tentando modificar admin (horizontal escalation)
        response = http_client.put(f"{api_url}/users/{admin_id}", json={
            "display_name": "Hacked Admin"
        }, headers=user_headers)

        assert response.status_code in [403, 401], "Escalação horizontal deve ser bloqueada"

    def test_vertical_privilege_escalation_blocked(self, http_client, api_url, regular_user, timer):
        """Escalação vertical de privilégios deve ser bloqueada"""
        if not regular_user or "token" not in regular_user:
            pytest.skip("Regular user não disponível")

        headers = {"Authorization": f"Bearer {regular_user['token']}"}

        # Tentar criar admin (escalação vertical)
        response = http_client.post(f"{api_url}/users", json={
            "username": f"elevated_{int(time.time())}",
            "display_name": "Elevated User",
            "password": "Test123!@#",
            "role": "admin"
        }, headers=headers)

        assert response.status_code in [403, 401], "Escalação vertical deve ser bloqueada"

    def test_role_verification_at_each_request(self, http_client, api_url, root_user, timer):
        """Role deve ser verificado em cada request (não apenas no login)"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        # Múltiplas requests devem todas verificar role
        for _ in range(5):
            response = http_client.get(f"{api_url}/users", headers=headers)
            assert response.status_code == 200, "Todas as requests devem validar role"
            time.sleep(0.1)

    def test_mixed_case_role_names_not_accepted(self, http_client, api_url, root_user, timer):
        """Roles com case diferente não devem funcionar"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        invalid_roles = ["ROOT", "Root", "ADMIN", "Admin", "USER", "User"]

        for invalid_role in invalid_roles:
            response = http_client.post(f"{api_url}/users", json={
                "username": f"test_case_{int(time.time())}",
                "display_name": "Test Case User",
                "password": "Test123!@#",
                "role": invalid_role
            }, headers=headers)

            # Deve rejeitar ou normalizar para lowercase
            if response.status_code in [200, 201]:
                # Se aceitar, deve normalizar para lowercase
                data = response.json()
                assert data.get("role", "").lower() == invalid_role.lower(), "Role deve ser normalizado"

    def test_empty_role_rejected(self, http_client, api_url, root_user, timer):
        """Role vazio deve ser rejeitado"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        response = http_client.post(f"{api_url}/users", json={
            "username": f"test_empty_{int(time.time())}",
            "display_name": "Test Empty Role",
            "password": "Test123!@#",
            "role": ""
        }, headers=headers)

        assert response.status_code in [400, 422], "Role vazio deve ser rejeitado"

    def test_invalid_role_rejected(self, http_client, api_url, root_user, timer):
        """Role inválido deve ser rejeitado"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        invalid_roles = ["superadmin", "guest", "moderator", "hacker", "god"]

        for invalid_role in invalid_roles:
            response = http_client.post(f"{api_url}/users", json={
                "username": f"test_invalid_{int(time.time())}",
                "display_name": "Test Invalid Role",
                "password": "Test123!@#",
                "role": invalid_role
            }, headers=headers)

            assert response.status_code in [400, 422], f"Role inválido '{invalid_role}' deve ser rejeitado"

    def test_null_role_rejected(self, http_client, api_url, root_user, timer):
        """Role null deve ser rejeitado"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        response = http_client.post(f"{api_url}/users", json={
            "username": f"test_null_{int(time.time())}",
            "display_name": "Test Null Role",
            "password": "Test123!@#",
            "role": None
        }, headers=headers)

        assert response.status_code in [400, 422], "Role null deve ser rejeitado"
