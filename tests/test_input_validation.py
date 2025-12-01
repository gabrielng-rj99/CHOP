import pytest
import requests
import time
import json

@pytest.mark.security
@pytest.mark.validation
class TestEmptyRequests:
    """Testes de validação de requisições vazias"""

    def test_login_empty_body(self, http_client, api_url, timer):
        """Login com body vazio deve retornar erro apropriado"""
        response = http_client.post(f"{api_url}/login", json={})
        assert response.status_code in [400, 401], "Body vazio deve ser rejeitado"
        assert response.status_code != 500, "Não deve causar erro interno"

    def test_login_no_body(self, http_client, api_url, timer):
        """Login sem body deve retornar erro apropriado"""
        response = http_client.post(f"{api_url}/login")
        assert response.status_code in [400, 401, 415], "Request sem body deve ser rejeitado"
        assert response.status_code != 500, "Não deve causar erro interno"

    def test_create_user_empty_body(self, http_client, api_url, root_user, timer):
        """Criar usuário com body vazio deve ser rejeitado"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}
        response = http_client.post(f"{api_url}/users", json={}, headers=headers)

        assert response.status_code in [400, 422], "Body vazio deve ser rejeitado"
        assert response.status_code != 500, "Não deve causar erro interno"

    def test_create_client_empty_body(self, http_client, api_url, root_user, timer):
        """Criar cliente com body vazio deve ser rejeitado"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}
        response = http_client.post(f"{api_url}/clients", json={}, headers=headers)

        assert response.status_code in [400, 422], "Body vazio deve ser rejeitado"
        assert response.status_code != 500, "Não deve causar erro interno"

    def test_create_category_empty_body(self, http_client, api_url, root_user, timer):
        """Criar categoria com body vazio deve ser rejeitado"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}
        response = http_client.post(f"{api_url}/categories", json={}, headers=headers)

        assert response.status_code in [400, 422], "Body vazio deve ser rejeitado"
        assert response.status_code != 500, "Não deve causar erro interno"

    def test_create_contract_empty_body(self, http_client, api_url, root_user, timer):
        """Criar contrato com body vazio deve ser rejeitado"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}
        response = http_client.post(f"{api_url}/contracts", json={}, headers=headers)

        assert response.status_code in [400, 422], "Body vazio deve ser rejeitado"
        assert response.status_code != 500, "Não deve causar erro interno"

    def test_refresh_token_empty_body(self, http_client, api_url, timer):
        """Refresh token com body vazio deve ser rejeitado"""
        response = http_client.post(f"{api_url}/refresh-token", json={})

        assert response.status_code in [400, 401], "Body vazio deve ser rejeitado"
        assert response.status_code != 500, "Não deve causar erro interno"


@pytest.mark.security
@pytest.mark.validation
class TestNullValues:
    """Testes de validação de valores null"""

    def test_login_null_username(self, http_client, api_url, timer):
        """Login com username null deve ser rejeitado"""
        response = http_client.post(f"{api_url}/login", json={
            "username": None,
            "password": "SomePassword123!@#"
        })
        assert response.status_code in [400, 401], "Username null deve ser rejeitado"

    def test_login_null_password(self, http_client, api_url, timer):
        """Login com password null deve ser rejeitado"""
        response = http_client.post(f"{api_url}/login", json={
            "username": "root",
            "password": None
        })
        assert response.status_code in [400, 401], "Password null deve ser rejeitado"

    def test_create_user_null_fields(self, http_client, api_url, root_user, timer):
        """Criar usuário com campos null deve ser rejeitado"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        # Username null
        response = http_client.post(f"{api_url}/users", json={
            "username": None,
            "display_name": "Test",
            "password": "ValidPass123!@#a",
            "role": "user"
        }, headers=headers)
        assert response.status_code in [400, 422], "Username null deve ser rejeitado"

        # Password null
        response = http_client.post(f"{api_url}/users", json={
            "username": f"testuser_{int(time.time())}",
            "display_name": "Test",
            "password": None,
            "role": "user"
        }, headers=headers)
        assert response.status_code in [400, 422], "Password null deve ser rejeitado"

        # Role null
        response = http_client.post(f"{api_url}/users", json={
            "username": f"testuser_{int(time.time())}",
            "display_name": "Test",
            "password": "ValidPass123!@#a",
            "role": None
        }, headers=headers)
        assert response.status_code in [400, 422], "Role null deve ser rejeitado"

    def test_create_client_null_name(self, http_client, api_url, root_user, timer):
        """Criar cliente com nome null deve ser rejeitado"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}
        response = http_client.post(f"{api_url}/clients", json={
            "name": None,
            "email": "test@test.com"
        }, headers=headers)

        assert response.status_code in [400, 422], "Nome null deve ser rejeitado"


@pytest.mark.security
@pytest.mark.validation
class TestInvalidTypes:
    """Testes de validação de tipos inválidos"""

    def test_login_array_username(self, http_client, api_url, timer):
        """Login com username como array deve ser rejeitado"""
        response = http_client.post(f"{api_url}/login", json={
            "username": ["root", "admin"],
            "password": "SomePassword123!@#"
        })
        assert response.status_code in [400, 401], "Array como username deve ser rejeitado"

    def test_login_object_password(self, http_client, api_url, timer):
        """Login com password como objeto deve ser rejeitado"""
        response = http_client.post(f"{api_url}/login", json={
            "username": "root",
            "password": {"value": "SomePassword123!@#"}
        })
        assert response.status_code in [400, 401], "Objeto como password deve ser rejeitado"

    def test_login_number_username(self, http_client, api_url, timer):
        """Login com username como número deve ser tratado corretamente"""
        response = http_client.post(f"{api_url}/login", json={
            "username": 12345,
            "password": "SomePassword123!@#"
        })
        # Pode converter para string ou rejeitar
        assert response.status_code in [400, 401], "Número como username deve ser tratado"

    def test_create_user_role_as_number(self, http_client, api_url, root_user, timer):
        """Criar usuário com role como número deve ser rejeitado"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}
        response = http_client.post(f"{api_url}/users", json={
            "username": f"typetest_{int(time.time())}",
            "display_name": "Type Test",
            "password": "ValidPass123!@#a",
            "role": 1  # Número em vez de string
        }, headers=headers)

        assert response.status_code in [400, 422], "Role como número deve ser rejeitado"

    def test_create_user_role_as_array(self, http_client, api_url, root_user, timer):
        """Criar usuário com role como array deve ser rejeitado"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}
        response = http_client.post(f"{api_url}/users", json={
            "username": f"arraytest_{int(time.time())}",
            "display_name": "Array Test",
            "password": "ValidPass123!@#a",
            "role": ["admin", "user"]  # Array em vez de string
        }, headers=headers)

        assert response.status_code in [400, 422], "Role como array deve ser rejeitado"


@pytest.mark.security
@pytest.mark.validation
class TestMalformedJSON:
    """Testes de validação de JSON malformado"""

    def test_login_malformed_json(self, http_client, api_url, timer):
        """Login com JSON malformado deve retornar erro apropriado"""
        headers = {"Content-Type": "application/json"}

        malformed_jsons = [
            '{"username": "root", "password": }',  # Valor ausente
            '{"username": "root" "password": "test"}',  # Vírgula faltando
            "{'username': 'root', 'password': 'test'}",  # Aspas simples
            '{"username": "root", "password": "test"',  # Chave não fechada
            'username=root&password=test',  # URL encoded
            '<username>root</username>',  # XML
        ]

        for malformed in malformed_jsons:
            response = requests.post(
                f"{api_url}/login",
                data=malformed,
                headers=headers
            )
            assert response.status_code in [400, 401, 415], f"JSON malformado deve ser rejeitado: {malformed}"
            assert response.status_code != 500, f"Não deve causar erro interno: {malformed}"

    def test_create_user_malformed_json(self, http_client, api_url, root_user, timer):
        """Criar usuário com JSON malformado deve retornar erro apropriado"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {
            "Authorization": f"Bearer {root_user['token']}",
            "Content-Type": "application/json"
        }

        response = requests.post(
            f"{api_url}/users",
            data='{"username": "test", "password": }',
            headers=headers
        )
        assert response.status_code in [400, 422], "JSON malformado deve ser rejeitado"
        assert response.status_code != 500, "Não deve causar erro interno"


@pytest.mark.security
@pytest.mark.validation
class TestFieldLengthValidation:
    """Testes de validação de tamanho de campos"""

    def test_username_too_short(self, http_client, api_url, root_user, timer):
        """Username muito curto deve ser rejeitado"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}
        response = http_client.post(f"{api_url}/users", json={
            "username": "ab",  # Muito curto
            "display_name": "Short Username",
            "password": "ValidPass123!@#a",
            "role": "user"
        }, headers=headers)

        assert response.status_code in [400, 422], "Username muito curto deve ser rejeitado"

    def test_username_too_long(self, http_client, api_url, root_user, timer):
        """Username muito longo deve ser tratado"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}
        long_username = "a" * 500  # 500 caracteres

        response = http_client.post(f"{api_url}/users", json={
            "username": long_username,
            "display_name": "Long Username",
            "password": "ValidPass123!@#a",
            "role": "user"
        }, headers=headers)

        # Deve rejeitar ou truncar
        assert response.status_code in [200, 201, 400, 422], "Username longo deve ser tratado"
        assert response.status_code != 500, "Não deve causar erro interno"

    def test_display_name_too_long(self, http_client, api_url, root_user, timer):
        """Display name muito longo deve ser tratado"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}
        long_name = "A" * 1000  # 1000 caracteres

        response = http_client.post(f"{api_url}/users", json={
            "username": f"longname_{int(time.time())}",
            "display_name": long_name,
            "password": "ValidPass123!@#a",
            "role": "user"
        }, headers=headers)

        assert response.status_code in [200, 201, 400, 422], "Display name longo deve ser tratado"
        assert response.status_code != 500, "Não deve causar erro interno"

    def test_client_name_too_long(self, http_client, api_url, root_user, timer):
        """Nome de cliente muito longo deve ser tratado"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}
        long_name = "Cliente " + "A" * 10000  # 10000+ caracteres

        response = http_client.post(f"{api_url}/clients", json={
            "name": long_name,
            "email": "test@test.com"
        }, headers=headers)

        assert response.status_code in [200, 201, 400, 413, 422], "Nome longo deve ser tratado"
        assert response.status_code != 500, "Não deve causar erro interno"

    def test_notes_very_long(self, http_client, api_url, root_user, timer):
        """Notas muito longas devem ser tratadas"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}
        very_long_notes = "Nota " * 50000  # Muitos caracteres

        response = http_client.post(f"{api_url}/clients", json={
            "name": f"Long Notes Client {int(time.time())}",
            "notes": very_long_notes,
            "email": "test@test.com"
        }, headers=headers)

        assert response.status_code in [200, 201, 400, 413, 422], "Notas longas devem ser tratadas"
        assert response.status_code != 500, "Não deve causar erro interno"


@pytest.mark.security
@pytest.mark.validation
class TestSpecialCharacters:
    """Testes de caracteres especiais em campos"""

    def test_username_with_special_chars(self, http_client, api_url, root_user, timer):
        """Username com caracteres especiais deve ser tratado"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        special_usernames = [
            "user@test",
            "user#test",
            "user$test",
            "user%test",
            "user&test",
            "user*test",
            "user(test)",
            "user[test]",
            "user{test}",
            "user<test>",
            "user;test",
            "user|test",
            "user\\test",
            "user/test",
            "user'test",
            'user"test',
        ]

        for username in special_usernames:
            response = http_client.post(f"{api_url}/users", json={
                "username": username,
                "display_name": "Special Char User",
                "password": "ValidPass123!@#a",
                "role": "user"
            }, headers=headers)

            # Pode aceitar ou rejeitar, mas não deve causar erro interno
            assert response.status_code in [200, 201, 400, 422], f"Caractere especial '{username}' não tratado"
            assert response.status_code != 500, f"Erro interno com username: {username}"

    def test_newline_in_fields(self, http_client, api_url, root_user, timer):
        """Quebras de linha em campos devem ser tratadas"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        response = http_client.post(f"{api_url}/clients", json={
            "name": "Client\nWith\nNewlines",
            "email": "test@test.com"
        }, headers=headers)

        assert response.status_code in [200, 201, 400, 422], "Newlines devem ser tratadas"
        assert response.status_code != 500, "Não deve causar erro interno"

    def test_tab_in_fields(self, http_client, api_url, root_user, timer):
        """Tabs em campos devem ser tratados"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        response = http_client.post(f"{api_url}/clients", json={
            "name": "Client\tWith\tTabs",
            "email": "test@test.com"
        }, headers=headers)

        assert response.status_code in [200, 201, 400, 422], "Tabs devem ser tratados"
        assert response.status_code != 500, "Não deve causar erro interno"

    def test_null_bytes_in_fields(self, http_client, api_url, root_user, timer):
        """Null bytes em campos devem ser tratados"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        response = http_client.post(f"{api_url}/clients", json={
            "name": "Client\x00With\x00NullBytes",
            "email": "test@test.com"
        }, headers=headers)

        assert response.status_code in [200, 201, 400, 422], "Null bytes devem ser tratados"
        assert response.status_code != 500, "Não deve causar erro interno"


@pytest.mark.security
@pytest.mark.validation
class TestRequiredFields:
    """Testes de campos obrigatórios"""

    def test_create_user_missing_username(self, http_client, api_url, root_user, timer):
        """Criar usuário sem username deve ser rejeitado"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}
        response = http_client.post(f"{api_url}/users", json={
            "display_name": "Missing Username",
            "password": "ValidPass123!@#a",
            "role": "user"
        }, headers=headers)

        assert response.status_code in [400, 422], "Falta de username deve ser rejeitada"

    def test_create_user_missing_password(self, http_client, api_url, root_user, timer):
        """Criar usuário sem password deve ser rejeitado"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}
        response = http_client.post(f"{api_url}/users", json={
            "username": f"nopass_{int(time.time())}",
            "display_name": "Missing Password",
            "role": "user"
        }, headers=headers)

        assert response.status_code in [400, 422], "Falta de password deve ser rejeitada"

    def test_create_user_missing_role(self, http_client, api_url, root_user, timer):
        """Criar usuário sem role deve ser rejeitado"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}
        response = http_client.post(f"{api_url}/users", json={
            "username": f"norole_{int(time.time())}",
            "display_name": "Missing Role",
            "password": "ValidPass123!@#a"
        }, headers=headers)

        assert response.status_code in [400, 422], "Falta de role deve ser rejeitada"

    def test_create_client_missing_name(self, http_client, api_url, root_user, timer):
        """Criar cliente sem nome deve ser rejeitado"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}
        response = http_client.post(f"{api_url}/clients", json={
            "email": "test@test.com"
        }, headers=headers)

        assert response.status_code in [400, 422], "Falta de nome deve ser rejeitada"

    def test_create_category_missing_name(self, http_client, api_url, root_user, timer):
        """Criar categoria sem nome deve ser rejeitado"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}
        response = http_client.post(f"{api_url}/categories", json={}, headers=headers)

        assert response.status_code in [400, 422], "Falta de nome deve ser rejeitada"

    def test_create_contract_missing_required_fields(self, http_client, api_url, root_user, timer):
        """Criar contrato sem campos obrigatórios deve ser rejeitado"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        # Sem line_id
        response = http_client.post(f"{api_url}/contracts", json={
            "client_id": "12345678-1234-1234-1234-123456789012"
        }, headers=headers)
        assert response.status_code in [400, 422], "Falta de line_id deve ser rejeitada"

        # Sem client_id
        response = http_client.post(f"{api_url}/contracts", json={
            "line_id": "12345678-1234-1234-1234-123456789012"
        }, headers=headers)
        assert response.status_code in [400, 422], "Falta de client_id deve ser rejeitada"


@pytest.mark.security
@pytest.mark.validation
class TestUUIDValidation:
    """Testes de validação de UUID e identificadores inválidos"""

    def test_invalid_identifier_format(self, http_client, api_url, root_user, timer):
        """Identificadores maliciosos devem ser tratados com segurança"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        # Nota: A rota /api/users/{username} usa username, não UUID
        # Estes testes verificam se identificadores maliciosos são tratados corretamente
        malicious_inputs = [
            "../../../etc/passwd",  # Path traversal
            "'; DROP TABLE users;--",  # SQL injection
            "<script>alert('xss')</script>",  # XSS
            "admin%00",  # Null byte injection
            "admin\x00",  # Null byte
        ]

        for malicious_input in malicious_inputs:
            response = http_client.get(f"{api_url}/users/{malicious_input}", headers=headers)
            # Deve retornar 404 (não encontrado) ou 400 (bad request), nunca 500
            assert response.status_code in [400, 404, 422], f"Input malicioso deve ser tratado: {malicious_input}"
            assert response.status_code != 500, f"Não deve causar erro interno: {malicious_input}"

    def test_nonexistent_username(self, http_client, api_url, root_user, timer):
        """Username inexistente deve retornar 404"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}
        nonexistent_user = "nonexistent_user_12345"

        response = http_client.get(f"{api_url}/users/{nonexistent_user}", headers=headers)
        assert response.status_code == 404, "Username inexistente deve retornar 404"

    def test_client_uuid_validation(self, http_client, api_url, root_user, timer):
        """UUID inválido para clients deve ser tratado corretamente"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        invalid_uuids = [
            "not-a-uuid",
            "12345",
            "12345678-1234-1234-1234",  # Incompleto
            "../../../etc/passwd",  # Path traversal
        ]

        for invalid_uuid in invalid_uuids:
            response = http_client.get(f"{api_url}/clients/{invalid_uuid}", headers=headers)
            # Deve retornar erro de validação ou not found, nunca 500
            assert response.status_code in [400, 404, 422], f"UUID inválido em clients: {invalid_uuid}"
            assert response.status_code != 500, f"Não deve causar erro interno: {invalid_uuid}"


@pytest.mark.security
@pytest.mark.validation
class TestEmailValidation:
    """Testes de validação de email"""

    def test_invalid_email_formats(self, http_client, api_url, root_user, timer):
        """Emails com formato inválido devem ser tratados"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        invalid_emails = [
            "notanemail",
            "missing@domain",
            "@nodomain.com",
            "spaces in@email.com",
            "double@@at.com",
            "no.at.sign.com",
            ".startswithdot@email.com",
            "endswith.@email.com",
        ]

        for email in invalid_emails:
            response = http_client.post(f"{api_url}/clients", json={
                "name": f"Email Test {int(time.time())}",
                "email": email
            }, headers=headers)

            # Pode aceitar ou rejeitar, mas não deve causar erro interno
            assert response.status_code in [200, 201, 400, 422], f"Email inválido não tratado: {email}"
            assert response.status_code != 500, f"Erro interno com email: {email}"

    def test_valid_email_formats(self, http_client, api_url, root_user, timer):
        """Emails com formato válido devem ser aceitos"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        valid_emails = [
            "simple@example.com",
            "very.common@example.com",
            "disposable+tag@example.com",
            "other.email-with-dash@example.com",
            "fully-qualified-domain@example.com",
            "user@subdomain.example.com",
        ]

        for i, email in enumerate(valid_emails[:3]):  # Testar apenas 3 para não criar muitos
            response = http_client.post(f"{api_url}/clients", json={
                "name": f"Valid Email Test {int(time.time())}_{i}",
                "email": email
            }, headers=headers)

            assert response.status_code in [200, 201], f"Email válido deve ser aceito: {email}"
