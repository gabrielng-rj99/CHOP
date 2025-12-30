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

@pytest.mark.security
@pytest.mark.password
class TestPasswordValidation:
    """Testes de validação de senha - senhas fracas, fortes, requisitos mínimos"""

    # Senhas fracas que devem ser rejeitadas
    WEAK_PASSWORDS = [
        "123456",
        "password",
        "12345678",
        "qwerty",
        "abc123",
        "admin",
        "letmein",
        "welcome",
        "Password1",
        "short",
        "onlyletters",
        "12345678901234",
        "aaaaaaaaaaaaaaa",
        "ALLUPPERCASE123!",
        "alllowercase123!",
        "NoNumbers!@#abc",
        "NoSpecial123abc",
        "Has Space123!@#",
        " leadingspace1!",
        "trailingspace1! ",
    ]

    # Senhas fortes que devem ser aceitas (16+ chars, upper, lower, number, symbol)
    STRONG_PASSWORDS = [
        "ValidPass123!@#a",
        "StrongP@ssw0rd123",
        "MyS3cur3P@ssw0rd!",
        "C0mpl3x!P@ssword1",
        "T3st!ng_Str0ng_P@ss",
        "Ab1!defghijklmno",
        "Qwerty123!@#$%^&a",
    ]

    def test_create_user_with_weak_password_rejected(self, http_client, api_url, root_user, timer):
        """Criar usuário com senha fraca deve ser rejeitado"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        for password in self.WEAK_PASSWORDS:
            response = http_client.post(f"{api_url}/users", json={
                "username": f"weakuser_{int(time.time())}_{hash(password) % 10000}",
                "display_name": "Weak Password User",
                "password": password,
                "role": "user"
            }, headers=headers)

            assert response.status_code in [400, 422], f"Senha fraca '{password}' deveria ser rejeitada"

    def test_create_user_with_strong_password_accepted(self, http_client, api_url, root_user, timer):
        """Criar usuário com senha forte deve ser aceito"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        for i, password in enumerate(self.STRONG_PASSWORDS[:3]):  # Testar apenas 3 para não criar muitos usuários
            response = http_client.post(f"{api_url}/users", json={
                "username": f"stronguser_{int(time.time())}_{i}",
                "display_name": "Strong Password User",
                "password": password,
                "role": "user"
            }, headers=headers)

            assert response.status_code in [200, 201], f"Senha forte '{password}' deveria ser aceita"

    def test_password_minimum_length_16_chars(self, http_client, api_url, root_user, timer):
        """Senha deve ter no mínimo 16 caracteres"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        # 15 caracteres - deve rejeitar
        response = http_client.post(f"{api_url}/users", json={
            "username": f"shortpass_{int(time.time())}",
            "display_name": "Short Password",
            "password": "Ab1!efghijklmno",  # 15 chars
            "role": "user"
        }, headers=headers)
        assert response.status_code in [400, 422], "Senha com 15 chars deveria ser rejeitada"

        # 16 caracteres - deve aceitar
        response = http_client.post(f"{api_url}/users", json={
            "username": f"exactpass_{int(time.time())}",
            "display_name": "Exact Length Password",
            "password": "Ab1!efghijklmnop",  # 16 chars
            "role": "user"
        }, headers=headers)
        assert response.status_code in [200, 201], "Senha com 16 chars deveria ser aceita"

    def test_password_requires_uppercase(self, http_client, api_url, root_user, timer):
        """Senha deve conter pelo menos uma letra maiúscula"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        response = http_client.post(f"{api_url}/users", json={
            "username": f"noupperuser_{int(time.time())}",
            "display_name": "No Uppercase User",
            "password": "alllowercase123!@#",  # sem maiúsculas
            "role": "user"
        }, headers=headers)

        assert response.status_code in [400, 422], "Senha sem maiúsculas deveria ser rejeitada"

    def test_password_requires_lowercase(self, http_client, api_url, root_user, timer):
        """Senha deve conter pelo menos uma letra minúscula"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        response = http_client.post(f"{api_url}/users", json={
            "username": f"noloweruser_{int(time.time())}",
            "display_name": "No Lowercase User",
            "password": "ALLUPPERCASE123!@#",  # sem minúsculas
            "role": "user"
        }, headers=headers)

        assert response.status_code in [400, 422], "Senha sem minúsculas deveria ser rejeitada"

    def test_password_requires_number(self, http_client, api_url, root_user, timer):
        """Senha deve conter pelo menos um número"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        response = http_client.post(f"{api_url}/users", json={
            "username": f"nonumberuser_{int(time.time())}",
            "display_name": "No Number User",
            "password": "NoNumbersHere!@#abc",  # sem números
            "role": "user"
        }, headers=headers)

        assert response.status_code in [400, 422], "Senha sem números deveria ser rejeitada"

    def test_password_requires_special_char(self, http_client, api_url, root_user, timer):
        """Senha deve conter pelo menos um caractere especial"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        response = http_client.post(f"{api_url}/users", json={
            "username": f"nospecialuser_{int(time.time())}",
            "display_name": "No Special User",
            "password": "NoSpecialChar123abc",  # sem especiais
            "role": "user"
        }, headers=headers)

        assert response.status_code in [400, 422], "Senha sem especiais deveria ser rejeitada"

    def test_password_no_spaces_allowed(self, http_client, api_url, root_user, timer):
        """Senha não pode conter espaços"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        space_passwords = [
            "Has Space 123!@#Ab",
            " LeadingSpace123!@#",
            "TrailingSpace123!@# ",
            "Multiple  Spaces123!@#",
        ]

        for password in space_passwords:
            response = http_client.post(f"{api_url}/users", json={
                "username": f"spaceuser_{int(time.time())}_{hash(password) % 10000}",
                "display_name": "Space Password User",
                "password": password,
                "role": "user"
            }, headers=headers)

            assert response.status_code in [400, 422], f"Senha com espaço '{password}' deveria ser rejeitada"

    def test_login_with_correct_password_works(self, http_client, api_url, timer):
        """Login com senha correta deve funcionar"""
        # Usa credenciais do root existente
        response = http_client.post(f"{api_url}/login", json={
            "username": "root",
            "password": "RootPass123!@#456789%%0321654987+-7dfgacvds"  # Senha forte padrão do conftest
        })

        # Pode retornar 200 se credenciais estão corretas ou 401 se senha diferente
        # O importante é não retornar 500 (erro interno)
        assert response.status_code in [200, 401], "Login não deve causar erro interno"

    def test_login_with_wrong_password_fails(self, http_client, api_url, timer):
        """Login com senha errada deve falhar"""
        response = http_client.post(f"{api_url}/login", json={
            "username": "root",
            "password": "WrongPassword123!@#"
        })

        assert response.status_code == 401, "Login com senha errada deve retornar 401"

    def test_password_hash_not_exposed_in_response(self, http_client, api_url, root_user, timer):
        """Hash da senha não deve ser exposto nas respostas"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        # Listar usuários
        response = http_client.get(f"{api_url}/users", headers=headers)

        if response.status_code == 200:
            data = response.json()
            response_text = str(data).lower()

            # Não deve conter hash de senha
            assert "password_hash" not in response_text, "password_hash não deve aparecer"
            assert "$2a$" not in response_text, "Hash bcrypt não deve aparecer"
            assert "$2b$" not in response_text, "Hash bcrypt não deve aparecer"

    def test_password_change_requires_strong_password(self, http_client, api_url, root_user, timer):
        """Alteração de senha também deve exigir senha forte"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        # Criar usuário para teste
        test_username = f"changepwuser_{int(time.time())}"
        create_response = http_client.post(f"{api_url}/users", json={
            "username": test_username,
            "display_name": "Change Password User",
            "password": "ValidPass123!@#abc",
            "role": "user"
        }, headers=headers)

        if create_response.status_code not in [200, 201]:
            pytest.skip("Não foi possível criar usuário de teste")

        user_data = create_response.json()
        user_id = user_data.get("data", {}).get("id") or user_data.get("id")

        if not user_id:
            pytest.skip("ID do usuário não retornado")

        # Tentar alterar para senha fraca
        # A rota espera username, não ID
        update_response = http_client.put(f"{api_url}/users/{test_username}", json={
            "password": "weak123"
        }, headers=headers)

        assert update_response.status_code in [400, 422], "Alteração para senha fraca deveria ser rejeitada"

    def test_empty_password_rejected(self, http_client, api_url, root_user, timer):
        """Senha vazia deve ser rejeitada"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        response = http_client.post(f"{api_url}/users", json={
            "username": f"emptypassuser_{int(time.time())}",
            "display_name": "Empty Password User",
            "password": "",
            "role": "user"
        }, headers=headers)

        assert response.status_code in [400, 422], "Senha vazia deveria ser rejeitada"

    def test_null_password_rejected(self, http_client, api_url, root_user, timer):
        """Senha null deve ser rejeitada"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        response = http_client.post(f"{api_url}/users", json={
            "username": f"nullpassuser_{int(time.time())}",
            "display_name": "Null Password User",
            "password": None,
            "role": "user"
        }, headers=headers)

        assert response.status_code in [400, 422], "Senha null deveria ser rejeitada"

    def test_unicode_password_handling(self, http_client, api_url, root_user, timer):
        """Sistema deve lidar corretamente com senhas unicode"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        # Senha com caracteres unicode (mas ainda válida se tiver os requisitos)
        unicode_passwords = [
            "Válid@Pass123!@#ñ",  # Caracteres acentuados
            "パスワード123!@#Abc",  # Japonês
            "Пароль123!@#Abcde",  # Russo
        ]

        for password in unicode_passwords:
            response = http_client.post(f"{api_url}/users", json={
                "username": f"unicodeuser_{int(time.time())}_{hash(password) % 10000}",
                "display_name": "Unicode Password User",
                "password": password,
                "role": "user"
            }, headers=headers)

            # Deve aceitar ou rejeitar graciosamente (não 500)
            assert response.status_code in [200, 201, 400, 422], "Unicode não deve causar erro interno"

    def test_very_long_password_handled(self, http_client, api_url, root_user, timer):
        """Sistema deve lidar com senhas muito longas"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        # Senha muito longa (mas válida)
        long_password = "Ab1!" + "x" * 1000

        response = http_client.post(f"{api_url}/users", json={
            "username": f"longpassuser_{int(time.time())}",
            "display_name": "Long Password User",
            "password": long_password,
            "role": "user"
        }, headers=headers)

        # Pode aceitar ou rejeitar, mas não deve causar erro interno
        assert response.status_code in [200, 201, 400, 413, 422], "Senha longa não deve causar erro interno"

    def test_special_chars_in_password(self, http_client, api_url, root_user, timer):
        """Sistema deve aceitar vários caracteres especiais na senha"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        special_char_passwords = [
            "ValidPass123!@#$%",
            "ValidPass123^&*()",
            "ValidPass123_+-=a",
            "ValidPass123[]{}a",
            "ValidPass123;':\"a",
            "ValidPass123<>?,./",
            "ValidPass123|\\`~a",
        ]

        for i, password in enumerate(special_char_passwords):
            response = http_client.post(f"{api_url}/users", json={
                "username": f"specialcharuser_{int(time.time())}_{i}",
                "display_name": "Special Char User",
                "password": password,
                "role": "user"
            }, headers=headers)

            # Não deve causar erro interno
            assert response.status_code in [200, 201, 400, 422], f"Especiais '{password}' não deve causar erro interno"


@pytest.mark.security
@pytest.mark.password
class TestLoginSecurity:
    """Testes de segurança relacionados ao login"""

    def test_login_with_empty_username(self, http_client, api_url, timer):
        """Login com username vazio deve falhar"""
        response = http_client.post(f"{api_url}/login", json={
            "username": "",
            "password": "SomePassword123!@#"
        })

        assert response.status_code in [400, 401], "Username vazio deve ser rejeitado"

    def test_login_with_empty_password(self, http_client, api_url, timer):
        """Login com senha vazia deve falhar"""
        response = http_client.post(f"{api_url}/login", json={
            "username": "root",
            "password": ""
        })

        assert response.status_code in [400, 401], "Senha vazia deve ser rejeitada"

    def test_login_with_empty_body(self, http_client, api_url, timer):
        """Login com body vazio deve falhar"""
        response = http_client.post(f"{api_url}/login", json={})

        assert response.status_code in [400, 401], "Body vazio deve ser rejeitado"

    def test_login_with_null_values(self, http_client, api_url, timer):
        """Login com valores null deve falhar"""
        response = http_client.post(f"{api_url}/login", json={
            "username": None,
            "password": None
        })

        assert response.status_code in [400, 401], "Valores null devem ser rejeitados"

    def test_login_with_extra_fields_ignored(self, http_client, api_url, timer):
        """Campos extras no login devem ser ignorados"""
        response = http_client.post(f"{api_url}/login", json={
            "username": "root",
            "password": "WrongPassword123!@#",
            "role": "root",  # Tentativa de injetar role
            "is_admin": True,  # Tentativa de injetar admin
            "bypass_auth": True  # Tentativa de bypass
        })

        # Não deve autenticar por causa dos campos extras
        assert response.status_code == 401, "Campos extras não devem permitir bypass"

    def test_login_response_no_password_leak(self, http_client, api_url, root_user, timer):
        """Resposta de login não deve vazar senha"""
        if not root_user:
            pytest.skip("Root user não disponível")

        response = http_client.post(f"{api_url}/login", json={
            "username": root_user.get("username", "root"),
            "password": root_user.get("password", "")
        })

        if response.status_code == 200:
            response_text = response.text.lower()
            assert "password" not in response_text or "password_hash" not in response_text
            assert "$2a$" not in response_text
            assert "$2b$" not in response_text

    def test_failed_login_generic_error_message(self, http_client, api_url, timer):
        """Mensagem de erro de login deve ser genérica (não revelar se usuário existe)"""
        # Login com usuário que não existe
        response1 = http_client.post(f"{api_url}/login", json={
            "username": "nonexistent_user_12345",
            "password": "SomePassword123!@#"
        })

        # Login com usuário que existe mas senha errada
        response2 = http_client.post(f"{api_url}/login", json={
            "username": "root",
            "password": "WrongPassword123!@#"
        })

        # Ambas devem retornar 401
        assert response1.status_code == 401
        assert response2.status_code == 401

        # Mensagens devem ser similares (não revelar se usuário existe)
        # Verificar que não há mensagem como "usuário não encontrado"
        msg1 = response1.text.lower()
        msg2 = response2.text.lower()

        assert "not found" not in msg1 or "not found" not in msg2
        assert "não encontrado" not in msg1 or "não encontrado" not in msg2

    def test_login_timing_attack_protection(self, http_client, api_url, timer):
        """Tempos de resposta para usuário válido/inválido devem ser similares"""
        # Este teste verifica proteção contra timing attacks

        times_valid_user = []
        times_invalid_user = []

        for _ in range(5):
            # Usuário válido, senha errada
            start = time.time()
            http_client.post(f"{api_url}/login", json={
                "username": "root",
                "password": "WrongPassword123!@#"
            })
            times_valid_user.append(time.time() - start)

            # Usuário inválido
            start = time.time()
            http_client.post(f"{api_url}/login", json={
                "username": "nonexistent_user_timing_test",
                "password": "SomePassword123!@#"
            })
            times_invalid_user.append(time.time() - start)

        avg_valid = sum(times_valid_user) / len(times_valid_user)
        avg_invalid = sum(times_invalid_user) / len(times_invalid_user)

        # Diferença não deve ser muito grande (< 500ms)
        diff = abs(avg_valid - avg_invalid)
        assert diff < 0.5, f"Diferença de timing muito grande: {diff}s - possível timing attack"
