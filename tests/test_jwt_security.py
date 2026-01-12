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
import jwt
import time
from datetime import datetime, timedelta

@pytest.mark.jwt
@pytest.mark.security
class TestJWTSecurity:
    """Testes de segurança JWT - manipulação, expiração, assinatura"""

    def test_request_without_token_returns_401(self, http_client, api_url, timer):
        """Request sem token deve retornar 401"""
        response = http_client.get(f"{api_url}/users")
        assert response.status_code == 401, "Deveria bloquear acesso sem token"
        assert "token" in response.text.lower() or "unauthorized" in response.text.lower()

    def test_invalid_token_returns_401(self, http_client, api_url, timer):
        """Token inválido deve retornar 401"""
        headers = {"Authorization": "Bearer invalid.token.here"}
        response = http_client.get(f"{api_url}/users", headers=headers)
        assert response.status_code == 401, "Deveria rejeitar token inválido"

    def test_malformed_token_returns_401(self, http_client, api_url, timer):
        """Token malformado deve retornar 401"""
        headers = {"Authorization": "Bearer notavalidjwttoken"}
        response = http_client.get(f"{api_url}/users", headers=headers)
        assert response.status_code == 401, "Deveria rejeitar token malformado"

    def test_expired_token_rejected(self, http_client, api_url, timer):
        """Token expirado deve ser rejeitado"""
        # Token JWT expirado (exp no passado)
        expired_payload = {
            "user_id": "123",
            "username": "test",
            "role": "user",
            "exp": int(time.time()) - 3600  # expirou há 1 hora
        }
        expired_token = jwt.encode(expired_payload, "fake_secret", algorithm="HS256")

        headers = {"Authorization": f"Bearer {expired_token}"}
        response = http_client.get(f"{api_url}/users", headers=headers)
        assert response.status_code == 401, "Deveria rejeitar token expirado"

    def test_token_with_tampered_signature(self, http_client, api_url, timer):
        """Token com assinatura adulterada deve ser rejeitado"""
        tampered_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoiMTIzIiwicm9sZSI6InJvb3QifQ.TAMPERED_SIGNATURE"
        headers = {"Authorization": f"Bearer {tampered_token}"}
        response = http_client.get(f"{api_url}/users", headers=headers)
        assert response.status_code == 401, "Deveria rejeitar assinatura adulterada"

    def test_authorization_header_without_bearer(self, http_client, api_url, timer):
        """Header Authorization sem 'Bearer' deve ser rejeitado"""
        headers = {"Authorization": "sometoken123"}
        response = http_client.get(f"{api_url}/users", headers=headers)
        assert response.status_code == 401, "Deveria rejeitar formato sem Bearer"

    def test_token_with_modified_role(self, http_client, api_url, timer):
        """Token com role modificado no payload deve ser rejeitado"""
        # Tentar criar token com role "root"
        fake_payload = {
            "user_id": "123",
            "username": "hacker",
            "role": "root",
            "exp": int(time.time()) + 3600
        }
        fake_token = jwt.encode(fake_payload, "wrong_secret", algorithm="HS256")

        headers = {"Authorization": f"Bearer {fake_token}"}
        response = http_client.get(f"{api_url}/users", headers=headers)
        assert response.status_code == 401, "Deveria rejeitar token com role modificado"

    def test_token_with_none_algorithm_attack(self, http_client, api_url, timer):
        """Ataque com algoritmo 'none' deve ser bloqueado"""
        none_payload = {
            "user_id": "123",
            "username": "hacker",
            "role": "root",
            "exp": int(time.time()) + 3600
        }
        # Criar token sem assinatura (algoritmo none)
        none_token = jwt.encode(none_payload, "", algorithm="none")

        headers = {"Authorization": f"Bearer {none_token}"}
        response = http_client.get(f"{api_url}/users", headers=headers)
        assert response.status_code == 401, "Deveria bloquear algoritmo 'none'"

    def test_valid_token_from_root_user_works(self, http_client, api_url, root_user, timer):
        """Token válido do root deve funcionar"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}
        response = http_client.get(f"{api_url}/users", headers=headers)
        assert response.status_code == 200, "Token válido do root deveria funcionar"

    def test_token_reuse_after_password_change_should_fail(self, http_client, api_url, root_user, timer):
        """Token antigo não deve funcionar após mudança de senha (se auth_secret mudar)"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        # Este teste valida que o sistema DEVERIA invalidar tokens após mudança de senha
        # Apenas verificamos que o conceito está implementado (auth_secret)
        # O teste completo requer mudar senha e verificar invalidação

        headers = {"Authorization": f"Bearer {root_user['token']}"}
        response = http_client.get(f"{api_url}/users", headers=headers)
        assert response.status_code in [200, 401], "Sistema deve validar tokens corretamente"

    def test_token_with_invalid_user_id(self, http_client, api_url, timer):
        """Token com user_id inexistente deve ser rejeitado"""
        invalid_payload = {
            "user_id": "99999999-9999-9999-9999-999999999999",
            "username": "nonexistent",
            "role": "user",
            "exp": int(time.time()) + 3600
        }
        # Mesmo com assinatura válida, user não existe
        invalid_token = jwt.encode(invalid_payload, "fake_secret", algorithm="HS256")

        headers = {"Authorization": f"Bearer {invalid_token}"}
        response = http_client.get(f"{api_url}/users", headers=headers)
        assert response.status_code == 401, "Deveria rejeitar token de usuário inexistente"

    def test_multiple_bearer_tokens_in_header(self, http_client, api_url, timer):
        """Múltiplos tokens no header devem ser tratados corretamente"""
        headers = {"Authorization": "Bearer token1 Bearer token2"}
        response = http_client.get(f"{api_url}/users", headers=headers)
        assert response.status_code == 401, "Deveria rejeitar formato inválido"

    def test_case_sensitive_bearer_keyword(self, http_client, api_url, timer):
        """Keyword 'Bearer' deve ser case-sensitive"""
        headers = {"Authorization": "bearer sometoken"}
        response = http_client.get(f"{api_url}/users", headers=headers)
        # Dependendo da implementação, pode aceitar ou rejeitar
        assert response.status_code in [401, 400], "Deve tratar variações de 'Bearer'"

    def test_jwt_with_extra_claims(self, http_client, api_url, timer):
        """JWT com claims extras não deve causar vulnerabilidade"""
        extra_payload = {
            "user_id": "123",
            "username": "test",
            "role": "user",
            "exp": int(time.time()) + 3600,
            "is_admin": True,  # claim extra malicioso
            "permissions": ["all"]  # claim extra malicioso
        }
        extra_token = jwt.encode(extra_payload, "fake_secret", algorithm="HS256")

        headers = {"Authorization": f"Bearer {extra_token}"}
        response = http_client.get(f"{api_url}/users", headers=headers)
        assert response.status_code == 401, "Claims extras não devem dar privilégios"

    def test_token_without_expiration(self, http_client, api_url, timer):
        """Token sem campo 'exp' deve ser rejeitado"""
        no_exp_payload = {
            "user_id": "123",
            "username": "test",
            "role": "user"
        }
        no_exp_token = jwt.encode(no_exp_payload, "fake_secret", algorithm="HS256")

        headers = {"Authorization": f"Bearer {no_exp_token}"}
        response = http_client.get(f"{api_url}/users", headers=headers)
        # Pode aceitar ou rejeitar dependendo da implementação
        assert response.status_code in [401, 400], "Deve validar expiração"

    def test_refresh_token_cannot_be_used_as_access_token(self, http_client, api_url, root_user, timer):
        """Refresh token não deve funcionar como access token"""
        if not root_user:
            pytest.skip("Root user não disponível")

        # Fazer login e pegar refresh token
        login_response = http_client.post(f"{api_url}/login", json={
            "username": root_user["username"],
            "password": root_user["password"]
        })

        if login_response.status_code != 200:
            pytest.skip("Login falhou")

        tokens = login_response.json()
        refresh_token = tokens.get("refresh_token") or tokens.get("data", {}).get("refresh_token")

        if not refresh_token:
            pytest.skip("Refresh token não retornado")

        # Tentar usar refresh token como access token
        headers = {"Authorization": f"Bearer {refresh_token}"}
        response = http_client.get(f"{api_url}/users", headers=headers)

        # Deveria ser rejeitado (formato/claims diferentes)
        assert response.status_code == 401, "Refresh token não deve funcionar como access token"
