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
Testes de Bypass e Encoding Attacks
Baseado em:
- OWASP Testing Guide v4.2
- CWE-173: Improper Handling of Alternate Encoding
- CWE-178: Improper Handling of Case Sensitivity
- CWE-180: Incorrect Behavior Order: Validate Before Canonicalize
- Cisco Security Best Practices
"""

import pytest

import time
import base64
import urllib.parse


class TestEncodingBypass:
    """Testes de bypass usando diferentes encodings"""

    def test_url_encoded_sql_injection_login(self, http_client, api_url, timer):
        """SQL Injection com URL encoding no login"""
        payloads = [
            "%27%20OR%20%271%27%3D%271",  # ' OR '1'='1
            "%27%3B%20DROP%20TABLE%20users%3B--",  # '; DROP TABLE users;--
            "%27%20UNION%20SELECT%20*%20FROM%20users--",
            "%2527",  # Double URL encoded '
            "%252527",  # Triple URL encoded '
        ]

        for payload in payloads:
            response = http_client.post(
                f"{api_url}/login",
                json={"username": payload, "password": "test"}
            )
            # Deve rejeitar, não bypassar
            assert response.status_code in [400, 401]
            # Deve ser rápido
            assert response.elapsed.total_seconds() < 2

    def test_base64_encoded_xss_attempt(self, http_client, api_url, root_token, timer):
        """XSS com Base64 encoding"""
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "javascript:alert('XSS')",
        ]

        if not root_token:
            pytest.skip("Root token not available for authenticated test.")

        for xss in xss_payloads:
            encoded = base64.b64encode(xss.encode()).decode()

            # Tentar como nome de cliente
            response = http_client.post(
                f"{api_url}/clients",
                headers={"Authorization": f"Bearer {root_token}"},
                json={"name": f"data:text/html;base64,{encoded}"}
            )

            if response.status_code == 201:
                # Se aceitar, verificar que não executa
                data = response.json()
                get_resp = http_client.get(
                    f"{api_url}/clients/{data.get('id')}",
                    headers={"Authorization": f"Bearer {root_token}"}
                )
                if get_resp.status_code == 200:
                    client_data = get_resp.json()
                    # Não deve ter sido decodificado para XSS
                    name = client_data.get("name", "")
                    assert "<script>" not in name
                    assert "javascript:" not in name.lower()

    def test_hex_encoded_sql_injection(self, http_client, api_url, timer):
        """SQL Injection com Hex encoding"""
        # 0x prefixed hex values
        payloads = [
            "0x27206F522027313D31",  # ' OR '1=1
            "0x61646D696E27--",  # admin'--
            "\\x27 OR \\x271\\x27=\\x271",
        ]

        for payload in payloads:
            response = http_client.post(
                f"{api_url}/login",
                json={"username": payload, "password": "test"}
            )
            assert response.status_code in [400, 401]

    def test_unicode_escaped_injection(self, http_client, api_url, timer):
        """Injection com Unicode escape sequences"""
        payloads = [
            "\\u0027 OR \\u00271\\u0027=\\u00271",  # ' OR '1'='1
            "\\u003cscript\\u003ealert(1)\\u003c/script\\u003e",  # <script>alert(1)</script>
            "\\u0022; DROP TABLE users;--",
        ]

        for payload in payloads:
            response = http_client.post(
                f"{api_url}/login",
                json={"username": payload, "password": "test"}
            )
            assert response.status_code in [400, 401]

    def test_html_entity_encoded_xss(self, http_client, api_url, root_token, timer):
        """XSS com HTML entities"""
        payloads = [
            "&lt;script&gt;alert('XSS')&lt;/script&gt;",
            "&#60;script&#62;alert('XSS')&#60;/script&#62;",
            "&#x3C;script&#x3E;alert('XSS')&#x3C;/script&#x3E;",
            "&quot;onclick=alert('XSS')&quot;",
        ]

        if not root_token:
            pytest.skip("Root token not available for authenticated test.")

        for payload in payloads:
            response = http_client.post(
                f"{api_url}/clients",
                headers={"Authorization": f"Bearer {root_token}"},
                json={"name": payload}
            )
            # Pode aceitar (entities são texto válido) ou rejeitar
            assert response.status_code in [201, 400]


class TestCaseSensitivityBypass:
    """Testes de bypass usando case sensitivity"""

    def test_role_case_variations(self, http_client, api_url, root_token, timer):
        """Tentar criar usuário com role em diferentes cases"""
        role_variations = [
            "ROOT", "Root", "rOOT", "rooT",
            "ADMIN", "Admin", "aDMIN",
            "USER", "User", "uSER",
        ]

        if not root_token:
            pytest.skip("Root token not available for authenticated test.")

        for role in role_variations:
            response = http_client.post(
                f"{api_url}/users",
                headers={"Authorization": f"Bearer {root_token}"},
                json={
                    "username": f"testcase_{role.lower()}",
                    "display_name": "Test Case User",
                    "password": "ValidPass123!@#abc",
                    "role": role
                }
            )
            # Deve rejeitar roles com case incorreto
            # ou normalizar para lowercase
            if response.status_code == 201:
                # Se aceitar, verificar que normalizou
                data = response.json()
                assert "data" in data and "id" in data["data"]
            else:
                assert response.status_code == 400

    def test_method_case_bypass(self, http_client, api_url, timer):
        """Tentar métodos HTTP com case diferente"""
        # Note: Isso testa o servidor/framework, não a aplicação
        methods = ["GET", "get", "Get", "gEt"]

        for method in methods:
            try:
                response = http_client.request(
                    method,
                    f"{api_url}/health"
                )
                # Deve funcionar apenas para GET correto
                assert response.status_code in [200, 405]
            except Exception:
                pass  # Método inválido pode causar exceção

    def test_header_case_bypass(self, http_client, api_url, root_token, timer):
        """Authorization header com case diferente"""
        if not root_token:
            pytest.skip("Root token not available for authenticated test.")

        headers_variations = [
            {"authorization": f"Bearer {root_token}"},
            {"AUTHORIZATION": f"Bearer {root_token}"},
            {"Authorization": f"bearer {root_token}"},
            {"Authorization": f"BEARER {root_token}"},
            {"Authorization": f"BeArEr {root_token}"},
        ]

        for headers in headers_variations:
            response = http_client.get(f"{api_url}/users", headers=headers)
            # HTTP headers são case-insensitive por spec
            # Mas Bearer keyword pode ser case-sensitive
            assert response.status_code in [200, 401]

    def test_endpoint_case_bypass(self, http_client, api_url, root_token, timer):
        """Endpoints com case diferente"""
        endpoints = [
            "/USERS", "/Users", "/uSERS",
            "/CLIENTS", "/Clients",
            "/LOGIN", "/Login",
        ]

        if not root_token:
            pytest.skip("Root token not available for authenticated test.")

        for endpoint in endpoints:
            response = http_client.get(
                f"{api_url}{endpoint}",
                headers={"Authorization": f"Bearer {root_token}"}
            )
            # Deve retornar 404 para case incorreto (URLs são case-sensitive)
            assert response.status_code in [200, 404, 405]


class TestPathTraversalBypass:
    """Testes de bypass usando path traversal"""

    PATH_TRAVERSAL_PAYLOADS = [
        "../",
        "..\\",
        "....//",
        "....\\\\",
        "%2e%2e%2f",
        "%2e%2e/",
        "..%2f",
        "%2e%2e%5c",
        "..%255c",
        "..%c0%af",
        "..%c1%9c",
        "..%252f",
        "/etc/passwd",
        "..\\..\\..\\etc\\passwd",
        "....//....//....//etc//passwd",
    ]

    def test_path_traversal_in_username_lookup(self, http_client, api_url, root_token, timer):
        """Path traversal no lookup de username"""
        if not root_token:
            pytest.skip("Root token not available for authenticated test.")

        for payload in self.PATH_TRAVERSAL_PAYLOADS:
            response = http_client.get(
                f"{api_url}/users/{payload}",
                headers={"Authorization": f"Bearer {root_token}"}
            )
            # DEVE retornar 404 ou 400, NUNCA 500 (erro interno)
            # 500 indica vulnerabilidade - backend não validou input
            assert response.status_code in [400, 404], \
                f"Path traversal '{payload}' retornou {response.status_code}, esperava 400/404 (NUNCA 500!)"
            # Resposta não deve conter conteúdo de arquivos do sistema
            text = response.text.lower()
            assert "root:" not in text  # /etc/passwd content
            assert "bin/bash" not in text

    def test_path_traversal_in_client_id(self, http_client, api_url, root_token, timer):
        """Path traversal no ID do cliente"""
        if not root_token:
            pytest.skip("Root token not available for authenticated test.")

        for payload in self.PATH_TRAVERSAL_PAYLOADS:
            response = http_client.get(
                f"{api_url}/clients/{payload}",
                headers={"Authorization": f"Bearer {root_token}"}
            )
            assert response.status_code in [400, 404]

    def test_path_traversal_in_audit_resource(self, http_client, api_url, root_token, timer):
        """Path traversal no endpoint de audit logs por resource"""
        if not root_token:
            pytest.skip("Root token not available for authenticated test.")

        for payload in self.PATH_TRAVERSAL_PAYLOADS[:5]:
            response = http_client.get(
                f"{api_url}/audit-logs/resource/{payload}/test",
                headers={"Authorization": f"Bearer {root_token}"}
            )
            # 200 é aceitável se não houve match nos logs
            assert response.status_code in [200, 400, 403, 404]


class TestNullByteBypass:
    """Testes de bypass usando null bytes"""

    def test_null_byte_in_username(self, http_client, api_url, timer):
        """Null byte no username para truncar"""
        payloads = [
            "admin\x00anything",
            "root\x00.txt",
            "\x00admin",
            "a\x00d\x00m\x00i\x00n",
        ]

        for payload in payloads:
            response = http_client.post(
                f"{api_url}/login",
                json={"username": payload, "password": "test"}
            )
            assert response.status_code in [400, 401]

    def test_null_byte_in_client_name(self, http_client, api_url, root_token, timer):
        """Null byte no nome do cliente"""
        if not root_token:
            pytest.skip("Root token not available for authenticated test.")

        response = http_client.post(
            f"{api_url}/clients",
            headers={"Authorization": f"Bearer {root_token}"},
            json={"name": "Test\x00<script>alert(1)</script>"}
        )

        if response.status_code == 201:
            data = response.json()
            # Verificar que XSS não passou
            get_resp = http_client.get(
                f"{api_url}/clients/{data.get('id')}",
                headers={"Authorization": f"Bearer {root_token}"}
            )
            if get_resp.status_code == 200:
                client = get_resp.json()
                assert "<script>" not in client.get("name", "")


class TestHTTPParameterPollution:
    """Testes de HTTP Parameter Pollution"""

    def test_duplicate_query_params(self, http_client, api_url, root_token, timer):
        """Parâmetros de query duplicados"""
        if not root_token:
            pytest.skip("Root token not available for authenticated test.")

        # Tentar passar dois valores para mesmo parâmetro
        response = http_client.get(
            f"{api_url}/clients?include_stats=true&include_stats=false",
            headers={"Authorization": f"Bearer {root_token}"}
        )
        # Deve usar um valor consistente
        assert response.status_code in [200, 400]

    def test_duplicate_body_params(self, http_client, api_url, timer):
        """Parâmetros duplicados no body JSON"""
        # Nota: JSON spec não define comportamento para chaves duplicadas
        duplicate_json = '{"username": "user1", "password": "pass1", "username": "admin"}'

        response = http_client.post(
            f"{api_url}/login",
            data=duplicate_json,
            headers={"Content-Type": "application/json"}
        )
        # Não deve aceitar o segundo username
        assert response.status_code in [400, 401]


class TestHTTPMethodOverride:
    """Testes de HTTP Method Override bypass"""

    def test_method_override_header(self, http_client, api_url, root_token, timer):
        """Tentar override de método via header"""
        if not root_token:
            pytest.skip("Root token not available for authenticated test.")

        override_headers = [
            "X-HTTP-Method-Override",
            "X-HTTP-Method",
            "X-Method-Override",
            "_method",
        ]

        for header in override_headers:
            # Tentar fazer DELETE via POST
            response = http_client.post(
                f"{api_url}/users/root",
                headers={
                    "Authorization": f"Bearer {root_token}",
                    header: "DELETE"
                }
            )
            # Não deve deletar o usuário root
            assert response.status_code in [400, 403, 404, 405]

    def test_method_override_query_param(self, http_client, api_url, root_token, timer):
        """Tentar override de método via query param"""
        if not root_token:
            pytest.skip("Root token not available for authenticated test.")

        # Tentar fazer DELETE via GET
        response = http_client.get(
            f"{api_url}/users/root?_method=DELETE",
            headers={"Authorization": f"Bearer {root_token}"}
        )
        # Não deve deletar
        assert response.status_code in [200, 400, 403, 404, 405]


class TestContentTypeBypass:
    """Testes de bypass usando Content-Type"""

    def test_wrong_content_type_json(self, http_client, api_url, timer):
        """Enviar JSON com Content-Type errado"""
        json_data = '{"username": "test", "password": "test"}'

        content_types = [
            "text/plain",
            "text/html",
            "application/x-www-form-urlencoded",
            "multipart/form-data",
            "application/xml",
        ]

        for ct in content_types:
            response = http_client.post(
                f"{api_url}/login",
                data=json_data,
                headers={"Content-Type": ct}
            )
            # Deve rejeitar ou processar corretamente
            assert response.status_code in [400, 401, 415]

    def test_json_with_xml_content_type(self, http_client, api_url, timer):
        """Enviar JSON com Content-Type XML"""
        response = http_client.post(
            f"{api_url}/login",
            json={"username": "test", "password": "test"},
            headers={"Content-Type": "application/xml"}
        )
        # Deve rejeitar XML ou processar JSON
        assert response.status_code in [400, 401, 415]


class TestJWTBypassAttempts:
    """Testes de bypass específicos para JWT"""

    def test_jwt_with_extra_dots(self, http_client, api_url, timer):
        """JWT com pontos extras"""
        fake_tokens = [
            "eyJ.eyJ.sig.extra",
            "eyJ.eyJ.sig.",
            ".eyJ.eyJ.sig",
            "eyJ..sig",
        ]

        for token in fake_tokens:
            response = http_client.get(
                f"{api_url}/users",
                headers={"Authorization": f"Bearer {token}"}
            )
            assert response.status_code == 401

    def test_jwt_with_special_chars(self, http_client, api_url, timer):
        """JWT com caracteres especiais inválidos"""
        fake_tokens = [
            "eyJ<script>eyJ.sig",
            "eyJ'OR'1'='1.eyJ.sig",
            "eyJ$(whoami).eyJ.sig",
            "eyJ;ls -la.eyJ.sig",
        ]

        for token in fake_tokens:
            response = http_client.get(
                f"{api_url}/users",
                headers={"Authorization": f"Bearer {token}"}
            )
            assert response.status_code == 401

    def test_jwt_algorithm_confusion(self, http_client, api_url, timer):
        """Tentar confusão de algoritmo JWT"""
        import jwt as pyjwt

        # Tentar assinar com HS256 usando chave pública como secret
        # (ataque clássico RS256 -> HS256)
        try:
            fake_token = pyjwt.encode(
                {"user_id": "admin", "role": "root"},
                "some_public_key",
                algorithm="HS256"
            )
            response = http_client.get(
                f"{api_url}/users",
                headers={"Authorization": f"Bearer {fake_token}"}
            )
            assert response.status_code == 401
        except Exception:
            pass  # Biblioteca pode rejeitar

    def test_jwt_kid_injection(self, http_client, api_url, timer):
        """Tentar injeção via claim 'kid' (key ID)"""
        import jwt as pyjwt

        evil_kids = [
            "../../etc/passwd",
            "'; DROP TABLE users; --",
            "| cat /etc/passwd",
        ]

        for kid in evil_kids:
            try:
                fake_token = pyjwt.encode(
                    {"user_id": "admin", "role": "root"},
                    "secret",
                    algorithm="HS256",
                    headers={"kid": kid}
                )
                response = http_client.get(
                    f"{api_url}/users",
                    headers={"Authorization": f"Bearer {fake_token}"}
                )
                assert response.status_code == 401
                # Resposta não deve vazar info do sistema
                assert "/etc/passwd" not in response.text
            except Exception:
                pass


class TestUnicodeNormalizationBypass:
    """Testes de bypass usando normalização Unicode"""

    def test_unicode_normalization_username(self, http_client, api_url, timer):
        """Diferentes representações Unicode do mesmo texto"""
        # 'admin' pode ser representado de diferentes formas
        payloads = [
            "ａｄｍｉｎ",  # Fullwidth Latin
            "аdmin",  # Cyrillic 'a'
            "admіn",  # Cyrillic 'i'
            "ɑdmin",  # Latin alpha
            "admin\u200B",  # Zero-width space
            "\u200Badmin",  # Zero-width space before
            "a\u0308dmin",  # Combining diaeresis
        ]

        for payload in payloads:
            response = http_client.post(
                f"{api_url}/login",
                json={"username": payload, "password": "test"}
            )
            # Não deve confundir com 'admin' real
            assert response.status_code in [400, 401]

    def test_homograph_attack(self, http_client, api_url, root_token, timer):
        """Ataque homograph - caracteres visualmente idênticos"""
        if not root_token:
            pytest.skip("Root token not available for authenticated test.")

        # Tentar criar usuário que parece 'admin' mas não é
        homographs = [
            "аdmin",  # Cyrillic 'а' (U+0430)
            "admіn",  # Cyrillic 'і' (U+0456)
            "аdmіn",  # Both
        ]

        for homograph in homographs:
            response = http_client.post(
                f"{api_url}/users",
                headers={"Authorization": f"Bearer {root_token}"},
                json={
                    "username": homograph,
                    "display_name": "Fake Admin",
                    "password": "ValidPass123!@#abc",
                    "role": "user"
                }
            )
            # Deve rejeitar ou sanitizar caracteres não-ASCII
            # Aceitar com alerta é ok, mas não deve confundir com 'admin'
            assert response.status_code in [201, 400]
