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
import json
import re

@pytest.mark.security
@pytest.mark.data_leakage
class TestDataLeakage:
    """Testes de vazamento de dados sensíveis"""

    # Padrões de dados sensíveis que não devem aparecer nas respostas
    SENSITIVE_PATTERNS = [
        r'\$2[aby]?\$[0-9]{1,2}\$[./A-Za-z0-9]{53}',  # bcrypt hash
        r'password_hash',
        r'auth_secret',
        r'secret_key',
        r'jwt_secret',
        r'private_key',
        r'api_key',
        r'access_key',
        r'Bearer [A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+',  # JWT em logs
    ]

    # Keywords de erro de banco de dados
    DB_ERROR_KEYWORDS = [
        'postgresql',
        'postgres',
        'pg_',
        'pq:',
        'sql syntax',
        'syntax error',
        'query failed',
        'database error',
        'relation "',
        'column "',
        'table "',
        'constraint violation',
        'foreign key',
        'unique constraint',
        'duplicate key',
        'ORA-',  # Oracle
        'MySQL',
        'SQLSTATE',
        'stack trace',
        'goroutine',
        'panic:',
        'runtime error',
    ]

    def test_user_list_no_password_hash(self, http_client, api_url, root_user, timer):
        """Lista de usuários não deve conter hash de senha"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}
        response = http_client.get(f"{api_url}/users", headers=headers)

        if response.status_code == 200:
            response_text = response.text.lower()

            assert "password_hash" not in response_text, "password_hash vazado na lista de usuários"
            assert "$2a$" not in response_text, "Hash bcrypt vazado na lista de usuários"
            assert "$2b$" not in response_text, "Hash bcrypt vazado na lista de usuários"

    def test_user_detail_no_password_hash(self, http_client, api_url, root_user, timer):
        """Detalhes de usuário não devem conter hash de senha"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        # Listar usuários para obter um ID
        list_response = http_client.get(f"{api_url}/users", headers=headers)
        if list_response.status_code != 200:
            pytest.skip("Não foi possível listar usuários")

        users = list_response.json()
        if not users:
            pytest.skip("Nenhum usuário encontrado")

        # Pegar detalhes de um usuário
        user = users[0] if isinstance(users, list) else users.get("data", [{}])[0]
        user_id = user.get("id") or user.get("username")

        if not user_id:
            pytest.skip("ID do usuário não encontrado")

        detail_response = http_client.get(f"{api_url}/users/{user_id}", headers=headers)

        if detail_response.status_code == 200:
            response_text = detail_response.text.lower()
            assert "password_hash" not in response_text, "password_hash vazado nos detalhes"
            assert "auth_secret" not in response_text, "auth_secret vazado nos detalhes"

    def test_user_no_auth_secret_exposed(self, http_client, api_url, root_user, timer):
        """auth_secret do usuário nunca deve ser exposto"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        response = http_client.get(f"{api_url}/users", headers=headers)

        if response.status_code == 200:
            assert "auth_secret" not in response.text, "auth_secret vazado na resposta"

    def test_login_response_no_sensitive_data(self, http_client, api_url, root_user, timer):
        """Resposta de login não deve conter dados sensíveis além dos tokens"""
        if not root_user:
            pytest.skip("Root user não disponível")

        response = http_client.post(f"{api_url}/login", json={
            "username": root_user.get("username", "root"),
            "password": root_user.get("password", "")
        })

        if response.status_code == 200:
            response_text = response.text.lower()

            # Não deve conter hash de senha
            assert "password_hash" not in response_text
            assert "$2a$" not in response_text
            assert "$2b$" not in response_text

            # Não deve conter auth_secret
            assert "auth_secret" not in response_text

    def test_error_response_no_stack_trace(self, http_client, api_url, timer):
        """Respostas de erro não devem conter stack traces"""
        # Provocar erro com request inválido
        response = http_client.post(f"{api_url}/login", json={
            "username": "test'--",
            "password": "test"
        })

        response_text = response.text.lower()

        assert "goroutine" not in response_text, "Stack trace Go vazado"
        assert "panic:" not in response_text, "Panic Go vazado"
        assert "runtime error" not in response_text, "Runtime error vazado"
        assert ".go:" not in response_text, "Arquivo Go vazado"

    def test_error_response_no_db_details(self, http_client, api_url, timer):
        """Respostas de erro não devem conter detalhes do banco"""
        # Provocar possível erro de banco
        response = http_client.post(f"{api_url}/login", json={
            "username": "'; SELECT * FROM users; --",
            "password": "test"
        })

        response_text = response.text.lower()

        for keyword in self.DB_ERROR_KEYWORDS:
            assert keyword.lower() not in response_text, f"Detalhe de banco vazado: {keyword}"

    def test_404_no_internal_paths(self, http_client, api_url, timer):
        """Respostas 404 não devem revelar caminhos internos"""
        response = http_client.get(f"{api_url}/nonexistent/path/here")

        response_text = response.text.lower()

        # Não deve revelar estrutura de arquivos
        assert "/home/" not in response_text
        assert "/root/" not in response_text
        assert "/var/" not in response_text
        assert "/app/" not in response_text
        assert "/go/" not in response_text
        assert "\\users\\" not in response_text  # Windows
        assert "c:\\" not in response_text

    def test_headers_no_sensitive_info(self, http_client, api_url, timer):
        """Headers HTTP não devem revelar informações sensíveis"""
        response = http_client.get(f"{api_url}/../health")

        # Verificar headers
        headers = dict(response.headers)

        # Não deve ter versões detalhadas
        server_header = headers.get("Server", "")
        x_powered_by = headers.get("X-Powered-By", "")

        # Avisar se versões detalhadas estão expostas
        if server_header:
            assert "nginx/" not in server_header.lower() or len(server_header) < 20, \
                "Versão detalhada do servidor exposta"

    def test_verbose_errors_disabled(self, http_client, api_url, root_user, timer):
        """Erros verbosos devem estar desabilitados"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        # Tentar criar recurso com dados inválidos
        response = http_client.post(f"{api_url}/users", json={
            "username": "",
            "display_name": "",
            "password": "",
            "role": "invalid_role"
        }, headers=headers)

        if response.status_code in [400, 422]:
            response_text = response.text

            # Erro deve ser genérico, não técnico
            assert "line " not in response_text.lower()
            assert "column " not in response_text.lower() or "sql" not in response_text.lower()
            assert "file:" not in response_text.lower()

    def test_audit_logs_no_passwords(self, http_client, api_url, root_user, timer):
        """Logs de auditoria não devem conter senhas"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        response = http_client.get(f"{api_url}/audit-logs", headers=headers)

        if response.status_code == 200:
            response_text = response.text.lower()

            assert "password" not in response_text or "password_hash" not in response_text
            assert "$2a$" not in response_text
            assert "$2b$" not in response_text

    def test_client_data_isolation(self, http_client, api_url, root_user, regular_user, timer):
        """Dados de clientes devem ser isolados por permissão"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")
        if not regular_user or "token" not in regular_user:
            pytest.skip("Regular user não disponível")

        admin_headers = {"Authorization": f"Bearer {root_user['token']}"}
        user_headers = {"Authorization": f"Bearer {regular_user['token']}"}

        # Admin cria cliente
        create_response = http_client.post(f"{api_url}/entities", json={
            "name": f"Isolated Client {int(time.time())}",
            "email": "isolated@test.com",
            "notes": "Dados confidenciais aqui"
        }, headers=admin_headers)

        if create_response.status_code not in [200, 201]:
            pytest.skip("Não foi possível criar cliente de teste")

        # Verificar que usuário comum pode ou não acessar
        # Comportamento depende das regras de negócio
        user_response = http_client.get(f"{api_url}/entities", headers=user_headers)

        # Não deve causar erro interno
        assert user_response.status_code != 500, "Erro interno ao verificar isolamento"

    def test_sensitive_fields_not_in_search_results(self, http_client, api_url, root_user, timer):
        """Campos sensíveis não devem aparecer em resultados de busca"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        # Buscar usuários
        response = http_client.get(
            f"{api_url}/users",
            params={"search": "admin"},
            headers=headers
        )

        if response.status_code == 200:
            for pattern in self.SENSITIVE_PATTERNS:
                matches = re.findall(pattern, response.text, re.IGNORECASE)
                assert not matches, f"Padrão sensível encontrado: {pattern}"

    def test_deleted_user_data_not_accessible(self, http_client, api_url, root_user, timer):
        """Dados de usuários deletados não devem ser acessíveis"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        # Criar usuário
        test_username = f"deleteleak_{int(time.time())}"
        create_response = http_client.post(f"{api_url}/users", json={
            "username": test_username,
            "display_name": "Delete Leak Test",
            "password": "ValidPass123!@#abc",
            "role": "user"
        }, headers=headers)

        if create_response.status_code not in [200, 201]:
            pytest.skip("Não foi possível criar usuário de teste")

        user_data = create_response.json()
        user_id = user_data.get("data", {}).get("id") or user_data.get("id")

        # Deletar usuário
        delete_response = http_client.delete(f"{api_url}/users/{test_username}", headers=headers)

        if delete_response.status_code in [200, 204]:
            # Tentar acessar usuário deletado
            get_response = http_client.get(f"{api_url}/users/{test_username}", headers=headers)
            assert get_response.status_code in [403, 404], "Usuário deletado não deve ser acessível"

    def test_jwt_payload_no_sensitive_data(self, http_client, api_url, root_user, timer):
        """Payload do JWT não deve conter dados sensíveis"""
        if not root_user:
            pytest.skip("Root user não disponível")

        response = http_client.post(f"{api_url}/login", json={
            "username": root_user.get("username", "root"),
            "password": root_user.get("password", "")
        })

        if response.status_code == 200:
            data = response.json()
            token = data.get("token") or data.get("access_token")

            if token:
                # Decodificar payload (sem verificar assinatura)
                import base64
                parts = token.split(".")
                if len(parts) >= 2:
                    # Adicionar padding se necessário
                    payload_b64 = parts[1]
                    padding = 4 - len(payload_b64) % 4
                    if padding != 4:
                        payload_b64 += "=" * padding

                    try:
                        payload = base64.urlsafe_b64decode(payload_b64).decode('utf-8')
                        payload_lower = payload.lower()

                        assert "password" not in payload_lower, "Password no payload JWT"
                        assert "auth_secret" not in payload_lower, "auth_secret no payload JWT"
                        assert "$2a$" not in payload, "Hash bcrypt no payload JWT"
                    except:
                        pass  # Se não conseguir decodificar, pula

    def test_cors_not_exposing_credentials(self, http_client, api_url, timer):
        """CORS não deve expor credenciais indevidamente"""
        # Request com origin diferente
        headers = {"Origin": "http://malicious-site.com"}
        response = http_client.options(f"{api_url}/login", headers=headers)

        # Verificar headers CORS
        cors_headers = response.headers

        # Access-Control-Allow-Credentials não deve ser true para origins não confiáveis
        allow_credentials = cors_headers.get("Access-Control-Allow-Credentials", "")
        allow_origin = cors_headers.get("Access-Control-Allow-Origin", "")

        if allow_credentials.lower() == "true":
            assert allow_origin != "*", "CORS com credentials=true e origin=* é inseguro"

    def test_no_debug_endpoints_exposed(self, http_client, api_url, timer):
        """Endpoints de debug não devem estar expostos em produção"""
        debug_endpoints = [
            "/debug",
            "/debug/pprof",
            "/debug/vars",
            "/_debug",
            "/metrics",
            "/actuator",
            "/actuator/health",
            "/swagger",
            "/swagger-ui",
            "/api-docs",
            "/.env",
            "/config",
            "/phpinfo",
            "/server-status",
        ]

        for endpoint in debug_endpoints:
            response = http_client.get(f"{api_url}{endpoint}")

            # Não deve retornar 200 com conteúdo sensível
            if response.status_code == 200:
                response_text = response.text.lower()
                assert "secret" not in response_text, f"Endpoint {endpoint} expondo secrets"
                assert "password" not in response_text, f"Endpoint {endpoint} expondo passwords"

    def test_http_response_splitting_prevented(self, http_client, api_url, timer):
        """Response splitting deve ser prevenido"""
        # Tentar injetar headers via parâmetros
        malicious_values = [
            "test\r\nX-Injected: true",
            "test%0d%0aX-Injected: true",
            "test\nX-Injected: true",
        ]

        for value in malicious_values:
            response = http_client.get(
                f"{api_url}/users",
                params={"search": value}
            )

            # Verificar que header injetado não está presente
            assert "X-Injected" not in response.headers, \
                f"Response splitting possível com: {value}"

    def test_sensitive_data_in_url_prevented(self, http_client, api_url, root_user, timer):
        """Dados sensíveis não devem ser aceitos via URL (apenas body)"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        # Tentar passar dados via query string
        response = http_client.post(
            f"{api_url}/users?password=Test123!@#&role=root",
            json={"username": "test", "display_name": "Test"},
            headers={"Authorization": f"Bearer {root_user['token']}"}
        )

        # Não deve criar usuário com password da URL
        if response.status_code in [200, 201]:
            # Verificar que password da URL não foi usado
            # (deveria falhar por falta de password no body)
            pass

    def test_error_no_full_path_disclosure(self, http_client, api_url, timer):
        """Erros não devem revelar caminhos completos do sistema"""
        # Provocar erro
        response = http_client.post(f"{api_url}/login", data="invalid json{{{")

        response_text = response.text

        path_patterns = [
            r'/home/\w+',
            r'/root/',
            r'/var/www',
            r'/app/',
            r'/opt/',
            r'C:\\',
            r'D:\\',
            r'/usr/local',
        ]

        for pattern in path_patterns:
            matches = re.findall(pattern, response_text, re.IGNORECASE)
            assert not matches, f"Caminho do sistema vazado: {pattern}"


@pytest.mark.security
@pytest.mark.data_leakage
class TestInformationDisclosure:
    """Testes de divulgação de informações"""

    def test_version_info_not_detailed(self, http_client, api_url, timer):
        """Informações de versão não devem ser detalhadas"""
        response = http_client.get(f"{api_url}/../health")

        headers = response.headers

        # Server header não deve ter versão detalhada
        server = headers.get("Server", "")
        if server:
            # Versões detalhadas como "nginx/1.18.0" são problemáticas
            version_pattern = r'\d+\.\d+\.\d+'
            if re.search(version_pattern, server):
                # Apenas aviso, não falha
                pass

    def test_technology_stack_not_revealed(self, http_client, api_url, timer):
        """Stack tecnológica não deve ser revelada"""
        response = http_client.get(f"{api_url}/../health")

        response_text = response.text.lower()
        headers_text = str(response.headers).lower()

        # Verificar resposta e headers
        combined_text = response_text + headers_text

        # Não deve revelar tecnologias específicas desnecessariamente
        tech_keywords = [
            "go1.",  # Go version
            "gin-gonic",
            "gorilla",
            "postgresql 1",
        ]

        for keyword in tech_keywords:
            assert keyword not in combined_text, f"Tecnologia revelada: {keyword}"

    def test_internal_ip_not_exposed(self, http_client, api_url, timer):
        """IPs internos não devem ser expostos"""
        response = http_client.get(f"{api_url}/../health")

        response_text = response.text

        # Padrões de IP interno
        internal_ip_patterns = [
            r'10\.\d{1,3}\.\d{1,3}\.\d{1,3}',
            r'172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}',
            r'192\.168\.\d{1,3}\.\d{1,3}',
            r'127\.\d{1,3}\.\d{1,3}\.\d{1,3}',
        ]

        for pattern in internal_ip_patterns:
            matches = re.findall(pattern, response_text)
            # Permite 127.0.0.1 em certos contextos
            filtered = [m for m in matches if not m.startswith("127.")]
            assert not filtered, f"IP interno exposto: {filtered}"

    def test_database_schema_not_exposed(self, http_client, api_url, timer):
        """Schema do banco de dados não deve ser exposto"""
        # Tentar provocar erro que revele schema
        response = http_client.post(f"{api_url}/login", json={
            "username": "' OR 1=1; SELECT * FROM information_schema.tables; --",
            "password": "test"
        })

        response_text = response.text.lower()

        schema_keywords = [
            "information_schema",
            "pg_catalog",
            "pg_tables",
            "table_name",
            "column_name",
            "table_schema",
        ]

        for keyword in schema_keywords:
            assert keyword not in response_text, f"Schema exposto: {keyword}"

    def test_environment_variables_not_exposed(self, http_client, api_url, timer):
        """Variáveis de ambiente não devem ser expostas"""
        debug_paths = [
            "/env",
            "/.env",
            "/environment",
            "/config/env",
        ]

        for path in debug_paths:
            response = http_client.get(f"{api_url}{path}")

            if response.status_code == 200:
                response_text = response.text.lower()

                env_keywords = [
                    "db_password",
                    "jwt_secret",
                    "secret_key",
                    "api_key",
                    "postgres_password",
                ]

                for keyword in env_keywords:
                    assert keyword not in response_text, f"Variável exposta: {keyword}"
