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
Testes de Segurança para APIs de File Upload, Deploy, Health e Affiliates
"""

import pytest
import requests
import time
import uuid
import io
import base64


class TestFileUploadAuth:
    """Testes de autenticação para API de File Upload"""

    def test_upload_requires_auth(self, http_client, api_url, timer):
        """POST /api/upload sem token deve retornar 401"""
        files = {"file": ("test.jpg", b"fake image content", "image/jpeg")}
        response = http_client.post(f"{api_url}/upload", files=files)
        assert response.status_code == 401

    def test_upload_requires_permission(self, http_client, api_url, regular_user, timer):
        """POST /api/upload sem permissão settings:manage_uploads deve retornar 403"""
        files = {"file": ("test.jpg", b"fake image content", "image/jpeg")}
        response = http_client.post(
            f"{api_url}/upload",
            headers={"Authorization": f"Bearer {regular_user['token']}"},
            files=files
        )
        assert response.status_code in [403, 401]


class TestFileUploadMIMEValidation:
    """Testes de validação de MIME type para File Upload"""

    # Tipos MIME permitidos conforme docs
    ALLOWED_MIMES = [
        ("test.jpg", "image/jpeg"),
        ("test.png", "image/png"),
        ("test.gif", "image/gif"),
        ("test.webp", "image/webp"),
        ("test.svg", "image/svg+xml"),
    ]

    # Tipos MIME proibidos
    FORBIDDEN_MIMES = [
        ("test.html", "text/html"),
        ("test.js", "application/javascript"),
        ("test.php", "application/x-php"),
        ("test.exe", "application/x-executable"),
        ("test.sh", "application/x-shellscript"),
        ("test.pdf", "application/pdf"),
        ("test.zip", "application/zip"),
    ]

    def test_forbidden_mime_types_rejected(self, http_client, api_url, root_user, timer):
        """Arquivos com MIME types não permitidos devem ser rejeitados"""
        for filename, mime in self.FORBIDDEN_MIMES:
            files = {"file": (filename, b"malicious content", mime)}
            response = http_client.post(
                f"{api_url}/upload",
                headers={"Authorization": f"Bearer {root_user['token']}"},
                files=files
            )
            assert response.status_code in [400, 415], f"MIME {mime} deveria ser rejeitado"


class TestFileUploadSecurity:
    """Testes de segurança para File Upload"""

    def test_file_size_limit(self, http_client, api_url, root_user, timer):
        """Arquivos > 15MB devem ser rejeitados"""
        # Criar arquivo de 16MB
        large_content = b"A" * (16 * 1024 * 1024)
        files = {"file": ("large.jpg", large_content, "image/jpeg")}

        response = http_client.post(
            f"{api_url}/upload",
            headers={"Authorization": f"Bearer {root_user['token']}"},
            files=files
        )
        assert response.status_code in [400, 413]

    def test_path_traversal_in_filename(self, http_client, api_url, root_user, timer):
        """Path traversal no nome do arquivo deve ser bloqueado"""
        evil_filenames = [
            "../../../etc/passwd.jpg",
            "..\\..\\..\\windows\\system32\\config\\sam.jpg",
            "....//....//test.jpg",
            "/etc/passwd.jpg",
            "C:\\Windows\\System32\\config\\sam.jpg",
        ]

        for filename in evil_filenames:
            files = {"file": (filename, b"test content", "image/jpeg")}
            response = http_client.post(
                f"{api_url}/upload",
                headers={"Authorization": f"Bearer {root_user['token']}"},
                files=files
            )
            # Deve sanitizar ou rejeitar
            if response.status_code == 200:
                data = response.json()
                url = data.get("url", "")
                # URL não deve conter path traversal
                assert ".." not in url
                assert "/etc/" not in url
                assert "\\windows\\" not in url.lower()

    def test_double_extension_attack(self, http_client, api_url, root_user, timer):
        """Double extension attack deve ser bloqueado"""
        evil_filenames = [
            "malware.php.jpg",
            "shell.jsp.png",
            "exploit.exe.gif",
            "script.js.webp",
        ]

        for filename in evil_filenames:
            files = {"file": (filename, b"test content", "image/jpeg")}
            response = http_client.post(
                f"{api_url}/upload",
                headers={"Authorization": f"Bearer {root_user['token']}"},
                files=files
            )
            # Se aceitar, verificar que extensão perigosa foi removida
            if response.status_code == 200:
                data = response.json()
                url = data.get("url", "")
                assert ".php" not in url
                assert ".jsp" not in url
                assert ".exe" not in url
                assert ".js" not in url.split(".")[-1]  # Não pode terminar em .js

    def test_svg_xss_payload(self, http_client, api_url, root_user, timer):
        """SVG com XSS deve ser sanitizado ou rejeitado"""
        evil_svg = b'''<?xml version="1.0"?>
        <svg xmlns="http://www.w3.org/2000/svg">
            <script>alert('XSS')</script>
        </svg>'''

        files = {"file": ("evil.svg", evil_svg, "image/svg+xml")}
        response = http_client.post(
            f"{api_url}/upload",
            headers={"Authorization": f"Bearer {root_user['token']}"},
            files=files
        )
        # Deve sanitizar o SVG ou rejeitar
        assert response.status_code in [200, 400]

    def test_null_byte_in_filename(self, http_client, api_url, root_user, timer):
        """Null byte no filename deve ser sanitizado"""
        files = {"file": ("test.jpg\x00.php", b"test content", "image/jpeg")}
        response = http_client.post(
            f"{api_url}/upload",
            headers={"Authorization": f"Bearer {root_user['token']}"},
            files=files
        )
        if response.status_code == 200:
            data = response.json()
            url = data.get("url", "")
            assert "\x00" not in url
            assert ".php" not in url


class TestDeployAPIAuth:
    """Testes de autenticação para Deploy API"""

    def test_deploy_config_without_token(self, http_client, api_url, root_user, timer):
        """POST /api/deploy/config sem token deve retornar 401 ou 403 (se instalado)"""
        # A fixture root_user garante que o sistema está instalado (DB não vazio)
        response = http_client.post(
            f"{api_url}/deploy/config",
            json={"server_host": "localhost"}
        )
        # Deve recusar: 401 (se token exigido e faltante) ou 403 (se sistema instalado)
        assert response.status_code in [401, 403], \
            f"Deploy config sem token retornou {response.status_code}, esperava 401 ou 403"

    def test_deploy_config_with_invalid_token(self, http_client, api_url, root_user, timer):
        """POST /api/deploy/config com token inválido deve retornar 401 ou 403"""
        response = http_client.post(
            f"{api_url}/deploy/config",
            headers={"Authorization": "Bearer invalid-deploy-token"},
            json={"server_host": "localhost"}
        )
        assert response.status_code in [401, 403], \
            f"Deploy config com token inválido retornou {response.status_code}, esperava 401 ou 403"

    def test_deploy_config_with_user_jwt_fails(self, http_client, api_url, root_user, timer):
        """POST /api/deploy/config com JWT de usuário deve falhar (precisa deploy token)"""
        response = http_client.post(
            f"{api_url}/deploy/config",
            headers={"Authorization": f"Bearer {root_user['token']}"},
            json={"server_host": "localhost"}
        )
        # Deploy endpoint DEVE exigir token especial, não aceitar JWT de usuário
        assert response.status_code in [401, 403], \
            f"Deploy config com JWT de usuário retornou {response.status_code}, esperava 401/403"


class TestDeployPublicEndpoints:
    """Testes para endpoints públicos de Deploy"""

    def test_deploy_status_is_public(self, http_client, api_url, timer):
        """GET /api/deploy/status deve ser público"""
        response = http_client.get(f"{api_url}/deploy/status")
        assert response.status_code == 200
        data = response.json()
        assert "status" in data or "environment" in data

    def test_deploy_defaults_security(self, http_client, api_url, root_user, timer):
        """GET /api/deploy/config/defaults deve ser PROTEGIDO se instalado"""
        # Se sistema instalado, deve retornar 403
        response = http_client.get(f"{api_url}/deploy/config/defaults")
        assert response.status_code in [401, 403], \
            f"Deploy defaults retornou {response.status_code} em sistema instalado, esperava 403"

    def test_deploy_validate_is_public(self, http_client, api_url, timer):
        """POST /api/deploy/validate deve ser público"""
        response = http_client.post(
            f"{api_url}/deploy/validate",
            json={"server_host": "localhost"}
        )
        # Deve validar sem autenticação
        assert response.status_code in [200, 400]

    def test_deploy_status_no_secrets(self, http_client, api_url, timer):
        """Deploy status não deve expor secrets"""
        response = http_client.get(f"{api_url}/deploy/status")
        if response.status_code == 200:
            text = response.text.lower()
            assert "password" not in text
            assert "secret" not in text
            assert "key" not in text or "secret_key" not in text

    def test_deploy_defaults_no_secrets(self, http_client, api_url, timer):
        """Deploy defaults não deve expor secrets"""
        response = http_client.get(f"{api_url}/deploy/config/defaults")
        if response.status_code == 200:
            text = response.text.lower()
            # Pode ter "password" como campo mas não valor real
            assert "actual_password" not in text
            assert "real_secret" not in text


class TestDeployValidateSQLi:
    """Testes de SQL Injection no Deploy Validate"""

    SQL_PAYLOADS = [
        "'; DROP TABLE users;--",
        "' OR '1'='1",
        "localhost'; SELECT * FROM pg_catalog.pg_tables;--",
    ]

    def test_sqli_in_database_host(self, http_client, api_url, timer):
        """SQL Injection em database_host deve ser bloqueado"""
        for payload in self.SQL_PAYLOADS:
            response = http_client.post(
                f"{api_url}/deploy/validate",
                json={"database_host": payload}
            )
            assert "syntax" not in response.text.lower()
            assert "error" not in response.text.lower() or response.status_code == 400

    def test_sqli_in_database_name(self, http_client, api_url, timer):
        """SQL Injection em database_name deve ser bloqueado"""
        for payload in self.SQL_PAYLOADS:
            response = http_client.post(
                f"{api_url}/deploy/validate",
                json={"database_name": payload}
            )
            assert "pg_" not in response.text.lower()  # Não deve expor catálogo


class TestHealthCheckAPI:
    """Testes para Health Check API"""

    def test_health_is_public(self, http_client, base_url, timer):
        """GET /health deve ser público"""
        response = http_client.get(f"{base_url}/health")
        assert response.status_code in [200, 503]

    def test_health_returns_status(self, http_client, base_url, timer):
        """Health check deve retornar status"""
        response = http_client.get(f"{base_url}/health")
        data = response.json()
        assert "status" in data
        assert data["status"] in ["healthy", "unhealthy"]

    def test_health_no_sensitive_info(self, http_client, base_url, timer):
        """Health check não deve expor info sensível"""
        response = http_client.get(f"{base_url}/health")
        text = response.text.lower()
        assert "password" not in text
        assert "secret" not in text
        assert "key" not in text
        assert "token" not in text


class TestAuditLogsAPIComplete:
    """Testes completos para API de Audit Logs"""

    def test_get_audit_logs_requires_auth(self, http_client, api_url, timer):
        """GET /api/audit-logs sem token deve retornar 401"""
        response = http_client.get(f"{api_url}/audit-logs")
        assert response.status_code == 401

    def test_get_audit_log_by_id_requires_auth(self, http_client, api_url, timer):
        """GET /api/audit-logs/{id} sem token deve retornar 401"""
        fake_id = str(uuid.uuid4())
        response = http_client.get(f"{api_url}/audit-logs/{fake_id}")
        assert response.status_code == 401

    def test_get_audit_logs_resource_requires_auth(self, http_client, api_url, timer):
        """GET /api/audit-logs/resource/{resource}/{id} sem token deve retornar 401"""
        response = http_client.get(f"{api_url}/audit-logs/resource/user/test-id")
        assert response.status_code == 401

    def test_export_audit_logs_requires_auth(self, http_client, api_url, timer):
        """GET /api/audit-logs/export sem token deve retornar 401"""
        response = http_client.get(f"{api_url}/audit-logs/export")
        assert response.status_code == 401

    def test_sqli_in_audit_logs_query_params(self, http_client, api_url, root_user, timer):
        """SQL Injection em query params de audit logs deve ser bloqueado"""
        sqli_params = [
            {"resource": "' OR '1'='1"},
            {"operation": "'; DROP TABLE audit_logs;--"},
            {"admin_search": "admin' UNION SELECT * FROM users--"},
            {"resource_search": "test'; SELECT password FROM users;--"},
            {"ip_address": "127.0.0.1' OR '1'='1"},
        ]

        for params in sqli_params:
            response = http_client.get(
                f"{api_url}/audit-logs",
                headers={"Authorization": f"Bearer {root_user['token']}"},
                params=params
            )
            # Não deve vazar erro SQL
            if response.status_code == 200:
                assert "syntax" not in response.text.lower()
                assert "error" not in response.text.lower()

    def test_audit_logs_limit_max(self, http_client, api_url, root_user, timer):
        """Limit > 1000 deve ser rejeitado ou truncado"""
        response = http_client.get(
            f"{api_url}/audit-logs",
            headers={"Authorization": f"Bearer {root_user['token']}"},
            params={"limit": 10000}
        )
        # Deve aceitar com truncamento ou rejeitar
        assert response.status_code in [200, 400]

        if response.status_code == 200:
            data = response.json()
            # Se aceitar, limit deve ser <= 1000
            if isinstance(data, dict) and "data" in data:
                assert len(data["data"]) <= 1000

    def test_audit_logs_no_passwords(self, http_client, api_url, root_user, timer):
        """Audit logs não devem conter senhas"""
        response = http_client.get(
            f"{api_url}/audit-logs",
            headers={"Authorization": f"Bearer {root_user['token']}"},
            params={"limit": 100}
        )
        if response.status_code == 200:
            text = response.text
            # Não deve ter hashes bcrypt
            assert "$2a$" not in text
            assert "$2b$" not in text
            assert "$2y$" not in text


class TestAffiliatesAPIComplete:
    """Testes completos para API de Affiliates"""

    def test_put_affiliate_requires_auth(self, http_client, api_url, timer):
        """PUT /api/affiliates/{id} sem token deve retornar 401"""
        fake_id = str(uuid.uuid4())
        response = http_client.put(
            f"{api_url}/affiliates/{fake_id}",
            json={"name": "Test Affiliate"}
        )
        assert response.status_code == 401

    def test_delete_affiliate_requires_auth(self, http_client, api_url, timer):
        """DELETE /api/affiliates/{id} sem token deve retornar 401"""
        fake_id = str(uuid.uuid4())
        response = http_client.delete(f"{api_url}/affiliates/{fake_id}")
        assert response.status_code == 401

    def test_put_affiliate_not_found(self, http_client, api_url, root_user, timer):
        """PUT /api/affiliates/{id} com ID inexistente deve retornar 404"""
        fake_id = str(uuid.uuid4())
        response = http_client.put(
            f"{api_url}/affiliates/{fake_id}",
            headers={"Authorization": f"Bearer {root_user['token']}"},
            json={"name": "Test Affiliate"}
        )
        # 404 ou 400 são respostas válidas para ID inexistente
        assert response.status_code in [400, 404]

    def test_delete_affiliate_not_found(self, http_client, api_url, root_user, timer):
        """DELETE /api/affiliates/{id} com ID inexistente deve retornar 404"""
        fake_id = str(uuid.uuid4())
        response = http_client.delete(
            f"{api_url}/affiliates/{fake_id}",
            headers={"Authorization": f"Bearer {root_user['token']}"}
        )
        # 400 ou 404 são respostas válidas para ID inexistente
        assert response.status_code in [400, 404]

    def test_xss_in_affiliate_name(self, http_client, api_url, root_user, timer):
        """XSS em nome de affiliate deve ser sanitizado"""
        # Primeiro criar um cliente para ter um affiliate
        client_resp = http_client.post(
            f"{api_url}/clients",
            headers={"Authorization": f"Bearer {root_user['token']}"},
            json={"name": "Test Client for Affiliate"}
        )

        if client_resp.status_code == 201:
            client_id = client_resp.json().get("id")

            # Criar affiliate com XSS
            aff_resp = http_client.post(
                f"{api_url}/clients/{client_id}/affiliates",
                headers={"Authorization": f"Bearer {root_user['token']}"},
                json={"name": "<script>alert('XSS')</script>"}
            )

            if aff_resp.status_code == 201:
                aff_id = aff_resp.json().get("id")

                # Verificar que XSS não está presente
                get_resp = http_client.get(
                    f"{api_url}/clients/{client_id}/affiliates",
                    headers={"Authorization": f"Bearer {root_user['token']}"}
                )
                if get_resp.status_code == 200:
                    assert "<script>" not in get_resp.text

    def test_sqli_in_affiliate_fields(self, http_client, api_url, root_user, timer):
        """SQL Injection em campos de affiliate deve ser bloqueado"""
        fake_id = str(uuid.uuid4())
        sqli_payloads = [
            {"name": "' OR '1'='1"},
            {"description": "'; DROP TABLE affiliates;--"},
            {"email": "test'@test.com UNION SELECT * FROM users--"},
        ]

        for payload in sqli_payloads:
            response = http_client.put(
                f"{api_url}/affiliates/{fake_id}",
                headers={"Authorization": f"Bearer {root_user['token']}"},
                json=payload
            )
            # 404 é esperado, mas não deve ter erro SQL
            assert "syntax" not in response.text.lower()
            assert "sql" not in response.text.lower()
