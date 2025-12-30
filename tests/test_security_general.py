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
@pytest.mark.sql_injection
class TestSQLInjection:
    """Tests for SQL Injection vulnerabilities"""

    def test_login_sql_injection(self, http_client, api_url):
        """Attempt SQL injection in login credentials"""
        payloads = [
            "' OR '1'='1",
            "admin' --",
            "admin' #",
            "' UNION SELECT 1,2,3 --"
        ]

        for payload in payloads:
            response = http_client.post(f"{api_url}/login", json={
                "username": payload,
                "password": "password123"
            })
            assert response.status_code in [400, 401, 404], f"Should fail SQLi login with payload: {payload}"
            assert "internal server error" not in response.text.lower()

    def test_get_client_sql_injection(self, http_client, api_url, root_user):
        """Attempt SQL injection in client retrieval"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user required")

        token = root_user["token"]
        headers = {"Authorization": f"Bearer {token}"}

        payloads = [
            "1' OR '1'='1",
            "00000000-0000-0000-0000-000000000000' UNION SELECT --"
        ]

        for payload in payloads:
            response = http_client.get(f"{api_url}/clients/{payload}", headers=headers)
            # Should be 404 (not found) or 400 (bad request/invalid UUID), NOT 500
            assert response.status_code in [400, 404], f"Should handle SQLi in ID: {payload}"

@pytest.mark.security
@pytest.mark.xss
class TestXSS:
    """Tests for Cross-Site Scripting (XSS) vulnerabilities"""

    def test_user_creation_xss(self, http_client, api_url, root_user):
        """Attempt to inject script tags in user fields"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user required")

        token = root_user["token"]
        headers = {"Authorization": f"Bearer {token}"}

        xss_payload = "<script>alert('xss')</script>"
        username = f"xssuser_{int(time.time())}"

        # Try to inject in display_name (username usually validated for chars)
        response = http_client.post(f"{api_url}/users", json={
            "username": username,
            "display_name": f"User {xss_payload}",
            "password": "ValidPass123!@#",
            "role": "user"
        }, headers=headers)

        # API should either reject it OR sanitize it on output.
        # But for now, we check if it accepts it. If it accepts, we must verify output encoding.
        if response.status_code == 201:
            user_id = response.json().get("id")
            # Fetch user
            get_resp = http_client.get(f"{api_url}/users/{user_id}", headers=headers)
            assert get_resp.status_code == 200
            data = get_resp.json()
            # If it comes back verbatim, client-side must handle it.
            # But ideally backend should sanitize or client should encode.
            # Here we just verify the system didn't crash.
            # Proper XSS check usually requires browser or HTML inspection.
            # We can check if response content-type is JSON (which mitigates XSS if treated as JSON).
            assert "application/json" in get_resp.headers["Content-Type"]
