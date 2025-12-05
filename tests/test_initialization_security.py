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

"""
Comprehensive tests for initialization flow and CORS security.

These tests verify:
1. Admin initialization endpoint security
2. Database empty check protection
3. CORS configuration
4. HTTP security headers
5. Race condition protection
"""

import pytest
import requests
import time
import threading
import concurrent.futures
from typing import List


@pytest.mark.security
@pytest.mark.initialization
class TestInitializationSecurity:
    """Tests for the admin initialization endpoint security"""

    def test_initialize_status_endpoint_accessible(self, http_client, api_url, timer):
        """Initialize status endpoint should be accessible without auth"""
        response = http_client.get(f"{api_url}/initialize/status")
        assert response.status_code == 200, "Status endpoint should be accessible"

        data = response.json()
        # Should have expected fields
        assert "is_initialized" in data
        assert "has_database" in data
        assert "requires_setup" in data

    def test_initialize_admin_blocked_when_database_has_data(self, http_client, api_url, root_user, timer):
        """Admin initialization should be blocked when database has data"""
        # First ensure we have a root user (database not empty)
        if not root_user:
            pytest.skip("Root user setup required")

        # Try to create another admin - should be blocked
        response = http_client.post(f"{api_url}/initialize/admin", json={
            "username": "hacker_root",
            "display_name": "Hacker Admin",
            "password": "HackerPass123!@#abc"
        })

        assert response.status_code == 403, "Should block admin creation when DB has data"

        data = response.json()
        assert data.get("success") is False
        assert "already initialized" in data.get("message", "").lower() or \
               "not empty" in data.get("message", "").lower() or \
               "contains" in data.get("message", "").lower()

    def test_initialize_admin_requires_strong_password(self, http_client, api_url, timer):
        """Admin initialization should require strong password (16+ chars)"""
        # This test may fail if database already has data (which is expected)
        # We're testing that weak passwords are rejected

        weak_passwords = [
            "short",           # Too short
            "12345678",        # Only numbers
            "password123",     # Too simple
            "Pass123!",        # Less than 16 chars
        ]

        for weak_pass in weak_passwords:
            response = http_client.post(f"{api_url}/initialize/admin", json={
                "username": "test_admin",
                "display_name": "Test Admin",
                "password": weak_pass
            })

            # Should either be 400 (bad request - weak password) or 403 (already initialized)
            # Both are acceptable - we care that it's not 200 with a weak password
            if response.status_code == 200:
                data = response.json()
                if data.get("success"):
                    pytest.fail(f"Weak password '{weak_pass}' was accepted")

    def test_initialize_admin_validates_username(self, http_client, api_url, timer):
        """Admin initialization should validate username format"""
        invalid_usernames = [
            "",                    # Empty
            "a",                   # Too short
            "user with spaces",    # Contains spaces
            "user@special!",       # Special characters
            "a" * 100,            # Too long
        ]

        for invalid_user in invalid_usernames:
            response = http_client.post(f"{api_url}/initialize/admin", json={
                "username": invalid_user,
                "display_name": "Test Admin",
                "password": "ValidPass123!@#abc"
            })

            # Should either be 400 (validation error) or 403 (already initialized)
            if response.status_code == 200:
                data = response.json()
                if data.get("success"):
                    pytest.fail(f"Invalid username '{invalid_user}' was accepted")

    def test_initialize_admin_requires_display_name(self, http_client, api_url, timer):
        """Admin initialization should require display name"""
        response = http_client.post(f"{api_url}/initialize/admin", json={
            "username": "test_admin",
            "display_name": "",  # Empty
            "password": "ValidPass123!@#abc"
        })

        # Should be 400 or 403 (if already initialized)
        if response.status_code == 200:
            data = response.json()
            if data.get("success"):
                pytest.fail("Empty display name was accepted")

    def test_initialize_admin_does_not_leak_password(self, http_client, api_url, timer):
        """Admin initialization response should not contain the password"""
        response = http_client.post(f"{api_url}/initialize/admin", json={
            "username": "test_admin",
            "display_name": "Test Admin",
            "password": "ValidPass123!@#abc"
        })

        data = response.json()
        # Whether successful or not, password should not be in response
        assert "admin_password" not in data or data.get("admin_password") is None, \
            "Password should not be returned in response"
        assert "password" not in data or data.get("password") is None, \
            "Password should not be returned in response"

    def test_initialize_status_shows_correct_state_after_init(self, http_client, api_url, root_user, timer):
        """After initialization, status should show system is initialized"""
        if not root_user:
            pytest.skip("Root user required")

        response = http_client.get(f"{api_url}/initialize/status")
        assert response.status_code == 200

        data = response.json()
        assert data.get("is_initialized") is True, "Should be initialized after admin creation"
        assert data.get("requires_setup") is False, "Should not require setup"

    def test_initialize_admin_only_post_method(self, http_client, api_url, timer):
        """Initialize admin endpoint should only accept POST method"""
        methods = ["GET", "PUT", "DELETE", "PATCH"]

        for method in methods:
            response = http_client.request(method, f"{api_url}/initialize/admin")
            assert response.status_code in [405, 404], \
                f"Method {method} should not be allowed"


@pytest.mark.security
@pytest.mark.cors
class TestCORSSecurity:
    """Tests for CORS (Cross-Origin Resource Sharing) security"""

    def test_cors_preflight_request(self, http_client, base_url, timer):
        """CORS preflight (OPTIONS) should be handled"""
        headers = {
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "Content-Type, Authorization"
        }

        response = http_client.options(f"{base_url}/api/login", headers=headers)
        # Should return 204 No Content or 200 OK for preflight
        assert response.status_code in [200, 204], "Preflight should be handled"

    def test_cors_allows_configured_origins(self, http_client, base_url, timer):
        """CORS should allow configured origins"""
        # Common development origins
        allowed_origins = [
            "http://localhost:5173",
            "http://localhost:8081",
            "http://localhost:65080",
        ]

        for origin in allowed_origins:
            headers = {"Origin": origin}
            response = http_client.get(f"{base_url}/health", headers=headers)

            # Check if CORS header is present for allowed origins
            cors_header = response.headers.get("Access-Control-Allow-Origin")
            # Either the specific origin or empty (if not in config)
            if cors_header:
                assert cors_header == origin or cors_header == "*", \
                    f"CORS origin mismatch for {origin}"

    def test_cors_blocks_unauthorized_origins(self, http_client, base_url, timer):
        """CORS should block unauthorized origins"""
        malicious_origins = [
            "http://evil.com",
            "http://attacker.site",
            "http://phishing.example.com",
        ]

        for origin in malicious_origins:
            headers = {"Origin": origin}
            response = http_client.get(f"{base_url}/health", headers=headers)

            cors_header = response.headers.get("Access-Control-Allow-Origin")
            # Should not return the malicious origin
            if cors_header:
                assert cors_header != origin, \
                    f"Malicious origin {origin} was allowed"

    def test_cors_credentials_handling(self, http_client, base_url, timer):
        """CORS credentials should be handled correctly"""
        headers = {
            "Origin": "http://localhost:5173",
        }

        response = http_client.get(f"{base_url}/health", headers=headers)

        # If Allow-Credentials is true, Allow-Origin cannot be *
        allow_creds = response.headers.get("Access-Control-Allow-Credentials")
        allow_origin = response.headers.get("Access-Control-Allow-Origin")

        if allow_creds == "true":
            assert allow_origin != "*", \
                "Cannot use * with credentials=true"


@pytest.mark.security
@pytest.mark.headers
class TestHTTPSecurityHeaders:
    """Tests for HTTP security headers"""

    def test_content_type_json_for_api(self, http_client, api_url, root_user, timer):
        """API responses should have Content-Type: application/json"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user required")

        headers = {"Authorization": f"Bearer {root_user['token']}"}
        response = http_client.get(f"{api_url}/users", headers=headers)

        content_type = response.headers.get("Content-Type", "")
        assert "application/json" in content_type, \
            "API should return JSON content type"

    def test_health_endpoint_returns_json(self, http_client, base_url, timer):
        """Health endpoint should return JSON"""
        response = http_client.get(f"{base_url}/health")

        content_type = response.headers.get("Content-Type", "")
        assert "application/json" in content_type, \
            "Health endpoint should return JSON"

    def test_no_server_version_disclosure(self, http_client, base_url, timer):
        """Server should not disclose version information"""
        response = http_client.get(f"{base_url}/health")

        # Check common headers that might leak server info
        dangerous_headers = ["X-Powered-By", "Server"]

        for header in dangerous_headers:
            value = response.headers.get(header, "")
            # Should not contain detailed version info
            if value:
                assert "version" not in value.lower(), \
                    f"Header {header} may leak version info: {value}"

    def test_error_responses_no_stack_trace(self, http_client, api_url, timer):
        """Error responses should not contain stack traces"""
        # Try to trigger an error
        response = http_client.get(f"{api_url}/nonexistent/endpoint")

        response_text = response.text.lower()

        # Should not contain stack trace indicators
        stack_indicators = [
            "goroutine",
            "panic",
            "runtime error",
            "stack trace",
            "at line",
            ".go:",
        ]

        for indicator in stack_indicators:
            assert indicator not in response_text, \
                f"Response may contain stack trace: found '{indicator}'"


@pytest.mark.security
@pytest.mark.concurrency
class TestConcurrencySecurity:
    """Tests for concurrent request handling and race conditions"""

    def test_concurrent_login_attempts(self, http_client, api_url, root_user, timer):
        """Concurrent login attempts should be handled safely"""
        if not root_user:
            pytest.skip("Root user required")

        def attempt_login():
            return http_client.post(f"{api_url}/login", json={
                "username": root_user["username"],
                "password": root_user["password"]
            })

        # Make 10 concurrent login attempts
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(attempt_login) for _ in range(10)]
            results = [f.result() for f in concurrent.futures.as_completed(futures)]

        # All should succeed without server errors
        for response in results:
            assert response.status_code != 500, "Server error on concurrent login"

    def test_concurrent_api_requests(self, http_client, api_url, root_user, timer):
        """Concurrent API requests should not cause race conditions"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user required")

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        def make_request(endpoint):
            return http_client.get(f"{api_url}/{endpoint}", headers=headers)

        endpoints = ["users", "entities", "categories", "agreements", "subcategories"]

        # Make concurrent requests to different endpoints
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(make_request, ep) for ep in endpoints * 2]
            results = [f.result() for f in concurrent.futures.as_completed(futures)]

        # Check for server errors
        for response in results:
            assert response.status_code != 500, "Server error on concurrent request"


@pytest.mark.security
@pytest.mark.database
class TestDatabaseResilienceSecurity:
    """Tests for database connection handling"""

    def test_health_check_indicates_db_status(self, http_client, base_url, timer):
        """Health endpoint should indicate database connection status"""
        response = http_client.get(f"{base_url}/health")

        # Should return health info
        assert response.status_code in [200, 503], "Health check should respond"

        data = response.json()
        assert "status" in data, "Health response should have status"

    def test_graceful_error_on_auth_failure(self, http_client, api_url, timer):
        """Authentication failures should return proper errors, not 500"""
        response = http_client.post(f"{api_url}/login", json={
            "username": "nonexistent_user_12345",
            "password": "wrongpassword"
        })

        # Should be 401 (unauthorized), not 500 (server error)
        assert response.status_code in [401, 400], \
            "Auth failure should return 401/400, not server error"


@pytest.mark.security
@pytest.mark.rate_limiting
class TestRateLimitingSecurity:
    """Tests for rate limiting protection"""

    def test_initialize_admin_not_abusable(self, http_client, api_url, timer):
        """Initialize admin endpoint should not be easily abused"""
        # Make multiple rapid requests
        responses = []
        for _ in range(20):
            response = http_client.post(f"{api_url}/initialize/admin", json={
                "username": "spam_admin",
                "display_name": "Spam Admin",
                "password": "ValidPass123!@#abc"
            })
            responses.append(response)

        # All should be handled (either 403 blocked or rate limited)
        # None should be 500 server error
        for response in responses:
            assert response.status_code != 500, "Server should handle rapid requests"

    def test_status_endpoint_handles_rapid_requests(self, http_client, api_url, timer):
        """Status endpoint should handle rapid requests"""
        responses = []
        for _ in range(50):
            response = http_client.get(f"{api_url}/initialize/status")
            responses.append(response.status_code)

        # All should succeed
        assert all(code == 200 for code in responses), \
            "Status endpoint should handle rapid requests"


@pytest.mark.security
@pytest.mark.input_validation
class TestInitializationInputValidation:
    """Input validation tests specific to initialization"""

    def test_initialize_admin_json_injection(self, http_client, api_url, timer):
        """Initialize admin should handle JSON injection attempts"""
        malicious_payloads = [
            {"username": "admin\",\"role\":\"root\"", "display_name": "Test", "password": "ValidPass123!@#abc"},
            {"username": "admin", "display_name": "{\"injection\": true}", "password": "ValidPass123!@#abc"},
            {"username": "admin'; DROP TABLE users; --", "display_name": "Test", "password": "ValidPass123!@#abc"},
        ]

        for payload in malicious_payloads:
            response = http_client.post(f"{api_url}/initialize/admin", json=payload)
            # Should either reject (400/403) or handle safely (200 with validation)
            assert response.status_code != 500, f"Injection caused server error: {payload}"

    def test_initialize_admin_unicode_handling(self, http_client, api_url, timer):
        """Initialize admin should handle unicode properly"""
        unicode_payloads = [
            {"username": "admin", "display_name": "管理员", "password": "ValidPass123!@#abc"},  # Chinese
            {"username": "admin", "display_name": "Администратор", "password": "ValidPass123!@#abc"},  # Russian
            {"username": "admin", "display_name": "مدير", "password": "ValidPass123!@#abc"},  # Arabic
            {"username": "admin", "display_name": "🔐 Admin 👤", "password": "ValidPass123!@#abc"},  # Emojis
        ]

        for payload in unicode_payloads:
            response = http_client.post(f"{api_url}/initialize/admin", json=payload)
            # Should handle without server error
            assert response.status_code != 500, f"Unicode caused server error: {payload}"

    def test_initialize_admin_null_bytes(self, http_client, api_url, timer):
        """Initialize admin should handle null bytes safely"""
        response = http_client.post(f"{api_url}/initialize/admin", json={
            "username": "admin\x00malicious",
            "display_name": "Test\x00Name",
            "password": "ValidPass123!@#abc"
        })

        # Should not cause server error
        assert response.status_code != 500, "Null bytes caused server error"

    def test_initialize_admin_oversized_payload(self, http_client, api_url, timer):
        """Initialize admin should reject oversized payloads"""
        huge_string = "A" * 1000000  # 1MB string

        try:
            response = http_client.post(f"{api_url}/initialize/admin", json={
                "username": "admin",
                "display_name": huge_string,
                "password": "ValidPass123!@#abc"
            }, timeout=30)

            # Should reject or handle
            assert response.status_code in [400, 413, 403], \
                "Oversized payload should be rejected"
        except requests.exceptions.RequestException:
            # Connection issues are acceptable for huge payloads
            pass
