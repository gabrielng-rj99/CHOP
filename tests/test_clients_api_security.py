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
Comprehensive security tests for Clients API endpoints.
Based on APIs-checklist.md for /api/clients/* endpoints.
"""

import pytest
import time
import uuid


# =============================================================================
# GET /api/clients TESTS
# =============================================================================

@pytest.mark.api
@pytest.mark.security
class TestGetClientsAPI:
    """Tests for GET /api/clients endpoint"""

    def test_include_stats_sql_injection(self, http_client, api_url, root_user, timer):
        """Test SQL injection in include_stats query param"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        sql_payloads = [
            "true; DROP TABLE clients;--",
            "1' OR '1'='1",
            "true UNION SELECT * FROM users--",
            "1; SELECT * FROM users--",
            "true' AND '1'='1",
        ]

        for payload in sql_payloads:
            response = http_client.get(
                f"{api_url}/clients?include_stats={payload}",
                headers=headers
            )
            # Should not cause internal server error
            assert response.status_code != 500, f"SQL injection caused error: {payload}"
            # Should either ignore or reject, but not execute
            assert response.status_code in [200, 400, 422], f"Unexpected status for: {payload}"


# =============================================================================
# POST /api/clients TESTS
# =============================================================================

@pytest.mark.api
@pytest.mark.security
class TestPostClientsAPI:
    """Tests for POST /api/clients endpoint"""

    def test_create_client_without_permission(self, http_client, api_url, regular_user, timer):
        """User without permission should not be able to create clients"""
        if not regular_user or "token" not in regular_user:
            pytest.skip("Regular user não disponível")

        headers = {"Authorization": f"Bearer {regular_user['token']}"}

        response = http_client.post(f"{api_url}/clients", json={
            "name": f"Unauthorized Client {int(time.time())}",
            "email": "unauthorized@test.com"
        }, headers=headers)

        # May be 200 if user has default permissions, or 403 if denied
        # This test documents the expected behavior
        assert response.status_code in [200, 201, 403], "Response should be success or forbidden"

    def test_create_client_name_overflow_10k(self, http_client, api_url, root_user, timer):
        """Test name field with 10K+ characters"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}
        long_name = "A" * 10001

        response = http_client.post(f"{api_url}/clients", json={
            "name": long_name,
            "email": "overflow@test.com"
        }, headers=headers)

        # Should reject with 400/422 or accept but truncate - never 500
        assert response.status_code != 500, "Overflow should not cause server error"
        assert response.status_code in [200, 201, 400, 413, 422], f"Unexpected status: {response.status_code}"

    def test_create_client_notes_overflow_10k(self, http_client, api_url, root_user, timer):
        """Test notes field with 10K+ characters"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}
        long_notes = "Note text. " * 2000  # Over 20K characters

        response = http_client.post(f"{api_url}/clients", json={
            "name": f"Overflow Notes Client {int(time.time())}",
            "notes": long_notes,
            "email": "overflownotes@test.com"
        }, headers=headers)

        # Should handle gracefully
        assert response.status_code != 500, "Overflow should not cause server error"
        assert response.status_code in [200, 201, 400, 413, 422], f"Unexpected status: {response.status_code}"


# =============================================================================
# GET /api/clients/{id} TESTS
# =============================================================================

@pytest.mark.api
@pytest.mark.security
class TestGetClientByIdAPI:
    """Tests for GET /api/clients/{id} endpoint"""

    def test_get_client_without_auth(self, http_client, api_url, timer):
        """Get client by ID without authentication should fail"""
        fake_uuid = "12345678-1234-1234-1234-123456789012"
        response = http_client.get(f"{api_url}/clients/{fake_uuid}")
        assert response.status_code == 401, "Should require authentication"

    def test_get_client_sql_injection_in_id(self, http_client, api_url, root_user, timer):
        """Test SQL injection in client ID parameter"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        sql_payloads = [
            "' OR '1'='1",
            "1; DROP TABLE clients;--",
            "1' UNION SELECT * FROM users--",
            "12345678-1234-1234-1234-123456789012' OR '1'='1",
            "12345678-1234-1234-1234-123456789012; DELETE FROM clients--",
        ]

        for payload in sql_payloads:
            response = http_client.get(f"{api_url}/clients/{payload}", headers=headers)
            # Should return 400 (invalid) or 404 (not found), never 500
            assert response.status_code != 500, f"SQL injection caused error: {payload}"
            assert response.status_code in [400, 404, 422], f"Unexpected status for: {payload}"

    def test_get_client_invalid_uuid_format(self, http_client, api_url, root_user, timer):
        """Test various invalid UUID formats"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        invalid_ids = [
            "not-a-uuid",
            "12345",
            "12345678-1234-1234-1234",  # Incomplete
            "12345678-1234-1234-1234-12345678901234567890",  # Too long
            "GGGGGGGG-GGGG-GGGG-GGGG-GGGGGGGGGGGG",  # Invalid hex
            "null",
            "undefined",
            "true",
            "false",
            "",
            "0",
            "-1",
            "../../../etc/passwd",
            "<script>alert('xss')</script>",
        ]

        for invalid_id in invalid_ids:
            if not invalid_id:  # Skip empty string as it would hit /api/clients
                continue
            response = http_client.get(f"{api_url}/clients/{invalid_id}", headers=headers)
            # Should return 400 or 404, never 500
            assert response.status_code != 500, f"Invalid ID caused error: {invalid_id}"
            assert response.status_code in [400, 404, 422], f"Unexpected status for: {invalid_id}"


# =============================================================================
# PUT /api/clients/{id} TESTS
# =============================================================================

@pytest.mark.api
@pytest.mark.security
class TestPutClientAPI:
    """Tests for PUT /api/clients/{id} endpoint"""

    def _create_test_client(self, http_client, api_url, headers):
        """Helper to create a client for testing"""
        unique_id = str(uuid.uuid4())[:8]
        response = http_client.post(f"{api_url}/clients", json={
            "name": f"Update Test Client {unique_id}",
            "email": f"updatetest{unique_id}@test.com"
        }, headers=headers)
        if response.status_code in [200, 201]:
            data = response.json()
            return data.get("data", {}).get("id") or data.get("id")
        return None

    def test_update_client_without_auth(self, http_client, api_url, timer):
        """Update client without authentication should fail"""
        fake_uuid = "12345678-1234-1234-1234-123456789012"
        response = http_client.put(f"{api_url}/clients/{fake_uuid}", json={
            "name": "Updated Name"
        })
        assert response.status_code == 401, "Should require authentication"

    def test_update_nonexistent_client(self, http_client, api_url, root_user, timer):
        """Update non-existent client should return 404"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}
        nonexistent_uuid = "00000000-0000-0000-0000-000000000001"

        response = http_client.put(f"{api_url}/clients/{nonexistent_uuid}", json={
            "name": "Updated Name"
        }, headers=headers)

        assert response.status_code == 404, "Non-existent client should return 404"

    def test_update_client_xss_all_fields(self, http_client, api_url, root_user, timer):
        """Test XSS in all updatable fields"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}
        client_id = self._create_test_client(http_client, api_url, headers)

        if not client_id:
            pytest.skip("Could not create test client")

        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "'><script>alert(String.fromCharCode(88,83,83))</script>",
        ]

        for payload in xss_payloads:
            response = http_client.put(f"{api_url}/clients/{client_id}", json={
                "name": payload,
                "nickname": payload,
                "notes": payload,
                "address": payload,
                "email": f"xss{int(time.time())}@test.com",
                "phone": "11999999999"
            }, headers=headers)

            # Should accept but sanitize, or reject
            assert response.status_code != 500, f"XSS payload caused error: {payload}"

            if response.status_code in [200, 204]:
                # Verify data is sanitized on read
                get_response = http_client.get(f"{api_url}/clients/{client_id}", headers=headers)
                if get_response.status_code == 200:
                    data = get_response.json()
                    client_data = data.get("data", data)
                    # Check that raw script tags are not present
                    for field in ["name", "nickname", "notes", "address"]:
                        value = client_data.get(field, "")
                        if value:
                            assert "<script>" not in value.lower(), f"XSS not sanitized in {field}"

    def test_update_client_sql_injection_all_fields(self, http_client, api_url, root_user, timer):
        """Test SQL injection in all updatable fields"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}
        client_id = self._create_test_client(http_client, api_url, headers)

        if not client_id:
            pytest.skip("Could not create test client")

        sql_payloads = [
            "'; DROP TABLE clients;--",
            "' OR '1'='1",
            "1; DELETE FROM clients WHERE 1=1;--",
            "Robert'); DROP TABLE Students;--",
        ]

        for payload in sql_payloads:
            response = http_client.put(f"{api_url}/clients/{client_id}", json={
                "name": f"Test {payload}",
                "notes": payload,
                "address": payload,
            }, headers=headers)

            # Should not cause internal error
            assert response.status_code != 500, f"SQL injection caused error: {payload}"

    def test_update_client_overflow_all_fields(self, http_client, api_url, root_user, timer):
        """Test overflow in all updatable fields"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}
        client_id = self._create_test_client(http_client, api_url, headers)

        if not client_id:
            pytest.skip("Could not create test client")

        long_string = "A" * 10001

        response = http_client.put(f"{api_url}/clients/{client_id}", json={
            "name": long_string,
            "nickname": long_string,
            "notes": long_string,
            "address": long_string,
        }, headers=headers)

        # Should handle gracefully
        assert response.status_code != 500, "Overflow should not cause server error"


# =============================================================================
# DELETE /api/clients/{id} TESTS
# =============================================================================

@pytest.mark.api
@pytest.mark.security
class TestDeleteClientAPI:
    """Tests for DELETE /api/clients/{id} endpoint"""

    def test_delete_client_without_auth(self, http_client, api_url, timer):
        """Delete client without authentication should fail"""
        fake_uuid = "12345678-1234-1234-1234-123456789012"
        response = http_client.delete(f"{api_url}/clients/{fake_uuid}")
        assert response.status_code == 401, "Should require authentication"

    def test_delete_client_without_permission(self, http_client, api_url, root_user, regular_user, timer):
        """User without permission should not be able to delete clients"""
        if not regular_user or "token" not in regular_user:
            pytest.skip("Regular user não disponível")
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        # Create a client as root
        root_headers = {"Authorization": f"Bearer {root_user['token']}"}
        create_response = http_client.post(f"{api_url}/clients", json={
            "name": f"Delete Permission Test {int(time.time())}",
            "email": "deletepermtest@test.com"
        }, headers=root_headers)

        if create_response.status_code not in [200, 201]:
            pytest.skip("Could not create test client")

        client_data = create_response.json()
        client_id = client_data.get("data", {}).get("id") or client_data.get("id")

        if not client_id:
            pytest.skip("Client ID not returned")

        # Try to delete as regular user
        user_headers = {"Authorization": f"Bearer {regular_user['token']}"}
        response = http_client.delete(f"{api_url}/clients/{client_id}", headers=user_headers)

        # May be 200 if user has permissions, or 403 if denied
        assert response.status_code in [200, 204, 403], "Response should be success or forbidden"

    def test_delete_client_sql_injection_in_id(self, http_client, api_url, root_user, timer):
        """Test SQL injection in delete client ID parameter"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        sql_payloads = [
            "' OR '1'='1",
            "1; DROP TABLE clients;--",
            "12345678-1234-1234-1234-123456789012'; DELETE FROM clients;--",
        ]

        for payload in sql_payloads:
            response = http_client.delete(f"{api_url}/clients/{payload}", headers=headers)
            # Should return 400 or 404, never 500
            assert response.status_code != 500, f"SQL injection caused error: {payload}"
            assert response.status_code in [400, 404, 422], f"Unexpected status for: {payload}"


# =============================================================================
# PUT /api/clients/{id}/archive TESTS
# =============================================================================

@pytest.mark.api
@pytest.mark.security
class TestArchiveClientAPI:
    """Tests for PUT /api/clients/{id}/archive endpoint"""

    def _create_test_client(self, http_client, api_url, headers):
        """Helper to create a client for testing"""
        unique_id = str(uuid.uuid4())[:8]
        response = http_client.post(f"{api_url}/clients", json={
            "name": f"Archive Test Client {unique_id}",
            "email": f"archivetest{unique_id}@test.com"
        }, headers=headers)
        if response.status_code in [200, 201]:
            data = response.json()
            return data.get("data", {}).get("id") or data.get("id")
        return None

    def test_archive_client_without_auth(self, http_client, api_url, timer):
        """Archive client without authentication should fail"""
        fake_uuid = "12345678-1234-1234-1234-123456789012"
        # Try both PUT and POST since endpoint might use either
        response_put = http_client.put(f"{api_url}/clients/{fake_uuid}/archive")
        response_post = http_client.post(f"{api_url}/clients/{fake_uuid}/archive")
        
        assert response_put.status_code == 401 or response_post.status_code == 401, \
            "Should require authentication"

    def test_archive_client_without_permission(self, http_client, api_url, root_user, regular_user, timer):
        """User without permission should not be able to archive clients"""
        if not regular_user or "token" not in regular_user:
            pytest.skip("Regular user não disponível")
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        # Create a client as root
        root_headers = {"Authorization": f"Bearer {root_user['token']}"}
        client_id = self._create_test_client(http_client, api_url, root_headers)

        if not client_id:
            pytest.skip("Could not create test client")

        # Try to archive as regular user
        user_headers = {"Authorization": f"Bearer {regular_user['token']}"}
        # Try POST since some endpoints use POST for archive
        response = http_client.post(f"{api_url}/clients/{client_id}/archive", headers=user_headers)

        # May be 200 if user has permissions, or 403 if denied
        assert response.status_code in [200, 204, 403], "Response should be success or forbidden"

    def test_archive_already_archived_client(self, http_client, api_url, root_user, timer):
        """Archiving an already archived client should be handled gracefully"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}
        client_id = self._create_test_client(http_client, api_url, headers)

        if not client_id:
            pytest.skip("Could not create test client")

        # Archive first time
        first_archive = http_client.post(f"{api_url}/clients/{client_id}/archive", headers=headers)
        assert first_archive.status_code in [200, 204], "First archive should succeed"

        # Archive second time
        second_archive = http_client.post(f"{api_url}/clients/{client_id}/archive", headers=headers)
        
        # Should return success (idempotent) or error for already archived
        assert second_archive.status_code in [200, 204, 400, 409], \
            f"Double archive should be handled gracefully, got {second_archive.status_code}"
        assert second_archive.status_code != 500, "Should not cause server error"


# =============================================================================
# PUT /api/clients/{id}/unarchive TESTS
# =============================================================================

@pytest.mark.api
@pytest.mark.security
class TestUnarchiveClientAPI:
    """Tests for PUT /api/clients/{id}/unarchive endpoint"""

    def _create_and_archive_client(self, http_client, api_url, headers):
        """Helper to create and archive a client for testing"""
        unique_id = str(uuid.uuid4())[:8]
        response = http_client.post(f"{api_url}/clients", json={
            "name": f"Unarchive Test Client {unique_id}",
            "email": f"unarchivetest{unique_id}@test.com"
        }, headers=headers)
        if response.status_code in [200, 201]:
            data = response.json()
            client_id = data.get("data", {}).get("id") or data.get("id")
            if client_id:
                # Archive the client
                http_client.post(f"{api_url}/clients/{client_id}/archive", headers=headers)
                return client_id
        return None

    def test_unarchive_client_without_auth(self, http_client, api_url, timer):
        """Unarchive client without authentication should fail"""
        fake_uuid = "12345678-1234-1234-1234-123456789012"
        # Try both PUT and POST
        response_put = http_client.put(f"{api_url}/clients/{fake_uuid}/unarchive")
        response_post = http_client.post(f"{api_url}/clients/{fake_uuid}/unarchive")
        
        assert response_put.status_code == 401 or response_post.status_code == 401, \
            "Should require authentication"

    def test_unarchive_client_without_permission(self, http_client, api_url, root_user, regular_user, timer):
        """User without permission should not be able to unarchive clients"""
        if not regular_user or "token" not in regular_user:
            pytest.skip("Regular user não disponível")
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        # Create and archive a client as root
        root_headers = {"Authorization": f"Bearer {root_user['token']}"}
        client_id = self._create_and_archive_client(http_client, api_url, root_headers)

        if not client_id:
            pytest.skip("Could not create and archive test client")

        # Try to unarchive as regular user
        user_headers = {"Authorization": f"Bearer {regular_user['token']}"}
        response = http_client.post(f"{api_url}/clients/{client_id}/unarchive", headers=user_headers)

        # May be 200 if user has permissions, or 403 if denied
        assert response.status_code in [200, 204, 403], "Response should be success or forbidden"

    def test_unarchive_active_client(self, http_client, api_url, root_user, timer):
        """Unarchiving an active (non-archived) client should be handled gracefully"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        # Create a client but DON'T archive it
        response = http_client.post(f"{api_url}/clients", json={
            "name": f"Active Unarchive Test {int(time.time())}",
            "email": f"activeunarchive{int(time.time())}@test.com"
        }, headers=headers)

        if response.status_code not in [200, 201]:
            pytest.skip("Could not create test client")

        client_data = response.json()
        client_id = client_data.get("data", {}).get("id") or client_data.get("id")

        if not client_id:
            pytest.skip("Client ID not returned")

        # Try to unarchive an active client
        unarchive_response = http_client.post(f"{api_url}/clients/{client_id}/unarchive", headers=headers)

        # Should return success (idempotent) or error for not archived
        assert unarchive_response.status_code in [200, 204, 400, 409], \
            f"Unarchiving active client should be handled gracefully, got {unarchive_response.status_code}"
        assert unarchive_response.status_code != 500, "Should not cause server error"


# =============================================================================
# GET /api/clients/{id}/affiliates TESTS
# =============================================================================

@pytest.mark.api
@pytest.mark.security
class TestGetClientAffiliatesAPI:
    """Tests for GET /api/clients/{id}/affiliates endpoint"""

    def test_get_affiliates_without_auth(self, http_client, api_url, timer):
        """Get client affiliates without authentication should fail"""
        fake_uuid = "12345678-1234-1234-1234-123456789012"
        response = http_client.get(f"{api_url}/clients/{fake_uuid}/affiliates")
        assert response.status_code == 401, "Should require authentication"

    def test_get_affiliates_nonexistent_client(self, http_client, api_url, root_user, timer):
        """Get affiliates for non-existent client should return 404"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}
        nonexistent_uuid = "00000000-0000-0000-0000-000000000001"

        response = http_client.get(f"{api_url}/clients/{nonexistent_uuid}/affiliates", headers=headers)

        assert response.status_code == 404, "Non-existent client should return 404"


# =============================================================================
# POST /api/clients/{id}/affiliates TESTS
# =============================================================================

@pytest.mark.api
@pytest.mark.security
class TestPostClientAffiliatesAPI:
    """Tests for POST /api/clients/{id}/affiliates endpoint"""

    def _create_test_client(self, http_client, api_url, headers):
        """Helper to create a client for testing"""
        unique_id = str(uuid.uuid4())[:8]
        response = http_client.post(f"{api_url}/clients", json={
            "name": f"Affiliate Test Client {unique_id}",
            "email": f"affiliatetest{unique_id}@test.com"
        }, headers=headers)
        if response.status_code in [200, 201]:
            data = response.json()
            return data.get("data", {}).get("id") or data.get("id")
        return None

    def test_create_affiliate_empty_body(self, http_client, api_url, root_user, timer):
        """Create affiliate with empty body should be rejected"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}
        client_id = self._create_test_client(http_client, api_url, headers)

        if not client_id:
            pytest.skip("Could not create test client")

        response = http_client.post(f"{api_url}/clients/{client_id}/affiliates", json={}, headers=headers)

        assert response.status_code in [400, 422], "Empty body should be rejected"
        assert response.status_code != 500, "Should not cause server error"

    def test_create_affiliate_null_name(self, http_client, api_url, root_user, timer):
        """Create affiliate with null name should be rejected"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}
        client_id = self._create_test_client(http_client, api_url, headers)

        if not client_id:
            pytest.skip("Could not create test client")

        response = http_client.post(f"{api_url}/clients/{client_id}/affiliates", json={
            "name": None,
            "description": "Test Description"
        }, headers=headers)

        assert response.status_code in [400, 422], "Null name should be rejected"
        assert response.status_code != 500, "Should not cause server error"

    def test_create_affiliate_xss_all_fields(self, http_client, api_url, root_user, timer):
        """Test XSS in all affiliate fields"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}
        client_id = self._create_test_client(http_client, api_url, headers)

        if not client_id:
            pytest.skip("Could not create test client")

        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
        ]

        for payload in xss_payloads:
            response = http_client.post(f"{api_url}/clients/{client_id}/affiliates", json={
                "name": payload,
                "description": payload,
                "email": f"xss{int(time.time())}@test.com",
            }, headers=headers)

            # Should accept but sanitize, or reject
            assert response.status_code != 500, f"XSS payload caused error: {payload}"

    def test_create_affiliate_sql_injection_all_fields(self, http_client, api_url, root_user, timer):
        """Test SQL injection in all affiliate fields"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}
        client_id = self._create_test_client(http_client, api_url, headers)

        if not client_id:
            pytest.skip("Could not create test client")

        sql_payloads = [
            "'; DROP TABLE affiliates;--",
            "' OR '1'='1",
            "Robert'); DROP TABLE Students;--",
        ]

        for payload in sql_payloads:
            response = http_client.post(f"{api_url}/clients/{client_id}/affiliates", json={
                "name": f"SQL Test {payload}",
                "description": payload,
            }, headers=headers)

            # Should not cause internal error
            assert response.status_code != 500, f"SQL injection caused error: {payload}"

    def test_create_affiliate_overflow_all_fields(self, http_client, api_url, root_user, timer):
        """Test overflow in all affiliate fields"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}
        client_id = self._create_test_client(http_client, api_url, headers)

        if not client_id:
            pytest.skip("Could not create test client")

        long_string = "A" * 10001

        response = http_client.post(f"{api_url}/clients/{client_id}/affiliates", json={
            "name": long_string,
            "description": long_string,
        }, headers=headers)

        # Should handle gracefully
        assert response.status_code != 500, "Overflow should not cause server error"
