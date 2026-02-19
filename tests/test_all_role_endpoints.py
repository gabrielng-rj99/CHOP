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
Comprehensive role endpoint tests using pytest fixtures and current API responses.

These tests validate:
- GET /api/roles
- GET /api/roles/{id}
- GET /api/roles/{id}/permissions
- PUT /api/roles/{id}/permissions
- Hardcoded permission IDs acceptance (schema-defined UUIDs)

Assumptions:
- API URL provided by fixtures in tests/conftest.py
- Root token provided by fixtures in tests/conftest.py
"""

import pytest
import requests

ROLE_ROOT = "a0000000-0000-0000-0000-000000000001"
ROLE_ADMIN = "a0000000-0000-0000-0000-000000000002"
ROLE_USER = "a0000000-0000-0000-0000-000000000003"

ROLE_IDS = {
    "root": ROLE_ROOT,
    "admin": ROLE_ADMIN,
    "user": ROLE_USER,
}

HARDCODED_PERMISSION_IDS = [
    "b0000000-0000-0000-0000-000000000001",  # clients:create
    "b0000000-0000-0000-0000-000000000002",  # clients:read
    "b0000000-0000-0000-0000-000000000003",  # clients:update
]


@pytest.fixture
def auth_headers(root_token):
    if not root_token:
        pytest.skip("Root token not available; ensure API is running and root login succeeds.")
    return {"Authorization": f"Bearer {root_token}"}


def _extract_roles(payload):
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        if "roles" in payload:
            return payload["roles"]
        if "data" in payload and isinstance(payload["data"], list):
            return payload["data"]
    return []


def _extract_permissions(payload):
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        if "permissions" in payload:
            return payload["permissions"]
        if "data" in payload and isinstance(payload["data"], list):
            return payload["data"]
    return []


@pytest.mark.api
@pytest.mark.authorization
def test_get_all_roles(api_url, auth_headers):
    response = requests.get(f"{api_url}/roles", headers=auth_headers, timeout=10)
    assert response.status_code == 200, response.text

    roles = _extract_roles(response.json())
    assert len(roles) >= 3, f"Expected at least 3 roles, got {len(roles)}"


@pytest.mark.api
@pytest.mark.authorization
@pytest.mark.parametrize("role_name,role_id", ROLE_IDS.items())
def test_get_role_by_id(api_url, auth_headers, role_name, role_id):
    response = requests.get(f"{api_url}/roles/{role_id}", headers=auth_headers, timeout=10)
    assert response.status_code == 200, response.text

    payload = response.json()
    role = payload
    if isinstance(payload, dict):
        role = payload.get("role") or payload.get("data") or payload
    assert role, f"Missing role payload for {role_name}"
    role_id_value = role.get("id") if isinstance(role, dict) else None
    assert role_id_value == role_id
    role_name_value = role.get("name") if isinstance(role, dict) else None
    assert role_name_value in {role_name, role_name.lower()}


@pytest.mark.api
@pytest.mark.authorization
@pytest.mark.parametrize("role_name,role_id", ROLE_IDS.items())
def test_get_role_permissions(api_url, auth_headers, role_name, role_id):
    response = requests.get(
        f"{api_url}/roles/{role_id}/permissions",
        headers=auth_headers,
        timeout=10,
    )
    assert response.status_code == 200, response.text

    permissions = _extract_permissions(response.json())
    assert isinstance(permissions, list), f"Expected permissions list for {role_name}"
    assert len(permissions) > 0, f"No permissions returned for {role_name}"


@pytest.mark.api
@pytest.mark.authorization
def test_set_role_permissions_accepts_valid_ids(api_url, auth_headers):
    response = requests.put(
        f"{api_url}/roles/{ROLE_USER}/permissions",
        headers=auth_headers,
        json={"permission_ids": HARDCODED_PERMISSION_IDS},
        timeout=10,
    )
    assert response.status_code == 200, response.text


@pytest.mark.api
@pytest.mark.authorization
def test_set_role_permissions_rejects_invalid_id(api_url, auth_headers):
    response = requests.put(
        f"{api_url}/roles/{ROLE_USER}/permissions",
        headers=auth_headers,
        json={"permission_ids": ["not-a-uuid"]},
        timeout=10,
    )
    assert response.status_code in {400, 422}, response.text
