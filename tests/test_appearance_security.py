"""
Entity Hub Open Project
Copyright (C) 2025 Entity Hub Contributors

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

"""
Security tests for Appearance/Theme API endpoints.

These tests verify that:
1. Only root users can access/modify global theme settings
2. Only root users can access/modify allowed themes
3. Only root users can access/modify system configuration
4. Theme permissions are properly enforced
5. Input validation is working correctly
6. SQL injection and XSS attacks are blocked
"""

import pytest
import requests
import json


class TestAppearanceAPISecurity:
    """Security tests for appearance-related API endpoints."""

    @pytest.fixture(autouse=True)
    def setup(self, base_url, root_token, admin_token, user_token):
        """Setup test fixtures."""
        self.base_url = base_url
        self.root_token = root_token
        self.admin_token = admin_token
        self.user_token = user_token

    def get_headers(self, token):
        """Get authorization headers."""
        return {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }

    # ==========================================
    # Global Theme Endpoint Tests
    # ==========================================

    def test_global_theme_get_as_root(self):
        """Root user should be able to get global theme."""
        response = requests.get(
            f"{self.base_url}/api/settings/global-theme",
            headers=self.get_headers(self.root_token)
        )
        assert response.status_code in [200, 404], f"Expected 200 or 404, got {response.status_code}"

    def test_global_theme_get_as_admin_denied(self):
        """Admin user should NOT be able to get global theme."""
        response = requests.get(
            f"{self.base_url}/api/settings/global-theme",
            headers=self.get_headers(self.admin_token)
        )
        assert response.status_code == 403, f"Expected 403 Forbidden, got {response.status_code}"

    def test_global_theme_get_as_user_denied(self):
        """Regular user should NOT be able to get global theme."""
        response = requests.get(
            f"{self.base_url}/api/settings/global-theme",
            headers=self.get_headers(self.user_token)
        )
        assert response.status_code == 403, f"Expected 403 Forbidden, got {response.status_code}"

    def test_global_theme_get_without_token_denied(self):
        """Unauthenticated request should be denied."""
        response = requests.get(f"{self.base_url}/api/settings/global-theme")
        assert response.status_code == 401, f"Expected 401 Unauthorized, got {response.status_code}"

    def test_global_theme_update_as_root(self):
        """Root user should be able to update global theme."""
        payload = {
            "theme_preset": "default",
            "primary_color": "#3498db",
            "secondary_color": "#2c3e50"
        }
        response = requests.put(
            f"{self.base_url}/api/settings/global-theme",
            headers=self.get_headers(self.root_token),
            json=payload
        )
        assert response.status_code == 200, f"Expected 200, got {response.status_code}"

    def test_global_theme_update_as_admin_denied(self):
        """Admin user should NOT be able to update global theme."""
        payload = {
            "theme_preset": "default",
            "primary_color": "#3498db"
        }
        response = requests.put(
            f"{self.base_url}/api/settings/global-theme",
            headers=self.get_headers(self.admin_token),
            json=payload
        )
        assert response.status_code == 403, f"Expected 403 Forbidden, got {response.status_code}"

    def test_global_theme_update_as_user_denied(self):
        """Regular user should NOT be able to update global theme."""
        payload = {
            "theme_preset": "default"
        }
        response = requests.put(
            f"{self.base_url}/api/settings/global-theme",
            headers=self.get_headers(self.user_token),
            json=payload
        )
        assert response.status_code == 403, f"Expected 403 Forbidden, got {response.status_code}"

    # ==========================================
    # Allowed Themes Endpoint Tests
    # ==========================================

    def test_allowed_themes_get_as_any_user(self):
        """Any authenticated user should be able to get allowed themes."""
        for token in [self.root_token, self.admin_token, self.user_token]:
            response = requests.get(
                f"{self.base_url}/api/settings/allowed-themes",
                headers=self.get_headers(token)
            )
            assert response.status_code == 200, f"Expected 200, got {response.status_code}"
            data = response.json()
            assert "allowed_themes" in data

    def test_allowed_themes_get_without_token_denied(self):
        """Unauthenticated request should be denied."""
        response = requests.get(f"{self.base_url}/api/settings/allowed-themes")
        assert response.status_code == 401, f"Expected 401 Unauthorized, got {response.status_code}"

    def test_allowed_themes_update_as_root(self):
        """Root user should be able to update allowed themes."""
        payload = {
            "allowed_themes": ["default", "ocean", "forest"]
        }
        response = requests.put(
            f"{self.base_url}/api/settings/allowed-themes",
            headers=self.get_headers(self.root_token),
            json=payload
        )
        assert response.status_code == 200, f"Expected 200, got {response.status_code}"

        # Reset to all themes
        payload = {
            "allowed_themes": ["default", "ocean", "forest", "sunset", "purple", "monochrome", "custom"]
        }
        requests.put(
            f"{self.base_url}/api/settings/allowed-themes",
            headers=self.get_headers(self.root_token),
            json=payload
        )

    def test_allowed_themes_update_as_admin_denied(self):
        """Admin user should NOT be able to update allowed themes."""
        payload = {
            "allowed_themes": ["default"]
        }
        response = requests.put(
            f"{self.base_url}/api/settings/allowed-themes",
            headers=self.get_headers(self.admin_token),
            json=payload
        )
        assert response.status_code == 403, f"Expected 403 Forbidden, got {response.status_code}"

    def test_allowed_themes_update_as_user_denied(self):
        """Regular user should NOT be able to update allowed themes."""
        payload = {
            "allowed_themes": ["default"]
        }
        response = requests.put(
            f"{self.base_url}/api/settings/allowed-themes",
            headers=self.get_headers(self.user_token),
            json=payload
        )
        assert response.status_code == 403, f"Expected 403 Forbidden, got {response.status_code}"

    def test_allowed_themes_empty_list_rejected(self):
        """Empty allowed themes list should be rejected."""
        payload = {
            "allowed_themes": []
        }
        response = requests.put(
            f"{self.base_url}/api/settings/allowed-themes",
            headers=self.get_headers(self.root_token),
            json=payload
        )
        assert response.status_code == 400, f"Expected 400 Bad Request, got {response.status_code}"

    def test_allowed_themes_invalid_theme_rejected(self):
        """Invalid theme names should be rejected."""
        payload = {
            "allowed_themes": ["default", "invalid_theme_name"]
        }
        response = requests.put(
            f"{self.base_url}/api/settings/allowed-themes",
            headers=self.get_headers(self.root_token),
            json=payload
        )
        assert response.status_code == 400, f"Expected 400 Bad Request, got {response.status_code}"

    # ==========================================
    # System Config Endpoint Tests
    # ==========================================

    def test_system_config_get_as_root(self):
        """Root user should be able to get system config."""
        response = requests.get(
            f"{self.base_url}/api/settings/system-config",
            headers=self.get_headers(self.root_token)
        )
        assert response.status_code == 200, f"Expected 200, got {response.status_code}"
        data = response.json()
        assert "login_block_time" in data
        assert "login_attempts" in data

    def test_system_config_get_as_admin_denied(self):
        """Admin user should NOT be able to get system config."""
        response = requests.get(
            f"{self.base_url}/api/settings/system-config",
            headers=self.get_headers(self.admin_token)
        )
        assert response.status_code == 403, f"Expected 403 Forbidden, got {response.status_code}"

    def test_system_config_get_as_user_denied(self):
        """Regular user should NOT be able to get system config."""
        response = requests.get(
            f"{self.base_url}/api/settings/system-config",
            headers=self.get_headers(self.user_token)
        )
        assert response.status_code == 403, f"Expected 403 Forbidden, got {response.status_code}"

    def test_system_config_update_as_root(self):
        """Root user should be able to update system config."""
        payload = {
            "login_block_time": 300,
            "login_attempts": 5,
            "notification_email": "",
            "notification_phone": ""
        }
        response = requests.put(
            f"{self.base_url}/api/settings/system-config",
            headers=self.get_headers(self.root_token),
            json=payload
        )
        assert response.status_code == 200, f"Expected 200, got {response.status_code}"

    def test_system_config_update_as_admin_denied(self):
        """Admin user should NOT be able to update system config."""
        payload = {
            "login_block_time": 300,
            "login_attempts": 5
        }
        response = requests.put(
            f"{self.base_url}/api/settings/system-config",
            headers=self.get_headers(self.admin_token),
            json=payload
        )
        assert response.status_code == 403, f"Expected 403 Forbidden, got {response.status_code}"

    def test_system_config_update_as_user_denied(self):
        """Regular user should NOT be able to update system config."""
        payload = {
            "login_block_time": 300,
            "login_attempts": 5
        }
        response = requests.put(
            f"{self.base_url}/api/settings/system-config",
            headers=self.get_headers(self.user_token),
            json=payload
        )
        assert response.status_code == 403, f"Expected 403 Forbidden, got {response.status_code}"

    def test_system_config_invalid_block_time_rejected(self):
        """Invalid login block time should be rejected."""
        # Too low
        payload = {
            "login_block_time": 30,  # Min is 60
            "login_attempts": 5
        }
        response = requests.put(
            f"{self.base_url}/api/settings/system-config",
            headers=self.get_headers(self.root_token),
            json=payload
        )
        assert response.status_code == 400, f"Expected 400 Bad Request, got {response.status_code}"

        # Too high
        payload = {
            "login_block_time": 5000,  # Max is 3600
            "login_attempts": 5
        }
        response = requests.put(
            f"{self.base_url}/api/settings/system-config",
            headers=self.get_headers(self.root_token),
            json=payload
        )
        assert response.status_code == 400, f"Expected 400 Bad Request, got {response.status_code}"

    def test_system_config_invalid_attempts_rejected(self):
        """Invalid login attempts should be rejected."""
        # Too low
        payload = {
            "login_block_time": 300,
            "login_attempts": 1  # Min is 3
        }
        response = requests.put(
            f"{self.base_url}/api/settings/system-config",
            headers=self.get_headers(self.root_token),
            json=payload
        )
        assert response.status_code == 400, f"Expected 400 Bad Request, got {response.status_code}"

        # Too high
        payload = {
            "login_block_time": 300,
            "login_attempts": 20  # Max is 10
        }
        response = requests.put(
            f"{self.base_url}/api/settings/system-config",
            headers=self.get_headers(self.root_token),
            json=payload
        )
        assert response.status_code == 400, f"Expected 400 Bad Request, got {response.status_code}"

    # ==========================================
    # Theme Permissions Endpoint Tests
    # ==========================================

    def test_theme_permissions_get_as_root(self):
        """Root user should be able to get theme permissions."""
        response = requests.get(
            f"{self.base_url}/api/settings/theme-permissions",
            headers=self.get_headers(self.root_token)
        )
        assert response.status_code == 200, f"Expected 200, got {response.status_code}"

    def test_theme_permissions_get_as_admin_denied(self):
        """Admin user should NOT be able to get theme permissions."""
        response = requests.get(
            f"{self.base_url}/api/settings/theme-permissions",
            headers=self.get_headers(self.admin_token)
        )
        assert response.status_code == 403, f"Expected 403 Forbidden, got {response.status_code}"

    def test_theme_permissions_get_as_user_denied(self):
        """Regular user should NOT be able to get theme permissions."""
        response = requests.get(
            f"{self.base_url}/api/settings/theme-permissions",
            headers=self.get_headers(self.user_token)
        )
        assert response.status_code == 403, f"Expected 403 Forbidden, got {response.status_code}"

    def test_theme_permissions_update_as_root(self):
        """Root user should be able to update theme permissions."""
        payload = {
            "users_can_edit_theme": True,
            "admins_can_edit_theme": True
        }
        response = requests.put(
            f"{self.base_url}/api/settings/theme-permissions",
            headers=self.get_headers(self.root_token),
            json=payload
        )
        assert response.status_code == 200, f"Expected 200, got {response.status_code}"

    def test_theme_permissions_update_as_admin_denied(self):
        """Admin user should NOT be able to update theme permissions."""
        payload = {
            "users_can_edit_theme": True,
            "admins_can_edit_theme": True
        }
        response = requests.put(
            f"{self.base_url}/api/settings/theme-permissions",
            headers=self.get_headers(self.admin_token),
            json=payload
        )
        assert response.status_code == 403, f"Expected 403 Forbidden, got {response.status_code}"

    # ==========================================
    # Input Validation & Injection Tests
    # ==========================================

    def test_global_theme_sql_injection_in_preset(self):
        """SQL injection attempt in theme preset should be blocked."""
        payload = {
            "theme_preset": "default'; DROP TABLE users; --",
            "primary_color": "#3498db"
        }
        response = requests.put(
            f"{self.base_url}/api/settings/global-theme",
            headers=self.get_headers(self.root_token),
            json=payload
        )
        # Should be rejected due to validation
        assert response.status_code == 400, f"Expected 400 Bad Request, got {response.status_code}"

    def test_global_theme_xss_in_preset(self):
        """XSS attempt in theme preset should be blocked."""
        payload = {
            "theme_preset": "<script>alert('xss')</script>",
            "primary_color": "#3498db"
        }
        response = requests.put(
            f"{self.base_url}/api/settings/global-theme",
            headers=self.get_headers(self.root_token),
            json=payload
        )
        # Should be rejected due to validation
        assert response.status_code == 400, f"Expected 400 Bad Request, got {response.status_code}"

    def test_global_theme_invalid_color_format(self):
        """Invalid color format should be rejected."""
        invalid_colors = [
            "not-a-color",
            "#GGG",
            "rgb(255,0,0)",
            "#12345",
            "<script>",
            "'; DROP TABLE",
        ]

        for color in invalid_colors:
            payload = {
                "theme_preset": "default",
                "primary_color": color
            }
            response = requests.put(
                f"{self.base_url}/api/settings/global-theme",
                headers=self.get_headers(self.root_token),
                json=payload
            )
            assert response.status_code == 400, f"Expected 400 for color '{color}', got {response.status_code}"

    def test_global_theme_valid_color_formats(self):
        """Valid color formats should be accepted."""
        valid_colors = [
            "#fff",
            "#FFF",
            "#ffffff",
            "#FFFFFF",
            "#3498db",
            "#ABC",
        ]

        for color in valid_colors:
            payload = {
                "theme_preset": "default",
                "primary_color": color
            }
            response = requests.put(
                f"{self.base_url}/api/settings/global-theme",
                headers=self.get_headers(self.root_token),
                json=payload
            )
            assert response.status_code == 200, f"Expected 200 for color '{color}', got {response.status_code}"

    def test_user_theme_respects_permissions(self):
        """User theme endpoint should respect theme permissions."""
        # First, disable user theme editing
        payload = {
            "users_can_edit_theme": False,
            "admins_can_edit_theme": True
        }
        requests.put(
            f"{self.base_url}/api/settings/theme-permissions",
            headers=self.get_headers(self.root_token),
            json=payload
        )

        # Now try to update theme as regular user
        theme_payload = {
            "theme_preset": "ocean",
            "theme_mode": "dark",
            "color_blind_mode": "none"
        }
        response = requests.put(
            f"{self.base_url}/api/user/theme",
            headers=self.get_headers(self.user_token),
            json=theme_payload
        )
        assert response.status_code == 403, f"Expected 403 when user theme editing is disabled, got {response.status_code}"

        # Re-enable for other tests
        payload = {
            "users_can_edit_theme": True,
            "admins_can_edit_theme": True
        }
        requests.put(
            f"{self.base_url}/api/settings/theme-permissions",
            headers=self.get_headers(self.root_token),
            json=payload
        )

    # ==========================================
    # Request Size Limit Tests
    # ==========================================

    def test_global_theme_request_size_limit(self):
        """Large request body should be rejected."""
        # Create a very large payload
        payload = {
            "theme_preset": "default",
            "primary_color": "#3498db",
            "extra_data": "x" * 100000  # 100KB of extra data
        }
        response = requests.put(
            f"{self.base_url}/api/settings/global-theme",
            headers=self.get_headers(self.root_token),
            json=payload
        )
        # Should be rejected due to size or unknown field
        assert response.status_code in [400, 413], f"Expected 400 or 413, got {response.status_code}"


class TestUserThemeSecurity:
    """Security tests for user theme endpoint."""

    @pytest.fixture(autouse=True)
    def setup(self, base_url, root_token, admin_token, user_token):
        """Setup test fixtures."""
        self.base_url = base_url
        self.root_token = root_token
        self.admin_token = admin_token
        self.user_token = user_token

    def get_headers(self, token):
        """Get authorization headers."""
        return {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }

    def test_user_theme_get_authenticated(self):
        """Authenticated users should be able to get their theme."""
        for token in [self.root_token, self.admin_token, self.user_token]:
            response = requests.get(
                f"{self.base_url}/api/user/theme",
                headers=self.get_headers(token)
            )
            assert response.status_code == 200, f"Expected 200, got {response.status_code}"

    def test_user_theme_get_unauthenticated_denied(self):
        """Unauthenticated request should be denied."""
        response = requests.get(f"{self.base_url}/api/user/theme")
        assert response.status_code == 401, f"Expected 401, got {response.status_code}"

    def test_user_theme_invalid_mode_rejected(self):
        """Invalid theme mode should be rejected."""
        payload = {
            "theme_preset": "default",
            "theme_mode": "invalid_mode",
            "color_blind_mode": "none"
        }
        response = requests.put(
            f"{self.base_url}/api/user/theme",
            headers=self.get_headers(self.root_token),
            json=payload
        )
        assert response.status_code == 400, f"Expected 400, got {response.status_code}"

    def test_user_theme_invalid_colorblind_mode_rejected(self):
        """Invalid colorblind mode should be rejected."""
        payload = {
            "theme_preset": "default",
            "theme_mode": "light",
            "color_blind_mode": "invalid_mode"
        }
        response = requests.put(
            f"{self.base_url}/api/user/theme",
            headers=self.get_headers(self.root_token),
            json=payload
        )
        assert response.status_code == 400, f"Expected 400, got {response.status_code}"

    def test_user_theme_sql_injection_blocked(self):
        """SQL injection in theme preset should be blocked."""
        payload = {
            "theme_preset": "'; DELETE FROM users WHERE '1'='1",
            "theme_mode": "light",
            "color_blind_mode": "none"
        }
        response = requests.put(
            f"{self.base_url}/api/user/theme",
            headers=self.get_headers(self.root_token),
            json=payload
        )
        assert response.status_code == 400, f"Expected 400, got {response.status_code}"

    def test_user_theme_xss_blocked(self):
        """XSS in theme preset should be blocked."""
        payload = {
            "theme_preset": "<script>document.location='http://evil.com'</script>",
            "theme_mode": "light",
            "color_blind_mode": "none"
        }
        response = requests.put(
            f"{self.base_url}/api/user/theme",
            headers=self.get_headers(self.root_token),
            json=payload
        )
        assert response.status_code == 400, f"Expected 400, got {response.status_code}"

    def test_user_theme_unknown_fields_rejected(self):
        """Unknown fields in request should be rejected."""
        payload = {
            "theme_preset": "default",
            "theme_mode": "light",
            "color_blind_mode": "none",
            "unknown_field": "value"
        }
        response = requests.put(
            f"{self.base_url}/api/user/theme",
            headers=self.get_headers(self.root_token),
            json=payload
        )
        # Should reject due to DisallowUnknownFields
        assert response.status_code == 400, f"Expected 400, got {response.status_code}"
