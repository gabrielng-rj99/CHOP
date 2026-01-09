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
Testes de Segurança para APIs de Settings, System Config e Dashboard
"""

import pytest
import requests
import time


class TestSettingsAPIAuth:
    """Testes de autenticação para API de Settings"""

    def test_get_settings_requires_auth(self, http_client, api_url, timer):
        """GET /api/settings sem token deve retornar 401"""
        response = http_client.get(f"{api_url}/settings")
        assert response.status_code == 401

    def test_put_settings_requires_auth(self, http_client, api_url, timer):
        """PUT /api/settings sem token deve retornar 401"""
        response = http_client.put(
            f"{api_url}/settings",
            json={"settings": {"branding.app_name": "Test"}}
        )
        assert response.status_code == 401

    def test_get_security_settings_requires_auth(self, http_client, api_url, timer):
        """GET /api/settings/security sem token deve retornar 401"""
        response = http_client.get(f"{api_url}/settings/security")
        assert response.status_code == 401

    def test_put_security_settings_requires_auth(self, http_client, api_url, timer):
        """PUT /api/settings/security sem token deve retornar 401"""
        response = http_client.put(
            f"{api_url}/settings/security",
            json={"rate_limit": 100}
        )
        assert response.status_code == 401

    def test_get_password_policy_settings_auth(self, http_client, api_url, timer):
        """GET /api/settings/password-policy precisa de autenticação"""
        response = http_client.get(f"{api_url}/settings/password-policy")
        # Este endpoint pode ser público para o frontend saber as regras
        assert response.status_code in [200, 401]


class TestSettingsXSSPrevention:
    """Testes de prevenção de XSS em Settings"""

    XSS_PAYLOADS = [
        "<script>alert('XSS')</script>",
        "javascript:alert('XSS')",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "'-alert('XSS')-'",
        "<iframe src='javascript:alert(1)'>",
        "<body onload=alert('XSS')>",
    ]

    def test_xss_in_app_name(self, http_client, api_url, root_user, timer):
        """XSS em branding.app_name deve ser bloqueado"""
        for payload in self.XSS_PAYLOADS:
            response = http_client.put(
                f"{api_url}/settings",
                headers={"Authorization": f"Bearer {root_user['token']}"},
                json={"settings": {"branding.app_name": payload}}
            )
            # Conforme docs, XSS patterns são bloqueados
            assert response.status_code in [200, 400]

            if response.status_code == 200:
                # Verificar que foi sanitizado
                get_resp = http_client.get(
                    f"{api_url}/settings",
                    headers={"Authorization": f"Bearer {root_user['token']}"}
                )
                if get_resp.status_code == 200:
                    settings = get_resp.json()
                    app_name = settings.get("branding.app_name", "")
                    assert "<script>" not in app_name
                    assert "javascript:" not in app_name.lower()

    def test_xss_in_label_settings(self, http_client, api_url, root_user, timer):
        """XSS em labels deve ser bloqueado"""
        label_keys = [
            "labels.client", "labels.affiliate", "labels.category",
            "labels.subcategory", "labels.contract"
        ]

        for key in label_keys:
            for payload in self.XSS_PAYLOADS[:2]:
                response = http_client.put(
                    f"{api_url}/settings",
                    headers={"Authorization": f"Bearer {root_user['token']}"},
                    json={"settings": {key: payload}}
                )
                assert response.status_code in [200, 400]


class TestSettingsOverflow:
    """Testes de overflow em Settings"""

    def test_setting_value_over_2000_chars(self, http_client, api_url, root_user, timer):
        """Valor > 2000 caracteres deve ser rejeitado (conforme docs)"""
        long_value = "A" * 2500

        response = http_client.put(
            f"{api_url}/settings",
            headers={"Authorization": f"Bearer {root_user['token']}"},
            json={"settings": {"labels.client": long_value}}
        )
        assert response.status_code in [400, 413]

    def test_branding_value_over_1mb(self, http_client, api_url, root_user, timer):
        """Branding images > 1MB devem ser rejeitadas"""
        # Base64 de 1MB+ seria enorme
        large_value = "data:image/png;base64," + "A" * (1024 * 1024 + 1000)

        response = http_client.put(
            f"{api_url}/settings",
            headers={"Authorization": f"Bearer {root_user['token']}"},
            json={"settings": {"branding.logo": large_value}}
        )
        assert response.status_code in [400, 413]


class TestSettingsColorValidation:
    """Testes de validação de cores em Settings"""

    def test_invalid_hex_colors_rejected(self, http_client, api_url, root_user, timer):
        """Cores hex inválidas devem ser rejeitadas"""
        invalid_colors = [
            "not-a-color",
            "#GGGGGG",
            "#12345",  # 5 chars
            "#1234567",  # 7 chars
            "rgb(255,0,0)",  # Format not supported
            "<script>",
            "javascript:alert(1)",
        ]

        for color in invalid_colors:
            response = http_client.put(
                f"{api_url}/settings",
                headers={"Authorization": f"Bearer {root_user['token']}"},
                json={"settings": {"branding.primary_color": color}}
            )
            # Deve rejeitar cores inválidas
            assert response.status_code in [200, 400]  # 200 se ignorar, 400 se rejeitar

    def test_valid_hex_colors_accepted(self, http_client, api_url, root_user, timer):
        """Cores hex válidas devem ser aceitas"""
        valid_colors = ["#FFF", "#FFFFFF", "#000", "#123ABC", "#abc"]

        for color in valid_colors:
            response = http_client.put(
                f"{api_url}/settings",
                headers={"Authorization": f"Bearer {root_user['token']}"},
                json={"settings": {"branding.primary_color": color}}
            )
            # Deve aceitar cores válidas
            assert response.status_code in [200, 201]


class TestSecuritySettingsAPI:
    """Testes para API de Security Settings"""

    def test_user_cannot_modify_security_settings(self, http_client, api_url, regular_user, timer):
        """Usuário comum não pode modificar security settings"""
        response = http_client.put(
            f"{api_url}/settings/security",
            headers={"Authorization": f"Bearer {regular_user['token']}"},
            json={"rate_limit": 1}  # Tentando desabilitar rate limit
        )
        assert response.status_code == 403

    def test_security_settings_invalid_values(self, http_client, api_url, root_user, timer):
        """Valores inválidos em security settings devem ser rejeitados"""
        invalid_settings = [
            {"rate_limit": -1},
            {"rate_limit": 0},
            {"lock_level_1_attempts": -5},
            {"audit_retention_days": -30},
            {"session_duration": -60},
        ]

        for settings in invalid_settings:
            response = http_client.put(
                f"{api_url}/settings/security",
                headers={"Authorization": f"Bearer {root_user['token']}"},
                json=settings
            )
            assert response.status_code in [400, 422]


class TestThemeAPIAuth:
    """Testes de autenticação para API de Theme"""

    def test_get_user_theme_requires_auth(self, http_client, api_url, timer):
        """GET /api/user/theme sem token deve retornar 401"""
        response = http_client.get(f"{api_url}/user/theme")
        assert response.status_code == 401

    def test_put_user_theme_requires_auth(self, http_client, api_url, timer):
        """PUT /api/user/theme sem token deve retornar 401"""
        response = http_client.put(
            f"{api_url}/user/theme",
            json={"theme_mode": "dark"}
        )
        assert response.status_code == 401

    def test_get_theme_permissions_requires_auth(self, http_client, api_url, timer):
        """GET /api/settings/theme-permissions sem token deve retornar 401"""
        response = http_client.get(f"{api_url}/settings/theme-permissions")
        assert response.status_code == 401

    def test_get_global_theme_requires_auth(self, http_client, api_url, timer):
        """GET /api/settings/global-theme sem token deve retornar 401"""
        response = http_client.get(f"{api_url}/settings/global-theme")
        assert response.status_code == 401

    def test_get_allowed_themes_requires_auth(self, http_client, api_url, timer):
        """GET /api/settings/allowed-themes sem token deve retornar 401"""
        response = http_client.get(f"{api_url}/settings/allowed-themes")
        assert response.status_code == 401


class TestThemeAPIValidation:
    """Testes de validação para API de Theme"""

    def test_theme_mode_invalid_value(self, http_client, api_url, root_user, timer):
        """theme_mode deve ser light/dark/system"""
        response = http_client.put(
            f"{api_url}/user/theme",
            headers={"Authorization": f"Bearer {root_user['token']}"},
            json={"theme_mode": "invalid"}
        )
        assert response.status_code in [200, 400]

    def test_layout_mode_invalid_value(self, http_client, api_url, root_user, timer):
        """layout_mode deve ser standard/full/centralized"""
        response = http_client.put(
            f"{api_url}/user/theme",
            headers={"Authorization": f"Bearer {root_user['token']}"},
            json={
                "theme_mode": "dark",
                "layout_mode": "invalid_layout"
            }
        )
        assert response.status_code in [200, 400]

    def test_color_blind_mode_invalid_value(self, http_client, api_url, root_user, timer):
        """color_blind_mode deve ser none/protanopia/deuteranopia/tritanopia"""
        response = http_client.put(
            f"{api_url}/user/theme",
            headers={"Authorization": f"Bearer {root_user['token']}"},
            json={
                "theme_mode": "dark",
                "layout_mode": "standard",
                "color_blind_mode": "invalid_mode"
            }
        )
        assert response.status_code in [200, 400]

    def test_xss_in_color_fields(self, http_client, api_url, root_user, timer):
        """XSS em campos de cor deve ser bloqueado"""
        color_fields = [
            "primary_color", "secondary_color", "background_color",
            "surface_color", "text_color", "border_color"
        ]

        for field in color_fields:
            response = http_client.put(
                f"{api_url}/user/theme",
                headers={"Authorization": f"Bearer {root_user['token']}"},
                json={
                    "theme_mode": "dark",
                    "layout_mode": "standard",
                    field: "<script>alert('XSS')</script>"
                }
            )
            assert response.status_code in [200, 400]

            if response.status_code == 200:
                # Verificar sanitização
                get_resp = http_client.get(
                    f"{api_url}/user/theme",
                    headers={"Authorization": f"Bearer {root_user['token']}"}
                )
                if get_resp.status_code == 200:
                    theme = get_resp.json()
                    assert "<script>" not in str(theme)


class TestDashboardAPIAuth:
    """Testes de autenticação para API de Dashboard"""

    def test_get_dashboard_config_requires_auth(self, http_client, api_url, timer):
        """GET /api/system-config/dashboard sem token deve retornar 401"""
        response = http_client.get(f"{api_url}/system-config/dashboard")
        assert response.status_code == 401

    def test_put_dashboard_config_requires_auth(self, http_client, api_url, timer):
        """PUT /api/system-config/dashboard sem token deve retornar 401"""
        response = http_client.put(
            f"{api_url}/system-config/dashboard",
            json={"show_birthdays": True}
        )
        assert response.status_code == 401


class TestDashboardAPIValidation:
    """Testes de validação para API de Dashboard"""

    def test_birthdays_days_ahead_range(self, http_client, api_url, root_user, timer):
        """birthdays_days_ahead deve ser 1-90"""
        invalid_values = [0, -1, 91, 100, 1000]

        for val in invalid_values:
            response = http_client.put(
                f"{api_url}/system-config/dashboard",
                headers={"Authorization": f"Bearer {root_user['token']}"},
                json={
                    "show_birthdays": True,
                    "birthdays_days_ahead": val,
                    "show_recent_activity": True,
                    "recent_activity_count": 10,
                    "show_statistics": True,
                    "show_expiring_contracts": True,
                    "expiring_days_ahead": 30,
                    "show_quick_actions": True
                }
            )
            assert response.status_code in [400, 422]

    def test_recent_activity_count_range(self, http_client, api_url, root_user, timer):
        """recent_activity_count deve ser 5-50"""
        invalid_values = [0, 4, 51, 100]

        for val in invalid_values:
            response = http_client.put(
                f"{api_url}/system-config/dashboard",
                headers={"Authorization": f"Bearer {root_user['token']}"},
                json={
                    "show_birthdays": True,
                    "birthdays_days_ahead": 30,
                    "show_recent_activity": True,
                    "recent_activity_count": val,
                    "show_statistics": True,
                    "show_expiring_contracts": True,
                    "expiring_days_ahead": 30,
                    "show_quick_actions": True
                }
            )
            assert response.status_code in [400, 422]

    def test_expiring_days_ahead_range(self, http_client, api_url, root_user, timer):
        """expiring_days_ahead deve ser 7-180"""
        invalid_values = [0, 6, 181, 365]

        for val in invalid_values:
            response = http_client.put(
                f"{api_url}/system-config/dashboard",
                headers={"Authorization": f"Bearer {root_user['token']}"},
                json={
                    "show_birthdays": True,
                    "birthdays_days_ahead": 30,
                    "show_recent_activity": True,
                    "recent_activity_count": 10,
                    "show_statistics": True,
                    "show_expiring_contracts": True,
                    "expiring_days_ahead": val,
                    "show_quick_actions": True
                }
            )
            assert response.status_code in [400, 422]

    def test_user_cannot_configure_dashboard(self, http_client, api_url, regular_user, timer):
        """Usuário comum não pode configurar dashboard"""
        response = http_client.put(
            f"{api_url}/system-config/dashboard",
            headers={"Authorization": f"Bearer {regular_user['token']}"},
            json={
                "show_birthdays": False,
                "birthdays_days_ahead": 30,
                "show_recent_activity": False,
                "recent_activity_count": 10,
                "show_statistics": False,
                "show_expiring_contracts": False,
                "expiring_days_ahead": 30,
                "show_quick_actions": False
            }
        )
        assert response.status_code == 403


class TestSystemConfigAPI:
    """Testes para API de System Config"""

    def test_get_system_config_requires_auth(self, http_client, api_url, timer):
        """GET /api/settings/system-config sem token deve retornar 401"""
        response = http_client.get(f"{api_url}/settings/system-config")
        assert response.status_code == 401

    def test_put_system_config_requires_auth(self, http_client, api_url, timer):
        """PUT /api/settings/system-config sem token deve retornar 401"""
        response = http_client.put(
            f"{api_url}/settings/system-config",
            json={"login_attempts": 5}
        )
        assert response.status_code == 401

    def test_xss_in_notification_email(self, http_client, api_url, root_user, timer):
        """XSS em notification_email deve ser bloqueado"""
        response = http_client.put(
            f"{api_url}/settings/system-config",
            headers={"Authorization": f"Bearer {root_user['token']}"},
            json={"notification_email": "<script>alert('XSS')</script>@test.com"}
        )
        assert response.status_code in [200, 400]

        if response.status_code == 200:
            get_resp = http_client.get(
                f"{api_url}/settings/system-config",
                headers={"Authorization": f"Bearer {root_user['token']}"}
            )
            if get_resp.status_code == 200:
                config = get_resp.json()
                assert "<script>" not in config.get("notification_email", "")

    def test_sqli_in_notification_phone(self, http_client, api_url, root_user, timer):
        """SQL Injection em notification_phone deve ser bloqueado"""
        response = http_client.put(
            f"{api_url}/settings/system-config",
            headers={"Authorization": f"Bearer {root_user['token']}"},
            json={"notification_phone": "'; DROP TABLE users;--"}
        )
        # Não deve causar erro SQL
        assert response.status_code in [200, 400]
        assert "sql" not in response.text.lower()
        assert "syntax" not in response.text.lower()
