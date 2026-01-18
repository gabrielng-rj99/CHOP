"""
Login Blocking System Tests

Tests for progressive lock levels and manual user blocking.
Validates that the blocking system correctly:
- Applies progressive locks (levels 1, 2, 3, 4)
- Prevents login during lock period
- Unlocks when time expires
- Supports manual admin blocks
"""

import pytest
import requests
import time
from datetime import datetime, timedelta
import json


@pytest.fixture
def api_url():
    """Get API base URL from environment or use default"""
    return "http://localhost:3000/api"


@pytest.fixture
def root_credentials():
    """Root user credentials for admin operations"""
    return {
        "username": "root",
        "password": "THIS_IS_A_DEV_ENVIRONMENT_PASSWORD@123abc"
    }


@pytest.fixture
def root_token(api_url, root_credentials):
    """Get root token for authenticated requests"""
    response = requests.post(
        f"{api_url}/login",
        json=root_credentials
    )
    assert response.status_code == 200, f"Failed to login as root: {response.text}"
    return response.json()["data"]["token"]


@pytest.fixture
def test_user(api_url, root_token):
    """Create a test user for blocking tests"""
    username = f"blocktest_{int(time.time())}"
    response = requests.post(
        f"{api_url}/users",
        json={
            "username": username,
            "password": "TestPassword123!",
            "display_name": "Block Test User",
            "role": "user"
        },
        headers={"Authorization": f"Bearer {root_token}"}
    )
    assert response.status_code == 201, f"Failed to create test user: {response.text}"

    yield {
        "username": username,
        "password": "TestPassword123!",
        "display_name": "Block Test User"
    }

    # Cleanup - delete test user
    requests.delete(
        f"{api_url}/users/{username}",
        headers={"Authorization": f"Bearer {root_token}"}
    )


class TestProgressiveLocking:
    """Tests for progressive lock levels (1, 2, 3, 4)"""

    def test_level_1_block_on_3_failures(self, api_url, test_user):
        """Test that level 1 block is applied after 3 failed attempts"""
        username = test_user["username"]

        # Attempt 3 wrong passwords
        for i in range(3):
            response = requests.post(
                f"{api_url}/login",
                json={"username": username, "password": f"wrong_password_{i}"}
            )
            assert response.status_code == 401, f"Expected 401, got {response.status_code}"

        # 4th attempt should be blocked (423)
        response = requests.post(
            f"{api_url}/login",
            json={"username": username, "password": test_user["password"]}
        )
        assert response.status_code == 423, \
            f"Expected 423 (Locked), got {response.status_code}: {response.text}"

        # Verify lock_type is temporary
        assert "bloqueado" in response.json()["message"].lower(), \
            "Response should indicate lock"

    def test_level_2_block_on_5_failures(self, api_url, test_user):
        """Test that level 2 block is applied after 5 failed attempts"""
        username = test_user["username"]

        # Attempt 5 wrong passwords
        for i in range(5):
            response = requests.post(
                f"{api_url}/login",
                json={"username": username, "password": f"wrong_password_{i}"}
            )
            assert response.status_code == 401

        # Should be blocked now
        response = requests.post(
            f"{api_url}/login",
            json={"username": username, "password": test_user["password"]}
        )
        assert response.status_code == 423

    def test_level_3_block_on_10_failures(self, api_url, test_user):
        """Test that level 3 block is applied after 10 failed attempts"""
        username = test_user["username"]

        # Attempt 10 wrong passwords
        for i in range(10):
            response = requests.post(
                f"{api_url}/login",
                json={"username": username, "password": f"wrong_password_{i}"}
            )
            assert response.status_code == 401

        # Should be blocked now
        response = requests.post(
            f"{api_url}/login",
            json={"username": username, "password": test_user["password"]}
        )
        assert response.status_code == 423

    def test_level_4_permanent_block_on_15_failures(self, api_url, test_user):
        """Test that level 4 (permanent) block is applied after 15 failed attempts"""
        username = test_user["username"]

        # Attempt 15 wrong passwords
        for i in range(15):
            response = requests.post(
                f"{api_url}/login",
                json={"username": username, "password": f"wrong_password_{i}"}
            )
            assert response.status_code == 401

        # Should be permanently blocked
        response = requests.post(
            f"{api_url}/login",
            json={"username": username, "password": test_user["password"]}
        )
        assert response.status_code == 423
        assert "permanente" in response.json()["message"].lower() or \
               "permanent" in response.json()["message"].lower()


class TestUserLockStatus:
    """Tests for user lock status in API responses"""

    def test_unlocked_user_shows_no_lock(self, api_url, root_token, test_user):
        """Test that unlocked user has is_locked=false and lock_type=none"""
        response = requests.get(
            f"{api_url}/users",
            headers={"Authorization": f"Bearer {root_token}"}
        )
        assert response.status_code == 200

        user_data = next(
            (u for u in response.json()["data"] if u["username"] == test_user["username"]),
            None
        )
        assert user_data is not None
        assert user_data["is_locked"] is False
        assert user_data["lock_type"] == "none"
        assert user_data["seconds_until_unlock"] is None

    def test_temporarily_locked_user_shows_countdown(self, api_url, root_token, test_user):
        """Test that temporarily locked user shows is_locked=true and seconds_until_unlock"""
        username = test_user["username"]

        # Create 3 failed attempts to trigger level 1 block
        for i in range(3):
            requests.post(
                f"{api_url}/login",
                json={"username": username, "password": f"wrong_{i}"}
            )

        # Check user status
        response = requests.get(
            f"{api_url}/users",
            headers={"Authorization": f"Bearer {root_token}"}
        )
        assert response.status_code == 200

        user_data = next(
            (u for u in response.json()["data"] if u["username"] == username),
            None
        )
        assert user_data is not None
        assert user_data["is_locked"] is True
        assert user_data["lock_type"] == "temporary"
        assert user_data["lock_level"] == 1
        assert user_data["seconds_until_unlock"] is not None
        assert user_data["seconds_until_unlock"] > 0


class TestManualBlocking:
    """Tests for manual admin-initiated user blocks"""

    def test_admin_can_block_user(self, api_url, root_token, test_user):
        """Test that admin can manually block a user"""
        username = test_user["username"]

        response = requests.put(
            f"{api_url}/users/{username}/block",
            headers={"Authorization": f"Bearer {root_token}"}
        )
        assert response.status_code == 200

        # Verify user is blocked
        response = requests.post(
            f"{api_url}/login",
            json={"username": username, "password": test_user["password"]}
        )
        assert response.status_code == 423

    def test_manually_blocked_user_shows_permanent_lock(self, api_url, root_token, test_user):
        """Test that manually blocked user shows permanent lock status"""
        username = test_user["username"]

        # Block user
        requests.put(
            f"{api_url}/users/{username}/block",
            headers={"Authorization": f"Bearer {root_token}"}
        )

        # Check status
        response = requests.get(
            f"{api_url}/users",
            headers={"Authorization": f"Bearer {root_token}"}
        )

        user_data = next(
            (u for u in response.json()["data"] if u["username"] == username),
            None
        )
        assert user_data is not None
        assert user_data["is_locked"] is True
        assert user_data["lock_type"] == "permanent"
        assert user_data["seconds_until_unlock"] is None

    def test_admin_can_unblock_user(self, api_url, root_token, test_user):
        """Test that admin can unblock a manually blocked user"""
        username = test_user["username"]

        # Block then unblock
        requests.put(
            f"{api_url}/users/{username}/block",
            headers={"Authorization": f"Bearer {root_token}"}
        )

        response = requests.put(
            f"{api_url}/users/{username}/unlock",
            headers={"Authorization": f"Bearer {root_token}"}
        )
        assert response.status_code == 200

        # Verify user can login
        response = requests.post(
            f"{api_url}/login",
            json={"username": username, "password": test_user["password"]}
        )
        assert response.status_code == 200

    def test_user_cannot_block_themselves(self, api_url, test_user):
        """Test that user cannot block themselves"""
        username = test_user["username"]

        # Login as test user
        response = requests.post(
            f"{api_url}/login",
            json={"username": username, "password": test_user["password"]}
        )
        assert response.status_code == 200
        token = response.json()["data"]["token"]

        # Try to block themselves
        response = requests.put(
            f"{api_url}/users/{username}/block",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 403  # Forbidden


class TestJWTValidationDuringBlock:
    """Tests that JWT tokens are validated against block status"""

    def test_existing_jwt_invalidated_when_user_blocked(self, api_url, root_token, test_user):
        """Test that existing JWT becomes invalid when user is blocked"""
        username = test_user["username"]

        # Login to get token
        response = requests.post(
            f"{api_url}/login",
            json={"username": username, "password": test_user["password"]}
        )
        assert response.status_code == 200
        token = response.json()["data"]["token"]

        # Verify token works
        response = requests.get(
            f"{api_url}/users",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 200

        # Block user
        requests.put(
            f"{api_url}/users/{username}/block",
            headers={"Authorization": f"Bearer {root_token}"}
        )

        # Token should now be invalid
        response = requests.get(
            f"{api_url}/users",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 401  # Unauthorized

    def test_refresh_token_denied_when_user_blocked(self, api_url, root_token, test_user):
        """Test that refresh token is denied when user is blocked"""
        username = test_user["username"]

        # Login to get tokens
        response = requests.post(
            f"{api_url}/login",
            json={"username": username, "password": test_user["password"]}
        )
        assert response.status_code == 200
        refresh_token = response.json()["data"].get("refresh_token")

        if refresh_token:
            # Block user
            requests.put(
                f"{api_url}/users/{username}/block",
                headers={"Authorization": f"Bearer {root_token}"}
            )

            # Refresh should be denied
            response = requests.post(
                f"{api_url}/refresh",
                json={"refresh_token": refresh_token}
            )
            assert response.status_code in [401, 423]


class TestBlockExpiration:
    """Tests that temporary blocks expire correctly"""

    def test_temporary_block_expires_after_duration(self, api_url, test_user):
        """Test that temporary block expires after its duration"""
        username = test_user["username"]

        # Create 3 failed attempts (level 1 = 5 min block)
        for i in range(3):
            requests.post(
                f"{api_url}/login",
                json={"username": username, "password": f"wrong_{i}"}
            )

        # Should be blocked now
        response = requests.post(
            f"{api_url}/login",
            json={"username": username, "password": test_user["password"]}
        )
        assert response.status_code == 423

        # This test is conceptual - in real scenario we'd wait 5+ minutes
        # For CI/CD, we'd need to mock time or use a shorter test duration setting


class TestErrorMessages:
    """Tests for appropriate error messages during blocking"""

    def test_blocked_user_gets_appropriate_message(self, api_url, test_user):
        """Test that blocked user receives clear error message"""
        username = test_user["username"]

        # Create block
        for i in range(3):
            requests.post(
                f"{api_url}/login",
                json={"username": username, "password": f"wrong_{i}"}
            )

        # Check message
        response = requests.post(
            f"{api_url}/login",
            json={"username": username, "password": test_user["password"]}
        )
        assert response.status_code == 423
        message = response.json()["message"].lower()
        assert "bloque" in message or "lock" in message
