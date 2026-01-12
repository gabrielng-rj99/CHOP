#!/usr/bin/env python3
"""
Comprehensive test for all role endpoints with hardcoded UUIDs.
Tests that hardcoded role IDs from the schema work correctly in all operations.
"""

import requests
import json
import sys

# Configuration
BASE_URL = "http://localhost:3000"
ROOT_USER = "root"
ROOT_PASSWORD = "THIS_IS_A_DEV_ENVIRONMENT_PASSWORD@123abc"

# Test role IDs (hardcoded in schema)
ROLE_ROOT = "a0000000-0000-0000-0000-000000000001"
ROLE_ADMIN = "a0000000-0000-0000-0000-000000000002"
ROLE_USER = "a0000000-0000-0000-0000-000000000003"

class TestResult:
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.errors = []

    def add_pass(self, test_name):
        self.passed += 1
        print(f"  ✅ {test_name}")

    def add_fail(self, test_name, reason):
        self.failed += 1
        self.errors.append(f"{test_name}: {reason}")
        print(f"  ❌ {test_name}")
        print(f"     Reason: {reason}")

    def summary(self):
        total = self.passed + self.failed
        print("\n" + "=" * 70)
        print(f"Test Summary: {self.passed}/{total} passed")
        if self.failed > 0:
            print(f"\nFailed tests:")
            for error in self.errors:
                print(f"  - {error}")
        print("=" * 70)
        return self.failed == 0

def login():
    """Login as root user and return token"""
    try:
        response = requests.post(
            f"{BASE_URL}/api/auth/login",
            json={"username": ROOT_USER, "password": ROOT_PASSWORD},
            timeout=5
        )

        if response.status_code != 200:
            print(f"❌ Login failed: {response.status_code}")
            print(f"   Response: {response.text}")
            return None

        data = response.json()
        token = data.get("token")
        print(f"✅ Logged in as root (token: {token[:20]}...)")
        return token
    except Exception as e:
        print(f"❌ Login error: {e}")
        return None

def test_get_all_roles(token, results):
    """Test GET /api/roles"""
    print("\n📋 Testing GET /api/roles...")
    try:
        response = requests.get(
            f"{BASE_URL}/api/roles",
            headers={"Authorization": f"Bearer {token}"},
            timeout=5
        )

        if response.status_code == 200:
            data = response.json()
            roles = data.get("roles", [])
            if len(roles) >= 3:
                results.add_pass(f"GET /api/roles (found {len(roles)} roles)")
            else:
                results.add_fail("GET /api/roles", f"Expected at least 3 roles, got {len(roles)}")
        else:
            results.add_fail("GET /api/roles", f"Status {response.status_code}: {response.text}")
    except Exception as e:
        results.add_fail("GET /api/roles", str(e))

def test_get_role_by_id(token, role_id, role_name, results):
    """Test GET /api/roles/{id}"""
    print(f"\n📄 Testing GET /api/roles/{role_id} ({role_name})...")
    try:
        response = requests.get(
            f"{BASE_URL}/api/roles/{role_id}",
            headers={"Authorization": f"Bearer {token}"},
            timeout=5
        )

        if response.status_code == 200:
            data = response.json()
            role = data.get("role", {})
            if role.get("id") == role_id:
                results.add_pass(f"GET /api/roles/{role_id} ({role_name})")
            else:
                results.add_fail(f"GET role {role_name}", f"ID mismatch: {role.get('id')} != {role_id}")
        elif response.status_code == 404:
            results.add_fail(f"GET role {role_name}", "404 Role not found - UUID validation bug!")
        else:
            results.add_fail(f"GET role {role_name}", f"Status {response.status_code}: {response.text}")
    except Exception as e:
        results.add_fail(f"GET role {role_name}", str(e))

def test_get_role_permissions(token, role_id, role_name, results):
    """Test GET /api/roles/{id}/permissions"""
    print(f"\n🔑 Testing GET /api/roles/{role_id}/permissions ({role_name})...")
    try:
        response = requests.get(
            f"{BASE_URL}/api/roles/{role_id}/permissions",
            headers={"Authorization": f"Bearer {token}"},
            timeout=5
        )

        if response.status_code == 200:
            data = response.json()
            permissions = data.get("permissions", [])
            results.add_pass(f"GET permissions for {role_name} ({len(permissions)} permissions)")
            return permissions
        elif response.status_code == 404:
            results.add_fail(f"GET permissions {role_name}", "404 Role not found - UUID validation bug!")
            return None
        else:
            results.add_fail(f"GET permissions {role_name}", f"Status {response.status_code}: {response.text}")
            return None
    except Exception as e:
        results.add_fail(f"GET permissions {role_name}", str(e))
        return None

def test_set_role_permissions(token, role_id, role_name, permission_ids, results):
    """Test PUT /api/roles/{id}/permissions"""
    print(f"\n✏️  Testing PUT /api/roles/{role_id}/permissions ({role_name})...")

    if not permission_ids:
        results.add_fail(f"SET permissions {role_name}", "No permissions to set")
        return False

    try:
        response = requests.put(
            f"{BASE_URL}/api/roles/{role_id}/permissions",
            headers={"Authorization": f"Bearer {token}"},
            json={"permission_ids": permission_ids},
            timeout=5
        )

        if response.status_code == 200:
            results.add_pass(f"PUT permissions for {role_name} ({len(permission_ids)} permissions)")
            return True
        elif response.status_code == 404:
            results.add_fail(f"SET permissions {role_name}", "404 Role not found - UUID validation bug!")
            return False
        elif response.status_code == 400:
            error_text = response.text
            if "ID de permissão inválido" in error_text:
                results.add_fail(f"SET permissions {role_name}", "Permission UUID validation bug!")
            else:
                results.add_fail(f"SET permissions {role_name}", f"400 Bad Request: {error_text}")
            return False
        else:
            results.add_fail(f"SET permissions {role_name}", f"Status {response.status_code}: {response.text}")
            return False
    except Exception as e:
        results.add_fail(f"SET permissions {role_name}", str(e))
        return False

def test_hardcoded_permission_ids(token, role_id, role_name, results):
    """Test setting permissions with hardcoded permission IDs"""
    print(f"\n🔐 Testing hardcoded permission IDs for {role_name}...")

    # Some hardcoded permission IDs from schema
    hardcoded_perms = [
        "b0000000-0000-0000-0000-000000000001",  # clients:create
        "b0000000-0000-0000-0000-000000000002",  # clients:read
        "b0000000-0000-0000-0000-000000000003",  # clients:update
    ]

    try:
        response = requests.put(
            f"{BASE_URL}/api/roles/{role_id}/permissions",
            headers={"Authorization": f"Bearer {token}"},
            json={"permission_ids": hardcoded_perms},
            timeout=5
        )

        if response.status_code == 200:
            results.add_pass(f"Hardcoded permission IDs accepted for {role_name}")
            return True
        elif response.status_code == 400 and "ID de permissão inválido" in response.text:
            results.add_fail(f"Hardcoded perms {role_name}", "Permission UUID validation rejects hardcoded IDs!")
            return False
        else:
            results.add_fail(f"Hardcoded perms {role_name}", f"Status {response.status_code}: {response.text}")
            return False
    except Exception as e:
        results.add_fail(f"Hardcoded perms {role_name}", str(e))
        return False

def test_invalid_role_id(token, results):
    """Test that invalid role IDs are properly rejected"""
    print(f"\n🛡️  Testing invalid role ID rejection...")

    invalid_ids = [
        "not-a-uuid",
        "12345",
        "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "' OR '1'='1",
        "../../../etc/passwd",
    ]

    for invalid_id in invalid_ids:
        try:
            response = requests.get(
                f"{BASE_URL}/api/roles/{invalid_id}",
                headers={"Authorization": f"Bearer {token}"},
                timeout=5
            )

            if response.status_code in [400, 404]:
                results.add_pass(f"Invalid ID rejected: {invalid_id[:30]}")
            else:
                results.add_fail(f"Invalid ID {invalid_id[:30]}", f"Expected 400/404, got {response.status_code}")
        except Exception as e:
            results.add_fail(f"Invalid ID {invalid_id[:30]}", str(e))

def main():
    print("=" * 70)
    print("Comprehensive Role Endpoints Test")
    print("Testing all endpoints with hardcoded UUID values")
    print("=" * 70)

    results = TestResult()

    # Login
    print("\n🔐 Logging in...")
    token = login()
    if not token:
        print("\n❌ Cannot proceed without authentication token")
        return False

    # Test 1: Get all roles
    test_get_all_roles(token, results)

    # Test 2: Get individual roles by hardcoded IDs
    test_roles = [
        (ROLE_ROOT, "root"),
        (ROLE_ADMIN, "admin"),
        (ROLE_USER, "user"),
    ]

    for role_id, role_name in test_roles:
        test_get_role_by_id(token, role_id, role_name, results)

    # Test 3: Get permissions for each role
    role_permissions = {}
    for role_id, role_name in test_roles:
        perms = test_get_role_permissions(token, role_id, role_name, results)
        if perms:
            role_permissions[role_id] = [p["id"] for p in perms]

    # Test 4: Set permissions (restore existing permissions to avoid breaking data)
    for role_id, role_name in test_roles:
        if role_id in role_permissions:
            test_set_role_permissions(token, role_id, role_name, role_permissions[role_id], results)

    # Test 5: Test with explicit hardcoded permission IDs
    # Only test with user role to avoid breaking root/admin
    test_hardcoded_permission_ids(token, ROLE_USER, "user", results)

    # Test 6: Restore user role permissions after hardcoded test
    if ROLE_USER in role_permissions:
        print(f"\n🔄 Restoring original permissions for user role...")
        test_set_role_permissions(token, ROLE_USER, "user (restore)", role_permissions[ROLE_USER], results)

    # Test 7: Test invalid IDs are rejected
    test_invalid_role_id(token, results)

    # Print summary
    success = results.summary()

    if success:
        print("\n🎉 All tests passed! UUID validation is working correctly.")
        print("   ✅ Hardcoded role IDs are accepted")
        print("   ✅ Hardcoded permission IDs are accepted")
        print("   ✅ Invalid IDs are properly rejected")
        return True
    else:
        print("\n❌ Some tests failed. Check the errors above.")
        print("\n💡 If you see '404 Role not found' or 'UUID validation' errors:")
        print("   Make sure you restarted the backend with: ./ehop-backend-fixed")
        return False

if __name__ == "__main__":
    try:
        success = main()
        sys.exit(0 if success else 1)
    except requests.exceptions.ConnectionError:
        print("\n❌ ERROR: Cannot connect to backend at", BASE_URL)
        print("   Make sure the backend is running!")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n\n⚠️  Test interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
