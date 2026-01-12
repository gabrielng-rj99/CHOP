#!/usr/bin/env python3
"""
Quick test script to verify role ID validation fix.
Tests that hardcoded role IDs (like a0000000-0000-0000-0000-000000000003)
are now accepted when setting role permissions.
"""

import requests
import json

# Configuration
BASE_URL = "http://localhost:3000"
ROOT_USER = "root"
ROOT_PASSWORD = "THIS_IS_A_DEV_ENVIRONMENT_PASSWORD@123abc"

# Test role ID (the "user" role from schema)
TEST_ROLE_ID = "a0000000-0000-0000-0000-000000000003"

def login():
    """Login as root user and return token"""
    print("🔐 Logging in as root...")
    response = requests.post(
        f"{BASE_URL}/api/auth/login",
        json={"username": ROOT_USER, "password": ROOT_PASSWORD}
    )

    if response.status_code != 200:
        print(f"❌ Login failed: {response.status_code}")
        print(f"   Response: {response.text}")
        return None

    data = response.json()
    token = data.get("token")
    print(f"✅ Login successful! Token: {token[:20]}...")
    return token

def get_role_permissions(token, role_id):
    """Get current permissions for a role"""
    print(f"\n📋 Getting permissions for role {role_id}...")
    response = requests.get(
        f"{BASE_URL}/api/roles/{role_id}/permissions",
        headers={"Authorization": f"Bearer {token}"}
    )

    if response.status_code != 200:
        print(f"❌ Failed to get permissions: {response.status_code}")
        print(f"   Response: {response.text}")
        return None

    data = response.json()
    permissions = data.get("permissions", [])
    print(f"✅ Got {len(permissions)} permissions")
    return permissions

def set_role_permissions(token, role_id, permission_ids):
    """Set permissions for a role"""
    print(f"\n✏️  Setting {len(permission_ids)} permissions for role {role_id}...")
    response = requests.put(
        f"{BASE_URL}/api/roles/{role_id}/permissions",
        headers={"Authorization": f"Bearer {token}"},
        json={"permission_ids": permission_ids}
    )

    print(f"   Status code: {response.status_code}")
    print(f"   Response: {response.text}")

    if response.status_code == 404:
        print("❌ Got 404 'Role not found' - This is the bug!")
        print("   The role ID validation is rejecting hardcoded UUIDs")
        return False
    elif response.status_code == 200:
        print("✅ Permissions updated successfully!")
        return True
    else:
        print(f"⚠️  Unexpected status code: {response.status_code}")
        return False

def main():
    print("=" * 60)
    print("Testing Role ID Validation Fix")
    print("=" * 60)
    print(f"\nTesting with role ID: {TEST_ROLE_ID}")
    print("This is a hardcoded UUID (not UUID v4) from schema.")
    print()

    # Login
    token = login()
    if not token:
        print("\n❌ Cannot proceed without token")
        return

    # Get current permissions
    current_permissions = get_role_permissions(token, TEST_ROLE_ID)
    if current_permissions is None:
        print("\n❌ Cannot proceed without current permissions")
        return

    # Extract permission IDs
    permission_ids = [p["id"] for p in current_permissions]

    # Try to set the same permissions (this should work)
    success = set_role_permissions(token, TEST_ROLE_ID, permission_ids)

    print("\n" + "=" * 60)
    if success:
        print("✅ SUCCESS! Role ID validation accepts hardcoded UUIDs")
        print("   The fix is working correctly!")
    else:
        print("❌ FAILED! Role ID validation still rejecting hardcoded UUIDs")
        print("   Make sure to restart backend with ehop-backend-fixed")
    print("=" * 60)

    return success

if __name__ == "__main__":
    try:
        main()
    except requests.exceptions.ConnectionError:
        print("\n❌ ERROR: Cannot connect to backend at", BASE_URL)
        print("   Make sure the backend is running!")
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        import traceback
        traceback.print_exc()
