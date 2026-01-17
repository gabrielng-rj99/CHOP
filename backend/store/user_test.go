/*
 * Client Hub Open Project
 * Copyright (C) 2025 Client Hub Contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package store

import (
	domain "Open-Generic-Hub/backend/domain"
	"fmt"
	"strings"
	"testing"
	"time"

	"database/sql"

	_ "github.com/jackc/pgx/v5/stdlib"
)

func TestEditUserAdminFlagPermissions(t *testing.T) {
	db, err := SetupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}
	defer CloseDB(db)

	// Limpa tabela users antes do teste
	_, err = db.Exec("DELETE FROM users")
	if err != nil {
		t.Fatalf("Failed to clear users table: %v", err)
	}

	userStore := NewUserStore(db)

	// Cria usuário admin (sem número)
	_, err = userStore.CreateUser("admin", "Administrador", "SenhaForte123!@#abc", "root")
	if err != nil {
		t.Fatalf("Erro ao criar usuário root: %v", err)
	}

	// Cria usuário admin0
	_, err = userStore.CreateUser("admin0", "Admin Zero", "SenhaForte123!@#abc", "admin")
	if err != nil {
		t.Fatalf("Erro ao criar usuário admin0: %v", err)
	}

	// Cria usuário normal
	_, err = userStore.CreateUser("user1", "Usuário Um", "SenhaForte123!@#abc", "user")
	if err != nil {
		t.Fatalf("Erro ao criar usuário normal: %v", err)
	}

	// Tenta alterar role de user1 usando admin-0 (não deve permitir)
	err = userStore.EditUserRole("admin-0", "user1", "admin")
	if err == nil {
		t.Error("admin-0 NÃO deveria poder alterar o role de outro usuário")
	}

	// Tenta alterar role de admin0 usando admin0 (não deve permitir)
	err = userStore.EditUserRole("admin0", "admin0", "user")
	if err == nil {
		t.Error("admin0 NÃO deveria poder alterar o role de outro admin")
	}

	// Tenta alterar role de user1 usando admin (deve permitir)
	err = userStore.EditUserRole("admin", "user1", "admin")
	if err != nil {
		t.Errorf("root deveria poder alterar o role de outro usuário: %v", err)
	}

	// Tenta remover role admin de admin0 usando admin (deve permitir)
	err = userStore.EditUserRole("admin", "admin0", "user")
	if err != nil {
		t.Errorf("root deveria poder remover o role admin de outro admin: %v", err)
	}

	// Confere se user1 virou admin
	users, err := userStore.ListUsers()
	if err != nil {
		t.Fatalf("Erro ao listar usuários: %v", err)
	}
	var user1, admin0 domain.User
	for _, u := range users {
		if u.Username != nil && *u.Username == "user1" {
			user1 = u
		}
		if u.Username != nil && *u.Username == "admin0" {
			admin0 = u
		}
	}
	if user1.Role == nil || *user1.Role != "admin" {
		t.Error("user1 deveria ser admin após alteração feita por root")
	}
	if admin0.Role == nil || *admin0.Role != "user" {
		t.Error("admin0 NÃO deveria ser admin após remoção feita por root")
	}
}

// ============================================================================
// CRITICAL TESTS
// ============================================================================

func setupUserTest(t *testing.T) *sql.DB {
	db, err := SetupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}
	if err := ClearTables(db); err != nil {
		t.Fatalf("Failed to clear tables: %v", err)
	}
	return db
}

// TestCreateUserBasic tests basic user creation with validation
func TestCreateUserBasic(t *testing.T) {
	db := setupUserTest(t)
	defer CloseDB(db)

	_, err := db.Exec("DELETE FROM users")
	if err != nil {
		t.Fatalf("Failed to clear users table: %v", err)
	}

	userStore := NewUserStore(db)

	tests := []struct {
		name        string
		username    string
		displayName string
		password    string
		role        string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "valid root user",
			username:    "fulladminuser",
			displayName: "Root User",
			password:    "ValidPass123!@#a",
			role:        "root",
			expectError: false,
		},
		{
			name:        "valid admin user",
			username:    "admin1",
			displayName: "Admin One",
			password:    "ValidPass123!@#a",
			role:        "admin",
			expectError: false,
		},
		{
			name:        "valid regular user",
			username:    "regularuser",
			displayName: "Regular User",
			password:    "ValidPass123!@#a",
			role:        "user",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id, err := userStore.CreateUser(tt.username, tt.displayName, tt.password, tt.role)
			if (err != nil) != tt.expectError {
				t.Errorf("CreateUser() error = %v, expectError %v", err, tt.expectError)
				return
			}
			if !tt.expectError && id == "" {
				t.Error("CreateUser() returned empty ID for valid user")
			}
		})
	}
}

// TestAuthenticateUserSuccess tests successful user authentication
func TestAuthenticateUserSuccess(t *testing.T) {
	db := setupUserTest(t)
	defer CloseDB(db)

	_, err := db.Exec("DELETE FROM users")
	if err != nil {
		t.Fatalf("Failed to clear users table: %v", err)
	}

	userStore := NewUserStore(db)

	username := "testuser"
	displayName := "Test User"
	password := "TestPass123!@#ab"

	_, err = userStore.CreateUser(username, displayName, password, "user")
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	user, err := userStore.AuthenticateUser(username, password)
	if err != nil {
		t.Errorf("AuthenticateUser() error = %v", err)
		return
	}
	if user == nil {
		t.Error("AuthenticateUser() returned nil user")
		return
	}
	if user.Username == nil || *user.Username != username {
		t.Errorf("AuthenticateUser() returned user with username %v, want %s", user.Username, username)
	}
}

// TestAuthenticateUserInvalidCredentials tests authentication with invalid credentials
func TestAuthenticateUserInvalidCredentials(t *testing.T) {
	db := setupUserTest(t)
	defer CloseDB(db)

	_, err := db.Exec("DELETE FROM users")
	if err != nil {
		t.Fatalf("Failed to clear users table: %v", err)
	}

	userStore := NewUserStore(db)

	username := "testuser"
	displayName := "Test User"
	password := "TestPass123!@#ab"

	_, err = userStore.CreateUser(username, displayName, password, "user")
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	user, err := userStore.AuthenticateUser(username, "WrongPassword123!@#")
	if err == nil {
		t.Error("AuthenticateUser() with wrong password should return error")
		return
	}
	if user != nil {
		t.Error("AuthenticateUser() with wrong password should return nil user")
	}
}

// TestAuthenticateUserInvalidInputs tests authentication with invalid inputs
func TestAuthenticateUserInvalidInputs(t *testing.T) {
	db := setupUserTest(t)
	defer CloseDB(db)

	_, err := db.Exec("DELETE FROM users")
	if err != nil {
		t.Fatalf("Failed to clear users table: %v", err)
	}

	userStore := NewUserStore(db)

	// Test with non-existent user
	user, err := userStore.AuthenticateUser("nonexistent", "SomePass123!@#")
	if err == nil {
		t.Error("AuthenticateUser() with non-existent user should return error")
		return
	}
	if user != nil {
		t.Error("AuthenticateUser() with non-existent user should return nil user")
	}
}

// TestEditUserPassword tests user password editing
func TestEditUserPassword(t *testing.T) {
	db := setupUserTest(t)
	defer CloseDB(db)

	_, err := db.Exec("DELETE FROM users")
	if err != nil {
		t.Fatalf("Failed to clear users table: %v", err)
	}

	userStore := NewUserStore(db)

	username := "testuser"
	displayName := "Test User"
	oldPassword := "OldPass123!@#abcd"
	newPassword := "NewPass123!@#abcd"

	_, err = userStore.CreateUser(username, displayName, oldPassword, "user")
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	// Edit password
	err = userStore.EditUserPassword(username, newPassword)
	if err != nil {
		t.Errorf("EditUserPassword() error = %v", err)
		return
	}

	// Try to authenticate with old password (should fail)
	_, err = userStore.AuthenticateUser(username, oldPassword)
	if err == nil {
		t.Error("AuthenticateUser() with old password should fail after password change")
		return
	}

	// Try to authenticate with new password (should succeed)
	user, err := userStore.AuthenticateUser(username, newPassword)
	if err != nil {
		t.Errorf("AuthenticateUser() with new password error = %v", err)
		return
	}
	if user == nil {
		t.Error("AuthenticateUser() with new password returned nil user")
	}
}

// TestEditUserDisplayName tests user display name editing
func TestEditUserDisplayName(t *testing.T) {
	db := setupUserTest(t)
	defer CloseDB(db)

	_, err := db.Exec("DELETE FROM users")
	if err != nil {
		t.Fatalf("Failed to clear users table: %v", err)
	}

	userStore := NewUserStore(db)

	username := "testuser"
	oldDisplayName := "Old Display Name"
	newDisplayName := "New Display Name"
	password := "TestPass123!@#abcd"

	_, err = userStore.CreateUser(username, oldDisplayName, password, "user")
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	// Edit display name
	err = userStore.EditUserDisplayName(username, newDisplayName)
	if err != nil {
		t.Errorf("EditUserDisplayName() error = %v", err)
		return
	}

	// Verify display name was changed
	users, err := userStore.GetUsersByName(oldDisplayName)
	if err != nil {
		t.Errorf("GetUsersByName() error = %v", err)
		return
	}
	if len(users) > 0 && (users[0].DisplayName == nil || *users[0].DisplayName != newDisplayName) {
		t.Errorf("EditUserDisplayName() failed: got %v, want %s", users[0].DisplayName, newDisplayName)
	}
}

// TestListUsers tests listing all users
func TestListUsers(t *testing.T) {
	db := setupUserTest(t)
	defer CloseDB(db)

	_, err := db.Exec("DELETE FROM users")
	if err != nil {
		t.Fatalf("Failed to clear users table: %v", err)
	}

	userStore := NewUserStore(db)

	// Create multiple users
	users := []struct {
		username    string
		displayName string
		password    string
		role        string
	}{
		{"user1", "User One", "Pass1@#Secure123", "user"},
		{"user2", "User Two", "Pass2@#Secure123", "user"},
		{"admin1", "Admin One", "Pass3@#Secure123", "admin"},
	}

	for _, u := range users {
		_, err := userStore.CreateUser(u.username, u.displayName, u.password, u.role)
		if err != nil {
			t.Fatalf("Failed to create user %s: %v", u.username, err)
		}
	}

	// List users
	userList, err := userStore.ListUsers()
	if err != nil {
		t.Errorf("ListUsers() error = %v", err)
		return
	}

	if len(userList) != len(users) {
		t.Errorf("ListUsers() returned %d users, want %d", len(userList), len(users))
	}
}

// TestCreateAdminUser tests admin user creation with auto-generated username
func TestCreateAdminUser(t *testing.T) {
	db := setupUserTest(t)
	defer CloseDB(db)

	_, err := db.Exec("DELETE FROM users")
	if err != nil {
		t.Fatalf("Failed to clear users table: %v", err)
	}

	userStore := NewUserStore(db)

	// Test 1: Auto-generated username
	id, username, displayName, password, err := userStore.CreateAdminUser("", "Test Admin", "root")
	if err != nil {
		t.Errorf("CreateAdminUser() error = %v", err)
		return
	}

	if id == "" {
		t.Error("CreateAdminUser() returned empty ID")
	}
	if username == "" {
		t.Error("CreateAdminUser() returned empty username")
	}
	if displayName != "Test Admin" {
		t.Errorf("CreateAdminUser() returned wrong display name")
	}
	if !strings.HasPrefix(username, "admin") {
		t.Errorf("Expected username to start with 'admin', got '%s'", username)
	}
	if password == "" {
		t.Error("CreateAdminUser() returned empty password")
	}

	// Verify user can authenticate
	user, err := userStore.AuthenticateUser(username, password)
	if err != nil {
		t.Errorf("Failed to authenticate created admin user: %v", err)
		return
	}
	if user.Role == nil || *user.Role != "root" {
		t.Errorf("Created admin user has role %v, want root", user.Role)
	}

	// Test 2: Custom username
	customName := "mycustomadmin"
	id2, user2, _, pass2, err := userStore.CreateAdminUser(customName, "Custom Admin", "admin")
	if err != nil {
		t.Fatalf("Failed to create custom admin: %v", err)
	}
	if id2 == "" || user2 != customName || pass2 == "" {
		t.Error("Expected correct custom admin data")
	}

	// Test 3: Duplicate custom username
	_, _, _, _, err = userStore.CreateAdminUser(customName, "Audit Log", "auditor")
	if err == nil {
		t.Error("Expected error for duplicate admin username")
	}
}

// TestUnlockUser tests user unlock functionality
func TestUnlockUser(t *testing.T) {
	db := setupUserTest(t)
	defer CloseDB(db)

	_, err := db.Exec("DELETE FROM users")
	if err != nil {
		t.Fatalf("Failed to clear users table: %v", err)
	}

	userStore := NewUserStore(db)

	username := "testuser"
	displayName := "Test User"
	password := "TestPass123!@#abcd"

	_, err = userStore.CreateUser(username, displayName, password, "user")
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	// Lock the user
	lockLevel := 2
	lockedUntil := time.Now().Add(1 * time.Hour)
	_, err = db.Exec(
		"UPDATE users SET lock_level = $1, locked_until = $2 WHERE username = $3",
		lockLevel, lockedUntil, username,
	)
	if err != nil {
		t.Fatalf("Failed to lock user: %v", err)
	}

	// Verify user is locked
	var level int
	err = db.QueryRow("SELECT lock_level FROM users WHERE username = $1", username).Scan(&level)
	if err != nil {
		t.Fatalf("Failed to query user lock level: %v", err)
	}
	if level == 0 {
		t.Error("User should be locked")
	}

	// Unlock user
	err = userStore.UnlockUser(username)
	if err != nil {
		t.Errorf("UnlockUser() error = %v", err)
		return
	}

	// Verify user is unlocked
	err = db.QueryRow("SELECT lock_level FROM users WHERE username = $1", username).Scan(&level)
	if err != nil {
		t.Fatalf("Failed to query user lock level after unlock: %v", err)
	}
	if level != 0 {
		t.Error("User should be unlocked")
	}
}

// TestCreateUserWithInvalidUsernames tests user creation with invalid usernames
func TestCreateUserWithInvalidUsernames(t *testing.T) {
	db := setupUserTest(t)
	defer CloseDB(db)

	_, err := db.Exec("DELETE FROM users")
	if err != nil {
		t.Fatalf("Failed to clear users table: %v", err)
	}

	userStore := NewUserStore(db)

	invalidUsernames := []string{
		"",
		"ab",
		strings.Repeat("a", 256),
		"user with spaces",
		"user@domain",
	}

	for _, username := range invalidUsernames {
		_, err := userStore.CreateUser(username, "Valid Name", "ValidPass123!@#a", "user")
		if err == nil {
			t.Errorf("CreateUser() should reject username %q", username)
		}
	}
}

// TestCreateUserWithInvalidDisplayNames tests user creation with invalid display names
func TestCreateUserWithInvalidDisplayNames(t *testing.T) {
	db := setupUserTest(t)
	defer CloseDB(db)

	_, err := db.Exec("DELETE FROM users")
	if err != nil {
		t.Fatalf("Failed to clear users table: %v", err)
	}

	userStore := NewUserStore(db)

	invalidDisplayNames := []string{
		"",
		strings.Repeat("a", 256),
	}

	for _, displayName := range invalidDisplayNames {
		_, err := userStore.CreateUser("validuser", displayName, "ValidPass123!@#a", "user")
		if err == nil {
			t.Errorf("CreateUser() should reject displayName %q", displayName)
		}
	}
}

// TestCreateUserWithWeakPasswords tests user creation with weak passwords
func TestCreateUserWithWeakPasswords(t *testing.T) {
	db := setupUserTest(t)
	defer CloseDB(db)

	_, err := db.Exec("DELETE FROM users")
	if err != nil {
		t.Fatalf("Failed to clear users table: %v", err)
	}

	userStore := NewUserStore(db)

	weakPasswords := []string{
		"weak",
		"123456",
		"abcdefgh",
		"Pass123",
		"",
	}

	for _, password := range weakPasswords {
		_, err := userStore.CreateUser("validuser"+strings.ReplaceAll(password, " ", ""), "Valid Name", password, "user")
		if err == nil {
			t.Errorf("CreateUser() should reject weak password %q", password)
		}
	}
}

// TestCreateUserWithPasswordEqualsUsername tests that password cannot be same as username
func TestCreateUserWithPasswordEqualsUsername(t *testing.T) {
	db := setupUserTest(t)
	defer CloseDB(db)

	_, err := db.Exec("DELETE FROM users")
	if err != nil {
		t.Fatalf("Failed to clear users table: %v", err)
	}

	userStore := NewUserStore(db)

	username := "testuser"
	_, err = userStore.CreateUser(username, "Valid Name", username, "user")
	if err == nil {
		t.Error("CreateUser() should reject password equal to username")
	}
}

// TestCreateUserWithInvalidRoles tests user creation with invalid roles
func TestCreateUserWithInvalidRoles(t *testing.T) {
	db := setupUserTest(t)
	defer CloseDB(db)

	_, err := db.Exec("DELETE FROM users")
	if err != nil {
		t.Fatalf("Failed to clear users table: %v", err)
	}

	userStore := NewUserStore(db)

	// Test invalid roles that don't exist in the database
	invalidRoles := []string{"superuser", "moderator", "guest", "invalid_role_xyz"}

	for _, role := range invalidRoles {
		_, err := userStore.CreateUser("validuser"+role, "Valid Name", "ValidPass123!@#a", role)
		if err == nil {
			t.Errorf("CreateUser() should reject role that doesn't exist in database: %q", role)
		}
		if !strings.Contains(err.Error(), "invalid role") {
			t.Errorf("Expected 'invalid role' error for role %q, got: %v", role, err)
		}
	}
}

// TestCreateUserWithSystemRoles verifies that system roles (user, admin, root, viewer) are valid
func TestCreateUserWithSystemRoles(t *testing.T) {
	db := setupUserTest(t)
	defer CloseDB(db)

	_, err := db.Exec("DELETE FROM users")
	if err != nil {
		t.Fatalf("Failed to clear users table: %v", err)
	}

	userStore := NewUserStore(db)

	// Test cases with appropriate password lengths for each role
	testCases := []struct {
		role     string
		password string
	}{
		{"user", "ValidPass123!@#abc"},        // user: 16 chars minimum
		{"admin", "ValidPass123!@#abcdef"},    // admin: 20 chars minimum
		{"root", "ValidPass123!@#abcdefghij"}, // root: 24 chars minimum
		{"viewer", "ValidPass123!@#abc"},      // viewer: 16 chars minimum
	}

	for i, tc := range testCases {
		username := fmt.Sprintf("sysuser%d", i)
		_, err := userStore.CreateUser(username, "System User", tc.password, tc.role)
		if err != nil {
			t.Errorf("CreateUser() should accept valid system role %q: %v", tc.role, err)
		}
	}
}

// TestValidateRoleExists verifies the dynamic role validation from database
func TestValidateRoleExists(t *testing.T) {
	db := setupUserTest(t)
	defer CloseDB(db)

	userStore := NewUserStore(db)

	testCases := []struct {
		role        string
		shouldExist bool
		description string
	}{
		{"user", true, "Standard user role should exist"},
		{"admin", true, "Admin role should exist"},
		{"root", true, "Root role should exist"},
		{"viewer", true, "Viewer role should exist"},
		{"invalid_role", false, "Invalid role should not exist"},
		{"superuser", false, "Superuser role should not exist"},
		{"", false, "Empty role should not be valid"},
	}

	for _, tc := range testCases {
		err := userStore.ValidateRoleExists(tc.role)
		if tc.shouldExist && err != nil {
			t.Errorf("ValidateRoleExists(%q) should succeed but got error: %v", tc.role, err)
		}
		if !tc.shouldExist && err == nil {
			t.Errorf("ValidateRoleExists(%q) should fail but succeeded", tc.role)
		}
		if !tc.shouldExist && err != nil {
			// Accept both "invalid role" or "role não pode estar vazio" as valid error messages
			errMsg := err.Error()
			if !strings.Contains(errMsg, "invalid role") && !strings.Contains(errMsg, "não pode estar vazio") {
				t.Errorf("ValidateRoleExists(%q) got unexpected error: %v", tc.role, err)
			}
		}
	}
}

// TestEditUserPasswordWithInvalidPasswords tests editing user password with invalid passwords
func TestEditUserPasswordWithInvalidPasswords(t *testing.T) {
	db := setupUserTest(t)
	defer CloseDB(db)

	_, err := db.Exec("DELETE FROM users")
	if err != nil {
		t.Fatalf("Failed to clear users table: %v", err)
	}

	userStore := NewUserStore(db)

	username := "testuser"
	displayName := "Test User"
	password := "ValidPass123!@#a"

	userID, err := userStore.CreateUser(username, displayName, password, "user")
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	invalidPasswords := []string{
		"weak",
		"123456",
		"",
	}

	for _, invalidPass := range invalidPasswords {
		err := userStore.EditUserPassword(userID, invalidPass)
		if err == nil {
			t.Errorf("EditUserPassword() should reject invalid password %q", invalidPass)
		}
	}
}

// TestEditUserDisplayNameWithInvalidData tests editing user display name with invalid data
func TestEditUserDisplayNameWithInvalidData(t *testing.T) {
	db := setupUserTest(t)
	defer CloseDB(db)

	_, err := db.Exec("DELETE FROM users")
	if err != nil {
		t.Fatalf("Failed to clear users table: %v", err)
	}

	userStore := NewUserStore(db)

	username := "testuser"
	displayName := "Test User"
	password := "ValidPass123!@#a"

	userID, err := userStore.CreateUser(username, displayName, password, "user")
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	invalidDisplayNames := []string{
		"",
		strings.Repeat("a", 256),
	}

	for _, invalidName := range invalidDisplayNames {
		err := userStore.EditUserDisplayName(userID, invalidName)
		if err == nil {
			t.Errorf("EditUserDisplayName() should reject invalid display name %q", invalidName)
		}
	}
}

// TestGetUserByID tests fetching a user by ID
func TestGetUserByID(t *testing.T) {
	db := setupUserTest(t)
	defer CloseDB(db)

	_, err := db.Exec("DELETE FROM users")
	if err != nil {
		t.Fatalf("Failed to clear users table: %v", err)
	}

	userStore := NewUserStore(db)

	username := "testuser"
	displayName := "Test User"
	password := "TestPass123!@#abcdef" // 20 chars
	role := "user"

	id, err := userStore.CreateUser(username, displayName, password, role)
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	// Fetch user by ID
	user, err := userStore.GetUserByID(id)
	if err != nil {
		t.Fatalf("GetUserByID failed: %v", err)
	}
	if user == nil {
		t.Fatal("GetUserByID returned nil user")
	}
	if *user.Username != username {
		t.Errorf("Expected username %s, got %s", username, *user.Username)
	}
	if *user.DisplayName != displayName {
		t.Errorf("Expected display name %s, got %s", displayName, *user.DisplayName)
	}

	// Test non-existent ID
	randomID := "00000000-0000-0000-0000-000000000000"
	nonExistentUser, err := userStore.GetUserByID(randomID)
	// We expect an error because 0000... doesn't exist.
	if err == nil {
		t.Error("Expected error for non-existent user")
	}
	if nonExistentUser != nil {
		t.Error("Expected nil user for non-existent ID")
	}
}

// TestUpdateUsername tests updating a user's username
func TestUpdateUsername(t *testing.T) {
	db := setupUserTest(t)
	defer CloseDB(db)

	_, err := db.Exec("DELETE FROM users")
	if err != nil {
		t.Fatalf("Failed to clear users table: %v", err)
	}

	userStore := NewUserStore(db)

	// Create a user
	username := "oldname"
	password := "TestPass123!@#abcdef"
	_, err = userStore.CreateUser(username, "Display Name", password, "user")
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	// Update username
	err = userStore.UpdateUsername(username, "newname")
	if err != nil {
		t.Fatalf("UpdateUsername failed: %v", err)
	}

	// Verify update
	user, err := userStore.AuthenticateUser("newname", password)
	if err != nil {
		t.Fatalf("Failed to authenticate with new username: %v", err)
	}
	if *user.Username != "newname" {
		t.Errorf("Expected username newname, got %s", *user.Username)
	}

	// Test constraint violation (duplicate username)
	_, err = userStore.CreateUser("another", "Another User", password, "user")
	if err != nil {
		t.Fatalf("Failed to create second user: %v", err)
	}

	err = userStore.UpdateUsername("newname", "another")
	if err == nil {
		t.Error("Expected error when updating to existing username")
	}
}

// TestDeleteUser tests deleting a user
func TestDeleteUser(t *testing.T) {
	db := setupUserTest(t)
	defer CloseDB(db)

	_, err := db.Exec("DELETE FROM users")
	if err != nil {
		t.Fatalf("Failed to clear users table: %v", err)
	}

	userStore := NewUserStore(db)

	username := "todelete"
	password := "TestPass123!@#abcdef"
	id, err := userStore.CreateUser(username, "Delete Me", password, "user")
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	// Delete user
	err = userStore.DeleteUser("admin-id", "admin-user", username)
	if err != nil {
		t.Fatalf("DeleteUser failed: %v", err)
	}

	// Verify deletion
	user, err := userStore.GetUserByID(id)
	if err != nil {
		t.Fatalf("Failed to get user: %v", err)
	}
	if user.DeletedAt == nil {
		t.Error("User should have deleted_at set")
	}
}

// TestBlockUser tests blocking a user
func TestBlockUser(t *testing.T) {
	db := setupUserTest(t)
	defer CloseDB(db)

	_, err := db.Exec("DELETE FROM users")
	if err != nil {
		t.Fatalf("Failed to clear users table: %v", err)
	}

	userStore := NewUserStore(db)

	_, username, _, _, err := userStore.CreateAdminUser("", "Admin", "root")
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	// Block user
	err = userStore.BlockUser(username)
	if err != nil {
		t.Fatalf("BlockUser failed: %v", err)
	}

	// Verify block
	var level int
	err = db.QueryRow("SELECT lock_level FROM users WHERE username = $1", username).Scan(&level)
	if err != nil {
		t.Fatalf("Failed to query lock level: %v", err)
	}
	if level <= 0 {
		t.Error("User should be blocked (lock_level > 0)")
	}
}

// TestGetUsersByName tests searching users by name
func TestGetUsersByName(t *testing.T) {
	db := setupUserTest(t)
	defer CloseDB(db)

	_, err := db.Exec("DELETE FROM users")
	if err != nil {
		t.Fatalf("Failed to clear users table: %v", err)
	}

	userStore := NewUserStore(db)

	password := "TestPass123!@#abcdef"
	_, err = userStore.CreateUser("user1", "Alpha User", password, "user")
	if err != nil {
		t.Fatalf("Failed to create u1: %v", err)
	}
	_, err = userStore.CreateUser("user2", "Beta User", password, "user")
	if err != nil {
		t.Fatalf("Failed to create u2: %v", err)
	}
	_, err = userStore.CreateUser("user3", "Alpha Two", password, "user")
	if err != nil {
		t.Fatalf("Failed to create u3: %v", err)
	}

	// Search "Alpha"
	users, err := userStore.GetUsersByName("Alpha")
	if err != nil {
		t.Fatalf("GetUsersByName failed: %v", err)
	}
	if len(users) != 2 {
		t.Errorf("Expected 2 users, got %d", len(users))
	}

	// Search "Beta"
	users, err = userStore.GetUsersByName("Beta")
	if err != nil {
		t.Fatalf("GetUsersByName failed: %v", err)
	}
	if len(users) != 1 {
		t.Errorf("Expected 1 user, got %d", len(users))
	}
}
