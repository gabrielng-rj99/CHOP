package store

import (
	"strings"
	"testing"
	"time"

	"Contracts-Manager/backend/domain"
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
	_, err = userStore.CreateUser("admin", "Administrador", "SenhaForte123!@#abc", "full_admin")
	if err != nil {
		t.Fatalf("Erro ao criar usuário full_admin: %v", err)
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
		t.Errorf("full_admin deveria poder alterar o role de outro usuário: %v", err)
	}

	// Tenta remover role admin de admin0 usando admin (deve permitir)
	err = userStore.EditUserRole("admin", "admin0", "user")
	if err != nil {
		t.Errorf("full_admin deveria poder remover o role admin de outro admin: %v", err)
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
		t.Error("user1 deveria ser admin após alteração feita por full_admin")
	}
	if admin0.Role == nil || *admin0.Role != "user" {
		t.Error("admin0 NÃO deveria ser admin após remoção feita por full_admin")
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
			name:        "valid full_admin user",
			username:    "fulladminuser",
			displayName: "Full Admin User",
			password:    "ValidPass123!@#a",
			role:        "full_admin",
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

	id, username, displayName, password, err := userStore.CreateAdminUser("", "Test Admin", "full_admin")
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
		t.Errorf("CreateAdminUser() returned displayName %s, want %s", displayName, "Test Admin")
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
	if user.Role == nil || *user.Role != "full_admin" {
		t.Errorf("Created admin user has role %v, want full_admin", user.Role)
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

	invalidRoles := []string{"superuser", "moderator", "guest", "invalid"}

	for _, role := range invalidRoles {
		_, err := userStore.CreateUser("validuser"+role, "Valid Name", "ValidPass123!@#a", role)
		if err == nil {
			t.Errorf("CreateUser() should reject invalid role %q", role)
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
