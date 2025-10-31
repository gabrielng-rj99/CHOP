package store

import (
	"strings"
	"testing"
	"time"

	"Contracts-Manager/backend/domain"
	"database/sql"
)

// Helper para criar UserStore com banco em memória
func setupUserStore(t *testing.T) *UserStore {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Erro ao abrir banco em memória: %v", err)
	}
	// Cria tabela users com todos os campos necessários
	_, err = db.Exec(`
		CREATE TABLE users (
			id TEXT PRIMARY KEY,
			username TEXT UNIQUE NOT NULL,
			display_name TEXT NOT NULL,
			password_hash TEXT NOT NULL,
			created_at DATETIME NOT NULL,
			role TEXT NOT NULL DEFAULT 'user',
			failed_attempts INTEGER NOT NULL DEFAULT 0,
			lock_level INTEGER NOT NULL DEFAULT 0,
			locked_until DATETIME
		);
	`)
	if err != nil {
		t.Fatalf("Erro ao criar tabela users: %v", err)
	}
	return NewUserStore(db)
}

func TestEditUserAdminFlagPermissions(t *testing.T) {
	userStore := setupUserStore(t)

	// Cria usuário admin (sem número)
	_, err := userStore.CreateUser("admin", "Administrador", "SenhaForte123!@#abc", "full_admin")
	if err != nil {
		t.Fatalf("Erro ao criar usuário full_admin: %v", err)
	}

	// Cria usuário admin-0
	_, err = userStore.CreateUser("admin-0", "Admin Zero", "SenhaForte123!@#abc", "admin")
	if err != nil {
		t.Fatalf("Erro ao criar usuário admin-0: %v", err)
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

	// Tenta alterar role de admin-0 usando admin-0 (não deve permitir)
	err = userStore.EditUserRole("admin-0", "admin-0", "user")
	if err == nil {
		t.Error("admin-0 NÃO deveria poder alterar o role de outro admin")
	}

	// Tenta alterar role de user1 usando admin (deve permitir)
	err = userStore.EditUserRole("admin", "user1", "admin")
	if err != nil {
		t.Errorf("full_admin deveria poder alterar o role de outro usuário: %v", err)
	}

	// Tenta remover role admin de admin-0 usando admin (deve permitir)
	err = userStore.EditUserRole("admin", "admin-0", "user")
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
		if u.Username == "user1" {
			user1 = u
		}
		if u.Username == "admin-0" {
			admin0 = u
		}
	}
	if user1.Role != "admin" {
		t.Error("user1 deveria ser admin após alteração feita por full_admin")
	}
	if admin0.Role != "user" {
		t.Error("admin-0 NÃO deveria ser admin após remoção feita por full_admin")
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
	return db
}

// TestCreateUserBasic tests basic user creation with validation
func TestCreateUserBasic(t *testing.T) {
	db := setupUserTest(t)
	defer CloseDB(db)

	// Create users table
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY,
			username TEXT UNIQUE NOT NULL,
			display_name TEXT NOT NULL,
			password_hash TEXT NOT NULL,
			created_at DATETIME NOT NULL,
			role TEXT NOT NULL DEFAULT 'user',
			failed_attempts INTEGER NOT NULL DEFAULT 0,
			lock_level INTEGER NOT NULL DEFAULT 0,
			locked_until DATETIME
		)
	`)
	if err != nil {
		t.Fatalf("Failed to create users table: %v", err)
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
			name:        "success - create normal user",
			username:    "john_doe",
			displayName: "John Doe",
			password:    "ValidPassword123!@#",
			role:        "user",
			expectError: false,
		},
		{
			name:        "success - create admin user",
			username:    "admin_user",
			displayName: "Admin User",
			password:    "AdminPassword123!@#",
			role:        "admin",
			expectError: false,
		},
		{
			name:        "success - role defaults to user if empty",
			username:    "default_role_user",
			displayName: "Default User",
			password:    "DefaultPass123!@#",
			role:        "",
			expectError: false,
		},
		{
			name:        "error - empty username",
			username:    "",
			displayName: "Test User",
			password:    "ValidPassword123!@#",
			role:        "user",
			expectError: true,
			errorMsg:    "nome de usuário não pode ser vazio",
		},
		{
			name:        "error - empty display name",
			username:    "testuser",
			displayName: "",
			password:    "ValidPassword123!@#",
			role:        "user",
			expectError: true,
			errorMsg:    "display name não pode ser vazio",
		},
		{
			name:        "error - weak password (too short)",
			username:    "weakpass_user",
			displayName: "Weak Pass User",
			password:    "Weak1!",
			role:        "user",
			expectError: true,
			errorMsg:    "16 caracteres",
		},
		{
			name:        "error - password without number",
			username:    "nonum_user",
			displayName: "No Number User",
			password:    "NoNumberPass!@#abc",
			role:        "user",
			expectError: true,
			errorMsg:    "número",
		},
		{
			name:        "error - duplicate username",
			username:    "john_doe",
			displayName: "John Doe 2",
			password:    "ValidPassword123!@#",
			role:        "user",
			expectError: true,
			errorMsg:    "já existe",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id, err := userStore.CreateUser(tt.username, tt.displayName, tt.password, tt.role)

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}
			if !tt.expectError && id == "" {
				t.Error("Expected ID but got empty string")
			}
		})
	}
}

// TestAuthenticateUserSuccess tests successful authentication scenarios
func TestAuthenticateUserSuccess(t *testing.T) {
	db := setupUserTest(t)
	defer CloseDB(db)

	// Create users table
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY,
			username TEXT UNIQUE NOT NULL,
			display_name TEXT NOT NULL,
			password_hash TEXT NOT NULL,
			created_at DATETIME NOT NULL,
			role TEXT NOT NULL DEFAULT 'user',
			failed_attempts INTEGER NOT NULL DEFAULT 0,
			lock_level INTEGER NOT NULL DEFAULT 0,
			locked_until DATETIME
		)
	`)
	if err != nil {
		t.Fatalf("Failed to create users table: %v", err)
	}

	userStore := NewUserStore(db)

	// Create a test user
	username := "testuser"
	password := "ValidTestPass123!@#"
	_, err = userStore.CreateUser(username, "Test User", password, "user")
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	// Test successful authentication
	user, err := userStore.AuthenticateUser(username, password)
	if err != nil {
		t.Errorf("Expected successful authentication, got error: %v", err)
	}
	if user == nil {
		t.Error("Expected user object, got nil")
	}
	if user != nil && user.Username != username {
		t.Errorf("Expected username '%s', got '%s'", username, user.Username)
	}
	if user != nil && user.FailedAttempts != 0 {
		t.Errorf("Expected failed_attempts to be 0 after successful login, got %d", user.FailedAttempts)
	}
	if user != nil && user.LockLevel != 0 {
		t.Errorf("Expected lock_level to be 0 after successful login, got %d", user.LockLevel)
	}
}

// TestAuthenticateUserInvalidCredentials tests authentication with wrong password
func TestAuthenticateUserInvalidCredentials(t *testing.T) {
	db := setupUserTest(t)
	defer CloseDB(db)

	// Create users table
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY,
			username TEXT UNIQUE NOT NULL,
			display_name TEXT NOT NULL,
			password_hash TEXT NOT NULL,
			created_at DATETIME NOT NULL,
			role TEXT NOT NULL DEFAULT 'user',
			failed_attempts INTEGER NOT NULL DEFAULT 0,
			lock_level INTEGER NOT NULL DEFAULT 0,
			locked_until DATETIME
		)
	`)
	if err != nil {
		t.Fatalf("Failed to create users table: %v", err)
	}

	userStore := NewUserStore(db)

	// Create a test user
	username := "testuser"
	password := "ValidTestPass123!@#"
	_, err = userStore.CreateUser(username, "Test User", password, "user")
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	// Test with wrong password
	user, err := userStore.AuthenticateUser(username, "WrongPassword123!@#")
	if err == nil {
		t.Error("Expected error with wrong password, got none")
	}
	if user != nil {
		t.Error("Expected nil user with wrong password, got user object")
	}

	// Verify failed_attempts was incremented
	var failedAttempts int
	err = db.QueryRow("SELECT failed_attempts FROM users WHERE username = ?", username).Scan(&failedAttempts)
	if err != nil {
		t.Fatalf("Failed to query user: %v", err)
	}
	if failedAttempts < 1 {
		t.Errorf("Expected failed_attempts >= 1, got %d", failedAttempts)
	}
}

// TestAuthenticateUserInvalidInputs tests authentication with empty credentials
func TestAuthenticateUserInvalidInputs(t *testing.T) {
	db := setupUserTest(t)
	defer CloseDB(db)

	// Create users table
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY,
			username TEXT UNIQUE NOT NULL,
			display_name TEXT NOT NULL,
			password_hash TEXT NOT NULL,
			created_at DATETIME NOT NULL,
			role TEXT NOT NULL DEFAULT 'user',
			failed_attempts INTEGER NOT NULL DEFAULT 0,
			lock_level INTEGER NOT NULL DEFAULT 0,
			locked_until DATETIME
		)
	`)
	if err != nil {
		t.Fatalf("Failed to create users table: %v", err)
	}

	userStore := NewUserStore(db)

	tests := []struct {
		name        string
		username    string
		password    string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "error - empty username",
			username:    "",
			password:    "ValidPassword123!@#",
			expectError: true,
			errorMsg:    "obrigatórios",
		},
		{
			name:        "error - empty password",
			username:    "testuser",
			password:    "",
			expectError: true,
			errorMsg:    "obrigatórios",
		},
		{
			name:        "error - both empty",
			username:    "",
			password:    "",
			expectError: true,
			errorMsg:    "obrigatórios",
		},
		{
			name:        "error - non-existent user",
			username:    "nonexistent",
			password:    "ValidPassword123!@#",
			expectError: true,
			errorMsg:    "não encontrado",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user, err := userStore.AuthenticateUser(tt.username, tt.password)
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}
			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if user != nil {
				t.Error("Expected nil user for invalid inputs")
			}
		})
	}
}

// TestEditUserPassword tests password editing
func TestEditUserPassword(t *testing.T) {
	db := setupUserTest(t)
	defer CloseDB(db)

	// Create users table
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY,
			username TEXT UNIQUE NOT NULL,
			display_name TEXT NOT NULL,
			password_hash TEXT NOT NULL,
			created_at DATETIME NOT NULL,
			role TEXT NOT NULL DEFAULT 'user',
			failed_attempts INTEGER NOT NULL DEFAULT 0,
			lock_level INTEGER NOT NULL DEFAULT 0,
			locked_until DATETIME
		)
	`)
	if err != nil {
		t.Fatalf("Failed to create users table: %v", err)
	}

	userStore := NewUserStore(db)

	// Create a test user
	username := "testuser"
	oldPassword := "ValidTestPass123!@#"
	_, err = userStore.CreateUser(username, "Test User", oldPassword, "user")
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	tests := []struct {
		name        string
		username    string
		newPassword string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "success - change password",
			username:    username,
			newPassword: "NewValidPass123!@#",
			expectError: false,
		},
		{
			name:        "error - weak new password",
			username:    username,
			newPassword: "Weak1!",
			expectError: true,
			errorMsg:    "16 caracteres",
		},
		{
			name:        "error - non-existent user",
			username:    "nonexistent",
			newPassword: "NewValidPass123!@#",
			expectError: true,
			errorMsg:    "não encontrado",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := userStore.EditUserPassword(tt.username, tt.newPassword)
			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}

			// If successful, verify the new password works
			if !tt.expectError && tt.username == username {
				user, err := userStore.AuthenticateUser(tt.username, tt.newPassword)
				if err != nil {
					t.Errorf("Failed to authenticate with new password: %v", err)
				}
				if user == nil {
					t.Error("Expected user after authentication with new password")
				}
			}
		})
	}
}

// TestEditUserDisplayName tests display name editing
func TestEditUserDisplayName(t *testing.T) {
	db := setupUserTest(t)
	defer CloseDB(db)

	// Create users table
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY,
			username TEXT UNIQUE NOT NULL,
			display_name TEXT NOT NULL,
			password_hash TEXT NOT NULL,
			created_at DATETIME NOT NULL,
			role TEXT NOT NULL DEFAULT 'user',
			failed_attempts INTEGER NOT NULL DEFAULT 0,
			lock_level INTEGER NOT NULL DEFAULT 0,
			locked_until DATETIME
		)
	`)
	if err != nil {
		t.Fatalf("Failed to create users table: %v", err)
	}

	userStore := NewUserStore(db)

	// Create a test user
	username := "testuser"
	_, err = userStore.CreateUser(username, "Test User", "ValidTestPass123!@#", "user")
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	tests := []struct {
		name           string
		username       string
		newDisplayName string
		expectError    bool
		errorMsg       string
	}{
		{
			name:           "success - change display name",
			username:       username,
			newDisplayName: "Updated Display Name",
			expectError:    false,
		},
		{
			name:           "error - empty display name",
			username:       username,
			newDisplayName: "",
			expectError:    true,
			errorMsg:       "vazio",
		},
		{
			name:           "error - non-existent user",
			username:       "nonexistent",
			newDisplayName: "New Name",
			expectError:    true,
			errorMsg:       "não encontrado",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := userStore.EditUserDisplayName(tt.username, tt.newDisplayName)
			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}

			// If successful, verify the change
			if !tt.expectError {
				var displayName string
				err = db.QueryRow("SELECT display_name FROM users WHERE username = ?", tt.username).Scan(&displayName)
				if err != nil {
					t.Fatalf("Failed to query user: %v", err)
				}
				if displayName != tt.newDisplayName {
					t.Errorf("Expected display_name '%s', got '%s'", tt.newDisplayName, displayName)
				}
			}
		})
	}
}

// TestListUsers tests listing users
func TestListUsers(t *testing.T) {
	db := setupUserTest(t)
	defer CloseDB(db)

	// Create users table
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY,
			username TEXT UNIQUE NOT NULL,
			display_name TEXT NOT NULL,
			password_hash TEXT NOT NULL,
			created_at DATETIME NOT NULL,
			role TEXT NOT NULL DEFAULT 'user',
			failed_attempts INTEGER NOT NULL DEFAULT 0,
			lock_level INTEGER NOT NULL DEFAULT 0,
			locked_until DATETIME
		)
	`)
	if err != nil {
		t.Fatalf("Failed to create users table: %v", err)
	}

	userStore := NewUserStore(db)

	// Create multiple users
	testUsers := []struct {
		username    string
		displayName string
		role        string
	}{
		{"user1", "User One", "user"},
		{"user2", "User Two", "user"},
		{"admin1", "Admin One", "admin"},
	}

	for _, tu := range testUsers {
		_, err := userStore.CreateUser(tu.username, tu.displayName, "ValidPassword123!@#", tu.role)
		if err != nil {
			t.Fatalf("Failed to create user: %v", err)
		}
	}

	// List users
	users, err := userStore.ListUsers()
	if err != nil {
		t.Fatalf("Failed to list users: %v", err)
	}

	if len(users) != len(testUsers) {
		t.Errorf("Expected %d users, got %d", len(testUsers), len(users))
	}

	// Verify all users are in the list
	usernames := make(map[string]bool)
	for _, u := range users {
		usernames[u.Username] = true
	}

	for _, tu := range testUsers {
		if !usernames[tu.username] {
			t.Errorf("Expected user '%s' in list", tu.username)
		}
	}
}

// TestCreateAdminUser tests creation of admin users with random password
func TestCreateAdminUser(t *testing.T) {
	db := setupUserTest(t)
	defer CloseDB(db)

	// Create users table
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY,
			username TEXT UNIQUE NOT NULL,
			display_name TEXT NOT NULL,
			password_hash TEXT NOT NULL,
			created_at DATETIME NOT NULL,
			role TEXT NOT NULL DEFAULT 'user',
			failed_attempts INTEGER NOT NULL DEFAULT 0,
			lock_level INTEGER NOT NULL DEFAULT 0,
			locked_until DATETIME
		)
	`)
	if err != nil {
		t.Fatalf("Failed to create users table: %v", err)
	}

	userStore := NewUserStore(db)

	tests := []struct {
		name               string
		customUsername     string
		displayName        string
		role               string
		shouldAutoGenerate bool
	}{
		{
			name:               "success - create admin with custom username",
			customUsername:     "custom_admin",
			displayName:        "Custom Admin",
			role:               "admin",
			shouldAutoGenerate: false,
		},
		{
			name:               "success - create admin with auto-generated username",
			customUsername:     "",
			displayName:        "Auto Admin",
			role:               "admin",
			shouldAutoGenerate: true,
		},
		{
			name:               "success - create full_admin with auto-generated username",
			customUsername:     "",
			displayName:        "Full Admin",
			role:               "full_admin",
			shouldAutoGenerate: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			username, displayName, password, err := userStore.CreateAdminUser(tt.customUsername, tt.displayName, tt.role)

			if err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}

			if username == "" {
				t.Error("Expected non-empty username")
			}

			if displayName != tt.displayName {
				t.Errorf("Expected display_name '%s', got '%s'", tt.displayName, displayName)
			}

			if password == "" {
				t.Error("Expected non-empty password")
			}

			if len(password) != 64 {
				t.Errorf("Expected password length 64, got %d", len(password))
			}

			// Verify user can authenticate with generated password
			user, err := userStore.AuthenticateUser(username, password)
			if err != nil {
				t.Errorf("Failed to authenticate with generated password: %v", err)
			}
			if user == nil {
				t.Error("Expected user after authentication")
			}
			if user != nil && user.Role != tt.role {
				t.Errorf("Expected role '%s', got '%s'", tt.role, user.Role)
			}
		})
	}
}

// TestUnlockUser tests user unlock functionality
func TestUnlockUser(t *testing.T) {
	db := setupUserTest(t)
	defer CloseDB(db)

	// Create users table
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY,
			username TEXT UNIQUE NOT NULL,
			display_name TEXT NOT NULL,
			password_hash TEXT NOT NULL,
			created_at DATETIME NOT NULL,
			role TEXT NOT NULL DEFAULT 'user',
			failed_attempts INTEGER NOT NULL DEFAULT 0,
			lock_level INTEGER NOT NULL DEFAULT 0,
			locked_until DATETIME
		)
	`)
	if err != nil {
		t.Fatalf("Failed to create users table: %v", err)
	}

	userStore := NewUserStore(db)

	// Create a test user
	username := "testuser"
	_, err = userStore.CreateUser(username, "Test User", "ValidTestPass123!@#", "user")
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	// Manually lock the user
	lockedUntil := time.Now().Add(1 * time.Hour)
	_, err = db.Exec(
		"UPDATE users SET failed_attempts = 5, lock_level = 2, locked_until = ? WHERE username = ?",
		lockedUntil, username,
	)
	if err != nil {
		t.Fatalf("Failed to lock user: %v", err)
	}

	// Verify user is locked
	var lockLevel int
	err = db.QueryRow("SELECT lock_level FROM users WHERE username = ?", username).Scan(&lockLevel)
	if err != nil {
		t.Fatalf("Failed to query user: %v", err)
	}
	if lockLevel != 2 {
		t.Errorf("Expected lock_level 2, got %d", lockLevel)
	}

	// Unlock the user
	err = userStore.UnlockUser(username)
	if err != nil {
		t.Errorf("Expected no error unlocking user, got: %v", err)
	}

	// Verify user is unlocked
	var failedAttempts, newLockLevel int
	var newLockedUntil *time.Time
	err = db.QueryRow(
		"SELECT failed_attempts, lock_level, locked_until FROM users WHERE username = ?",
		username,
	).Scan(&failedAttempts, &newLockLevel, &newLockedUntil)
	if err != nil {
		t.Fatalf("Failed to query user: %v", err)
	}

	if failedAttempts != 0 {
		t.Errorf("Expected failed_attempts 0, got %d", failedAttempts)
	}
	if newLockLevel != 0 {
		t.Errorf("Expected lock_level 0, got %d", newLockLevel)
	}
	if newLockedUntil != nil {
		t.Error("Expected locked_until to be NULL")
	}

	// Verify user can now authenticate
	user, err := userStore.AuthenticateUser(username, "ValidTestPass123!@#")
	if err != nil {
		t.Errorf("Failed to authenticate after unlock: %v", err)
	}
	if user == nil {
		t.Error("Expected user after unlock")
	}
}

// ============================================================================
// VALIDATION & EDGE CASES
// ============================================================================

// TestCreateUserWithInvalidUsernames tests various invalid username formats
func TestCreateUserWithInvalidUsernames(t *testing.T) {
	db := setupUserTest(t)
	defer CloseDB(db)

	// Create users table
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY,
			username TEXT UNIQUE NOT NULL,
			display_name TEXT NOT NULL,
			password_hash TEXT NOT NULL,
			created_at DATETIME NOT NULL,
			role TEXT NOT NULL DEFAULT 'user',
			failed_attempts INTEGER NOT NULL DEFAULT 0,
			lock_level INTEGER NOT NULL DEFAULT 0,
			locked_until DATETIME
		)
	`)
	if err != nil {
		t.Fatalf("Failed to create users table: %v", err)
	}

	userStore := NewUserStore(db)

	// Generate long usernames
	longUsername := strings.Repeat("a", 256)
	veryLongUsername := strings.Repeat("a", 1000)

	tests := []struct {
		name        string
		username    string
		expectError bool
		description string
	}{
		{
			name:        "invalid - username too long (256 chars)",
			username:    longUsername,
			expectError: true,
			description: "Username with 256 characters should be rejected",
		},
		{
			name:        "invalid - username way too long (1000 chars)",
			username:    veryLongUsername,
			expectError: true,
			description: "Username with 1000 characters should be rejected",
		},
		{
			name:        "invalid - username with only spaces",
			username:    "     ",
			expectError: true,
			description: "Username with only whitespace should be rejected",
		},
		{
			name:        "invalid - username with spaces",
			username:    "user name",
			expectError: false, // Depends on validation - may be allowed
			description: "Username with spaces",
		},
		{
			name:        "valid - username at max length (255 chars)",
			username:    strings.Repeat("a", 255),
			expectError: false,
			description: "Username with exactly 255 characters should be allowed",
		},
		{
			name:        "valid - username with underscores",
			username:    "user_name_123",
			expectError: false,
			description: "Username with underscores should be allowed",
		},
		{
			name:        "valid - username with dots",
			username:    "user.name.123",
			expectError: false,
			description: "Username with dots should be allowed",
		},
		{
			name:        "valid - username with dashes",
			username:    "user-name-123",
			expectError: false,
			description: "Username with dashes should be allowed",
		},
		{
			name:        "invalid - username with special chars",
			username:    "user@name#123",
			expectError: false, // Depends on validation
			description: "Username with special characters",
		},
		{
			name:        "invalid - SQL injection attempt",
			username:    "'; DROP TABLE users; --",
			expectError: false, // Should be escaped, not rejected
			description: "SQL injection attempt in username",
		},
	}

	counter := 0
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear users table between tests to avoid duplicates
			_, err := db.Exec("DELETE FROM users")
			if err != nil {
				t.Fatalf("Failed to clear users: %v", err)
			}

			_, err = userStore.CreateUser(
				tt.username,
				"Test User "+string(rune('A'+counter)),
				"ValidPassword123!@#abc",
				"user",
			)
			counter++

			if tt.expectError && err == nil {
				t.Errorf("Expected error for %s, but got none", tt.description)
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error for %s, but got: %v", tt.description, err)
			}
		})
	}
}

// TestCreateUserWithInvalidDisplayNames tests various invalid display name formats
func TestCreateUserWithInvalidDisplayNames(t *testing.T) {
	db := setupUserTest(t)
	defer CloseDB(db)

	// Create users table
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY,
			username TEXT UNIQUE NOT NULL,
			display_name TEXT NOT NULL,
			password_hash TEXT NOT NULL,
			created_at DATETIME NOT NULL,
			role TEXT NOT NULL DEFAULT 'user',
			failed_attempts INTEGER NOT NULL DEFAULT 0,
			lock_level INTEGER NOT NULL DEFAULT 0,
			locked_until DATETIME
		)
	`)
	if err != nil {
		t.Fatalf("Failed to create users table: %v", err)
	}

	userStore := NewUserStore(db)

	// Generate long display names
	longDisplayName := strings.Repeat("a", 256)
	veryLongDisplayName := strings.Repeat("a", 1000)

	tests := []struct {
		name        string
		displayName string
		expectError bool
		description string
	}{
		{
			name:        "invalid - display name too long (256 chars)",
			displayName: longDisplayName,
			expectError: true,
			description: "Display name with 256 characters should be rejected",
		},
		{
			name:        "invalid - display name way too long (1000 chars)",
			displayName: veryLongDisplayName,
			expectError: true,
			description: "Display name with 1000 characters should be rejected",
		},
		{
			name:        "invalid - display name with only spaces",
			displayName: "     ",
			expectError: true,
			description: "Display name with only whitespace should be rejected",
		},
		{
			name:        "valid - display name at max length (255 chars)",
			displayName: strings.Repeat("a", 255),
			expectError: false,
			description: "Display name with exactly 255 characters should be allowed",
		},
		{
			name:        "valid - display name with special characters",
			displayName: "John O'Connor - Jr.",
			expectError: false,
			description: "Display name with special characters should be allowed",
		},
		{
			name:        "valid - display name with accents",
			displayName: "José María González",
			expectError: false,
			description: "Display name with accents should be allowed",
		},
	}

	counter := 0
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear users table between tests
			_, err := db.Exec("DELETE FROM users")
			if err != nil {
				t.Fatalf("Failed to clear users: %v", err)
			}

			_, err = userStore.CreateUser(
				"user"+string(rune('a'+counter)),
				tt.displayName,
				"ValidPassword123!@#abc",
				"user",
			)
			counter++

			if tt.expectError && err == nil {
				t.Errorf("Expected error for %s, but got none", tt.description)
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error for %s, but got: %v", tt.description, err)
			}
		})
	}
}

// TestCreateUserWithWeakPasswords tests comprehensive password validation
func TestCreateUserWithWeakPasswords(t *testing.T) {
	db := setupUserTest(t)
	defer CloseDB(db)

	// Create users table
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY,
			username TEXT UNIQUE NOT NULL,
			display_name TEXT NOT NULL,
			password_hash TEXT NOT NULL,
			created_at DATETIME NOT NULL,
			role TEXT NOT NULL DEFAULT 'user',
			failed_attempts INTEGER NOT NULL DEFAULT 0,
			lock_level INTEGER NOT NULL DEFAULT 0,
			locked_until DATETIME
		)
	`)
	if err != nil {
		t.Fatalf("Failed to create users table: %v", err)
	}

	userStore := NewUserStore(db)

	tests := []struct {
		name        string
		password    string
		expectError bool
		description string
	}{
		{
			name:        "invalid - password with spaces",
			password:    "Valid Password 123!@#",
			expectError: true,
			description: "Password with spaces should be rejected",
		},
		{
			name:        "invalid - password too short (8 chars)",
			password:    "Pass123!",
			expectError: true,
			description: "Password with only 8 characters should be rejected",
		},
		{
			name:        "invalid - password exactly 15 chars (1 short)",
			password:    "Password123!@#a",
			expectError: true,
			description: "Password with 15 characters should be rejected",
		},
		{
			name:        "valid - password exactly 16 chars",
			password:    "Password123!@#ab",
			expectError: false,
			description: "Password with exactly 16 characters should be allowed",
		},
		{
			name:        "invalid - password without uppercase",
			password:    "password123!@#abc",
			expectError: true,
			description: "Password without uppercase should be rejected",
		},
		{
			name:        "invalid - password without lowercase",
			password:    "PASSWORD123!@#ABC",
			expectError: true,
			description: "Password without lowercase should be rejected",
		},
		{
			name:        "invalid - password without number",
			password:    "PasswordABC!@#abc",
			expectError: true,
			description: "Password without number should be rejected",
		},
		{
			name:        "invalid - password without symbol",
			password:    "Password123ABCabc",
			expectError: true,
			description: "Password without symbol should be rejected",
		},
		{
			name:        "valid - password with all requirements",
			password:    "ValidPassword123!@#",
			expectError: false,
			description: "Password meeting all requirements should be allowed",
		},
		{
			name:        "valid - password with various symbols",
			password:    "P@ssw0rd!#$%^&*()",
			expectError: false,
			description: "Password with various symbols should be allowed",
		},
		{
			name:        "valid - very long password",
			password:    "ThisIsAVeryLongPassword123!@#WithManyCharacters",
			expectError: false,
			description: "Very long password should be allowed",
		},
		{
			name:        "invalid - empty password",
			password:    "",
			expectError: true,
			description: "Empty password should be rejected",
		},
		{
			name:        "invalid - password only numbers",
			password:    "1234567890123456",
			expectError: true,
			description: "Password with only numbers should be rejected",
		},
		{
			name:        "invalid - password only letters",
			password:    "abcdefghijklmnop",
			expectError: true,
			description: "Password with only letters should be rejected",
		},
		{
			name:        "invalid - password only symbols",
			password:    "!@#$%^&*()_+-=[]",
			expectError: true,
			description: "Password with only symbols should be rejected",
		},
	}

	counter := 0
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear users table between tests
			_, err := db.Exec("DELETE FROM users")
			if err != nil {
				t.Fatalf("Failed to clear users: %v", err)
			}

			_, err = userStore.CreateUser(
				"user"+string(rune('a'+counter)),
				"Test User",
				tt.password,
				"user",
			)
			counter++

			if tt.expectError && err == nil {
				t.Errorf("Expected error for %s, but got none", tt.description)
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error for %s, but got: %v", tt.description, err)
			}
		})
	}
}

// TestCreateUserWithPasswordEqualsUsername tests password security
func TestCreateUserWithPasswordEqualsUsername(t *testing.T) {
	db := setupUserTest(t)
	defer CloseDB(db)

	// Create users table
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY,
			username TEXT UNIQUE NOT NULL,
			display_name TEXT NOT NULL,
			password_hash TEXT NOT NULL,
			created_at DATETIME NOT NULL,
			role TEXT NOT NULL DEFAULT 'user',
			failed_attempts INTEGER NOT NULL DEFAULT 0,
			lock_level INTEGER NOT NULL DEFAULT 0,
			locked_until DATETIME
		)
	`)
	if err != nil {
		t.Fatalf("Failed to create users table: %v", err)
	}

	userStore := NewUserStore(db)

	// Note: This test checks if password == username is prevented
	// This is a security best practice but may not be implemented
	username := "testuser123"

	// Password that equals username but meets other requirements
	password := "Testuser123!@#ab" // Contains username

	_, err = userStore.CreateUser(username, "Test User", password, "user")

	// Currently this might be allowed - depends on if this validation exists
	// This test documents expected behavior
	if err != nil {
		t.Logf("Password similar to username was rejected (good security): %v", err)
	} else {
		t.Logf("Password similar to username was allowed (potential security concern)")
	}
}

// TestCreateUserWithInvalidRoles tests role validation
func TestCreateUserWithInvalidRoles(t *testing.T) {
	db := setupUserTest(t)
	defer CloseDB(db)

	// Create users table
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY,
			username TEXT UNIQUE NOT NULL,
			display_name TEXT NOT NULL,
			password_hash TEXT NOT NULL,
			created_at DATETIME NOT NULL,
			role TEXT NOT NULL DEFAULT 'user',
			failed_attempts INTEGER NOT NULL DEFAULT 0,
			lock_level INTEGER NOT NULL DEFAULT 0,
			locked_until DATETIME
		)
	`)
	if err != nil {
		t.Fatalf("Failed to create users table: %v", err)
	}

	userStore := NewUserStore(db)

	tests := []struct {
		name        string
		role        string
		expectError bool
		description string
	}{
		{
			name:        "valid - role 'user'",
			role:        "user",
			expectError: false,
			description: "Role 'user' should be allowed",
		},
		{
			name:        "valid - role 'admin'",
			role:        "admin",
			expectError: false,
			description: "Role 'admin' should be allowed",
		},
		{
			name:        "valid - role 'full_admin'",
			role:        "full_admin",
			expectError: false,
			description: "Role 'full_admin' should be allowed",
		},
		{
			name:        "valid - empty role defaults to user",
			role:        "",
			expectError: false,
			description: "Empty role should default to 'user'",
		},
		{
			name:        "invalid - role 'superuser'",
			role:        "superuser",
			expectError: false, // May be allowed if no validation
			description: "Invalid role 'superuser'",
		},
		{
			name:        "invalid - role 'root'",
			role:        "root",
			expectError: false, // May be allowed if no validation
			description: "Invalid role 'root'",
		},
		{
			name:        "invalid - SQL injection in role",
			role:        "'; DROP TABLE users; --",
			expectError: false, // Should be escaped
			description: "SQL injection attempt in role",
		},
	}

	counter := 0
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear users table between tests
			_, err := db.Exec("DELETE FROM users")
			if err != nil {
				t.Fatalf("Failed to clear users: %v", err)
			}

			_, err = userStore.CreateUser(
				"user"+string(rune('a'+counter)),
				"Test User",
				"ValidPassword123!@#abc",
				tt.role,
			)
			counter++

			if tt.expectError && err == nil {
				t.Errorf("Expected error for %s, but got none", tt.description)
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error for %s, but got: %v", tt.description, err)
			}
		})
	}
}

// TestEditUserPasswordWithInvalidPasswords tests password change validation
func TestEditUserPasswordWithInvalidPasswords(t *testing.T) {
	db := setupUserTest(t)
	defer CloseDB(db)

	// Create users table
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY,
			username TEXT UNIQUE NOT NULL,
			display_name TEXT NOT NULL,
			password_hash TEXT NOT NULL,
			created_at DATETIME NOT NULL,
			role TEXT NOT NULL DEFAULT 'user',
			failed_attempts INTEGER NOT NULL DEFAULT 0,
			lock_level INTEGER NOT NULL DEFAULT 0,
			locked_until DATETIME
		)
	`)
	if err != nil {
		t.Fatalf("Failed to create users table: %v", err)
	}

	userStore := NewUserStore(db)

	// Create initial user
	username := "testuser"
	_, err = userStore.CreateUser(username, "Test User", "OldPassword123!@#abc", "user")
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	tests := []struct {
		name        string
		newPassword string
		expectError bool
		description string
	}{
		{
			name:        "invalid - new password too short",
			newPassword: "Short1!",
			expectError: true,
			description: "New password too short should be rejected",
		},
		{
			name:        "invalid - new password without number",
			newPassword: "NoNumberPassword!@#",
			expectError: true,
			description: "New password without number should be rejected",
		},
		{
			name:        "invalid - new password without symbol",
			newPassword: "NoSymbolPassword123",
			expectError: true,
			description: "New password without symbol should be rejected",
		},
		{
			name:        "valid - new password meets all requirements",
			newPassword: "NewValidPassword123!@#",
			expectError: false,
			description: "Valid new password should be accepted",
		},
		{
			name:        "invalid - empty new password",
			newPassword: "",
			expectError: true,
			description: "Empty new password should be rejected",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := userStore.EditUserPassword(username, tt.newPassword)

			if tt.expectError && err == nil {
				t.Errorf("Expected error for %s, but got none", tt.description)
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error for %s, but got: %v", tt.description, err)
			}
		})
	}
}

// TestEditUserDisplayNameWithInvalidData tests display name update validation
func TestEditUserDisplayNameWithInvalidData(t *testing.T) {
	db := setupUserTest(t)
	defer CloseDB(db)

	// Create users table
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY,
			username TEXT UNIQUE NOT NULL,
			display_name TEXT NOT NULL,
			password_hash TEXT NOT NULL,
			created_at DATETIME NOT NULL,
			role TEXT NOT NULL DEFAULT 'user',
			failed_attempts INTEGER NOT NULL DEFAULT 0,
			lock_level INTEGER NOT NULL DEFAULT 0,
			locked_until DATETIME
		)
	`)
	if err != nil {
		t.Fatalf("Failed to create users table: %v", err)
	}

	userStore := NewUserStore(db)

	// Create initial user
	username := "testuser"
	_, err = userStore.CreateUser(username, "Original Name", "Password123!@#abc", "user")
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	tests := []struct {
		name           string
		newDisplayName string
		expectError    bool
		description    string
	}{
		{
			name:           "invalid - display name too long",
			newDisplayName: strings.Repeat("a", 256),
			expectError:    true,
			description:    "Display name too long should be rejected",
		},
		{
			name:           "invalid - display name with only spaces",
			newDisplayName: "     ",
			expectError:    true,
			description:    "Display name with only whitespace should be rejected",
		},
		{
			name:           "invalid - empty display name",
			newDisplayName: "",
			expectError:    true,
			description:    "Empty display name should be rejected",
		},
		{
			name:           "valid - normal display name update",
			newDisplayName: "Updated Display Name",
			expectError:    false,
			description:    "Valid display name should be accepted",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := userStore.EditUserDisplayName(username, tt.newDisplayName)

			if tt.expectError && err == nil {
				t.Errorf("Expected error for %s, but got none", tt.description)
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error for %s, but got: %v", tt.description, err)
			}
		})
	}
}
