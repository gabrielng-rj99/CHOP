package tests

import (
	"Licenses-Manager/backend/store"
	"database/sql"
	"testing"
	"time"
)

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

	userStore := store.NewUserStore(db)

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

	userStore := store.NewUserStore(db)

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

	userStore := store.NewUserStore(db)

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

	userStore := store.NewUserStore(db)

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

	userStore := store.NewUserStore(db)

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

	userStore := store.NewUserStore(db)

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

	userStore := store.NewUserStore(db)

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

	userStore := store.NewUserStore(db)

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

	userStore := store.NewUserStore(db)

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
