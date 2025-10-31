package domain

import (
	"testing"
	"time"
)

// TestContractStatus tests the Status() method of Contract domain model
// This is a critical business rule function that determines contract state
func TestContractStatus(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name           string
		contract       Contract
		expectedStatus string
	}{
		// Test: Contract is active (more than 30 days remaining)
		{
			name: "status - ativo (more than 30 days)",
			contract: Contract{
				ID:         "test-1",
				Model:      "Test Contract",
				ProductKey: "TEST-KEY-1",
				StartDate:  now.AddDate(0, 0, -10),
				EndDate:    now.AddDate(0, 0, 45), // 45 days from now
				LineID:     "line-1",
				ClientID:   "client-1",
			},
			expectedStatus: "Ativo",
		},
		// Test: Contract is expiring soon (less than or equal to 30 days)
		{
			name: "status - expirando em breve (exactly 30 days)",
			contract: Contract{
				ID:         "test-2",
				Model:      "Test Contract",
				ProductKey: "TEST-KEY-2",
				StartDate:  now.AddDate(0, 0, -10),
				EndDate:    now.AddDate(0, 0, 30), // exactly 30 days from now
				LineID:     "line-1",
				ClientID:   "client-1",
			},
			expectedStatus: "Expirando em Breve",
		},
		// Test: Contract is expiring soon (15 days remaining)
		{
			name: "status - expirando em breve (15 days)",
			contract: Contract{
				ID:         "test-3",
				Model:      "Test Contract",
				ProductKey: "TEST-KEY-3",
				StartDate:  now.AddDate(0, 0, -10),
				EndDate:    now.AddDate(0, 0, 15), // 15 days from now
				LineID:     "line-1",
				ClientID:   "client-1",
			},
			expectedStatus: "Expirando em Breve",
		},
		// Test: Contract is expiring soon (1 day remaining)
		{
			name: "status - expirando em breve (1 day)",
			contract: Contract{
				ID:         "test-4",
				Model:      "Test Contract",
				ProductKey: "TEST-KEY-4",
				StartDate:  now.AddDate(0, 0, -10),
				EndDate:    now.AddDate(0, 0, 1), // 1 day from now
				LineID:     "line-1",
				ClientID:   "client-1",
			},
			expectedStatus: "Expirando em Breve",
		},
		// Test: Contract has expired (past end date)
		{
			name: "status - expirado (past end date)",
			contract: Contract{
				ID:         "test-5",
				Model:      "Test Contract",
				ProductKey: "TEST-KEY-5",
				StartDate:  now.AddDate(0, 0, -30),
				EndDate:    now.AddDate(0, 0, -5), // 5 days ago
				LineID:     "line-1",
				ClientID:   "client-1",
			},
			expectedStatus: "Expirado",
		},
		// Test: Contract just expired (yesterday)
		{
			name: "status - expirado (yesterday)",
			contract: Contract{
				ID:         "test-6",
				Model:      "Test Contract",
				ProductKey: "TEST-KEY-6",
				StartDate:  now.AddDate(0, 0, -30),
				EndDate:    now.AddDate(0, 0, -1), // yesterday
				LineID:     "line-1",
				ClientID:   "client-1",
			},
			expectedStatus: "Expirado",
		},
		// Test: Contract expires far in the future (100+ days)
		{
			name: "status - ativo (100+ days)",
			contract: Contract{
				ID:         "test-7",
				Model:      "Test Contract",
				ProductKey: "TEST-KEY-7",
				StartDate:  now.AddDate(0, 0, -10),
				EndDate:    now.AddDate(0, 0, 365), // 1 year from now
				LineID:     "line-1",
				ClientID:   "client-1",
			},
			expectedStatus: "Ativo",
		},
		// Test: Contract expires in 31 days (should be ativo, not expiring soon)
		{
			name: "status - ativo (31 days)",
			contract: Contract{
				ID:         "test-8",
				Model:      "Test Contract",
				ProductKey: "TEST-KEY-8",
				StartDate:  now.AddDate(0, 0, -10),
				EndDate:    now.AddDate(0, 0, 31), // 31 days from now
				LineID:     "line-1",
				ClientID:   "client-1",
			},
			expectedStatus: "Ativo",
		},
		// Test: Contract starts today
		{
			name: "status - ativo (starts today)",
			contract: Contract{
				ID:         "test-9",
				Model:      "Test Contract",
				ProductKey: "TEST-KEY-9",
				StartDate:  now,
				EndDate:    now.AddDate(0, 0, 60), // 60 days from now
				LineID:     "line-1",
				ClientID:   "client-1",
			},
			expectedStatus: "Ativo",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status := tt.contract.Status()
			if status != tt.expectedStatus {
				t.Errorf("expected status '%s', got '%s'", tt.expectedStatus, status)
			}
		})
	}
}

// TestContractStatusBoundaryConditions tests edge cases and boundary conditions
func TestContractStatusBoundaryConditions(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name           string
		endDate        time.Time
		expectedStatus string
	}{
		// Just before 30 day window (31 days from now)
		{
			name:           "boundary - 31 days from now (just outside window)",
			endDate:        now.AddDate(0, 0, 31),
			expectedStatus: "Ativo",
		},
		// Exactly at 30 day window
		{
			name:           "boundary - 30 days from now (exactly at window)",
			endDate:        now.AddDate(0, 0, 30),
			expectedStatus: "Expirando em Breve",
		},
		// Just inside 30 day window (29 days)
		{
			name:           "boundary - 29 days from now (inside window)",
			endDate:        now.AddDate(0, 0, 29),
			expectedStatus: "Expirando em Breve",
		},
		// Exactly today's end of day (should be expired)
		{
			name:           "boundary - expired today",
			endDate:        now.Add(-1 * time.Nanosecond), // Just before now
			expectedStatus: "Expirado",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			contract := Contract{
				ID:         "test",
				Model:      "Test",
				ProductKey: "TEST-KEY",
				StartDate:  now.AddDate(0, 0, -10),
				EndDate:    tt.endDate,
				LineID:     "line-1",
				ClientID:   "client-1",
			}
			status := contract.Status()
			if status != tt.expectedStatus {
				t.Errorf("expected status '%s', got '%s'", tt.expectedStatus, status)
			}
		})
	}
}

// TestClientModel tests the Client domain model
func TestClientModel(t *testing.T) {
	t.Run("client model structure", func(t *testing.T) {
		client := Client{
			ID:             "test-id",
			Name:           "Test Client",
			RegistrationID: "12345678000180",
		}

		if client.ID != "test-id" {
			t.Errorf("expected ID 'test-id', got '%s'", client.ID)
		}
		if client.Name != "Test Client" {
			t.Errorf("expected Name 'Test Client', got '%s'", client.Name)
		}
		if client.RegistrationID != "12345678000180" {
			t.Errorf("expected RegistrationID '12345678000180', got '%s'", client.RegistrationID)
		}
	})

	t.Run("client with archived_at", func(t *testing.T) {
		archivedTime := time.Now()
		client := Client{
			ID:             "test-id",
			Name:           "Test Client",
			RegistrationID: "12345678000180",
			ArchivedAt:     &archivedTime,
		}

		if client.ArchivedAt == nil {
			t.Error("expected ArchivedAt to be set")
		}
		if client.ArchivedAt.Unix() != archivedTime.Unix() {
			t.Errorf("expected ArchivedAt to match")
		}
	})
}

// TestUserModel tests the User domain model
func TestUserModel(t *testing.T) {
	t.Run("user model structure", func(t *testing.T) {
		user := User{
			ID:           "test-id",
			Username:     "testuser",
			DisplayName:  "Test User",
			PasswordHash: "hashed-password",
			CreatedAt:    time.Now(),
			Role:         "user",
		}

		if user.ID != "test-id" {
			t.Errorf("expected ID 'test-id', got '%s'", user.ID)
		}
		if user.Username != "testuser" {
			t.Errorf("expected Username 'testuser', got '%s'", user.Username)
		}
		if user.Role != "user" {
			t.Errorf("expected Role 'user', got '%s'", user.Role)
		}
	})

	t.Run("user with lock fields", func(t *testing.T) {
		lockedTime := time.Now().Add(1 * time.Hour)
		user := User{
			ID:             "test-id",
			Username:       "testuser",
			DisplayName:    "Test User",
			PasswordHash:   "hashed-password",
			CreatedAt:      time.Now(),
			Role:           "admin",
			FailedAttempts: 3,
			LockLevel:      1,
			LockedUntil:    &lockedTime,
		}

		if user.FailedAttempts != 3 {
			t.Errorf("expected FailedAttempts 3, got %d", user.FailedAttempts)
		}
		if user.LockLevel != 1 {
			t.Errorf("expected LockLevel 1, got %d", user.LockLevel)
		}
		if user.LockedUntil == nil {
			t.Error("expected LockedUntil to be set")
		}
	})
}

// TestDependentModel tests the Dependent domain model
func TestDependentModel(t *testing.T) {
	dependent := Dependent{
		ID:       "dependent-1",
		Name:     "Test Dependent",
		ClientID: "client-1",
	}

	if dependent.ID != "dependent-1" {
		t.Errorf("expected ID 'dependent-1', got '%s'", dependent.ID)
	}
	if dependent.Name != "Test Dependent" {
		t.Errorf("expected Name 'Test Dependent', got '%s'", dependent.Name)
	}
	if dependent.ClientID != "client-1" {
		t.Errorf("expected ClientID 'client-1', got '%s'", dependent.ClientID)
	}
}

// TestCategoryModel tests the Category domain model
func TestCategoryModel(t *testing.T) {
	category := Category{
		ID:   "category-1",
		Name: "Software",
	}

	if category.ID != "category-1" {
		t.Errorf("expected ID 'category-1', got '%s'", category.ID)
	}
	if category.Name != "Software" {
		t.Errorf("expected Name 'Software', got '%s'", category.Name)
	}
}

// TestLineModel tests the Line domain model
func TestLineModel(t *testing.T) {
	line := Line{
		ID:         "line-1",
		Line:       "Windows Server",
		CategoryID: "category-1",
	}

	if line.ID != "line-1" {
		t.Errorf("expected ID 'line-1', got '%s'", line.ID)
	}
	if line.Line != "Windows Server" {
		t.Errorf("expected Line 'Windows Server', got '%s'", line.Line)
	}
	if line.CategoryID != "category-1" {
		t.Errorf("expected CategoryID 'category-1', got '%s'", line.CategoryID)
	}
}
