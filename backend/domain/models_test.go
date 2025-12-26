/*
 * Entity Hub Open Project
 * Copyright (C) 2025 Entity Hub Contributors
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

package domain

import (
	"testing"
	"time"
)

// timePtr is a helper function to convert time.Time to *time.Time for tests
func timePtr(t time.Time) *time.Time {
	return &t
}

// TestAgreementStatus tests the Status() method of Agreement domain model
// This is a critical business rule function that determines agreement state
func TestAgreementStatus(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name           string
		agreement      Agreement
		expectedStatus string
	}{
		// Test: Agreement is active (more than 30 days remaining)
		{
			name: "status - ativo (more than 30 days)",
			agreement: Agreement{
				ID:            "test-1",
				Model:         "Test Agreement",
				ItemKey:       "TEST-KEY-1",
				StartDate:     timePtr(now.AddDate(0, 0, -10)),
				EndDate:       timePtr(now.AddDate(0, 0, 45)), // 45 days from now
				SubcategoryID: "line-1",
				EntityID:      "client-1",
			},
			expectedStatus: "Ativo",
		},
		// Test: Agreement is expiring soon (less than or equal to 30 days)
		{
			name: "status - expirando em breve (exactly 30 days)",
			agreement: Agreement{
				ID:            "test-2",
				Model:         "Test Agreement",
				ItemKey:       "TEST-KEY-2",
				StartDate:     timePtr(now.AddDate(0, 0, -10)),
				EndDate:       timePtr(now.AddDate(0, 0, 30)), // exactly 30 days from now
				SubcategoryID: "line-1",
				EntityID:      "client-1",
			},
			expectedStatus: "Expirando em Breve",
		},
		// Test: Agreement is expiring soon (15 days remaining)
		{
			name: "status - expirando em breve (15 days)",
			agreement: Agreement{
				ID:            "test-3",
				Model:         "Test Agreement",
				ItemKey:       "TEST-KEY-3",
				StartDate:     timePtr(now.AddDate(0, 0, -10)),
				EndDate:       timePtr(now.AddDate(0, 0, 15)), // 15 days from now
				SubcategoryID: "line-1",
				EntityID:      "client-1",
			},
			expectedStatus: "Expirando em Breve",
		},
		// Test: Agreement is expiring soon (1 day remaining)
		{
			name: "status - expirando em breve (1 day)",
			agreement: Agreement{
				ID:            "test-4",
				Model:         "Test Agreement",
				ItemKey:       "TEST-KEY-4",
				StartDate:     timePtr(now.AddDate(0, 0, -10)),
				EndDate:       timePtr(now.AddDate(0, 0, 1)), // 1 day from now
				SubcategoryID: "line-1",
				EntityID:      "client-1",
			},
			expectedStatus: "Expirando em Breve",
		},
		// Test: Agreement has expired (past end date)
		{
			name: "status - expirado (past end date)",
			agreement: Agreement{
				ID:            "test-5",
				Model:         "Test Agreement",
				ItemKey:       "TEST-KEY-5",
				StartDate:     timePtr(now.AddDate(0, 0, -30)),
				EndDate:       timePtr(now.AddDate(0, 0, -5)), // 5 days ago
				SubcategoryID: "line-1",
				EntityID:      "client-1",
			},
			expectedStatus: "Expirado",
		},
		// Test: Agreement just expired (yesterday)
		{
			name: "status - expirado (yesterday)",
			agreement: Agreement{
				ID:            "test-6",
				Model:         "Test Agreement",
				ItemKey:       "TEST-KEY-6",
				StartDate:     timePtr(now.AddDate(0, 0, -30)),
				EndDate:       timePtr(now.AddDate(0, 0, -1)), // yesterday
				SubcategoryID: "line-1",
				EntityID:      "client-1",
			},
			expectedStatus: "Expirado",
		},
		// Test: Agreement expires far in the future (100+ days)
		{
			name: "status - ativo (100+ days)",
			agreement: Agreement{
				ID:            "test-7",
				Model:         "Test Agreement",
				ItemKey:       "TEST-KEY-7",
				StartDate:     timePtr(now.AddDate(0, 0, -10)),
				EndDate:       timePtr(now.AddDate(0, 0, 365)), // 1 year from now
				SubcategoryID: "line-1",
				EntityID:      "client-1",
			},
			expectedStatus: "Ativo",
		},
		// Test: Agreement expires in 31 days (should be ativo, not expiring soon)
		{
			name: "status - ativo (31 days)",
			agreement: Agreement{
				ID:            "test-8",
				Model:         "Test Agreement",
				ItemKey:       "TEST-KEY-8",
				StartDate:     timePtr(now.AddDate(0, 0, -10)),
				EndDate:       timePtr(now.AddDate(0, 0, 31)), // 31 days from now
				SubcategoryID: "line-1",
				EntityID:      "client-1",
			},
			expectedStatus: "Ativo",
		},
		// Test: Agreement starts today
		{
			name: "status - ativo (starts today)",
			agreement: Agreement{
				ID:            "test-9",
				Model:         "Test Agreement",
				ItemKey:       "TEST-KEY-9",
				StartDate:     timePtr(now),
				EndDate:       timePtr(now.AddDate(0, 0, 60)), // 60 days from now
				SubcategoryID: "line-1",
				EntityID:      "client-1",
			},
			expectedStatus: "Ativo",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status := tt.agreement.Status()
			if status != tt.expectedStatus {
				t.Errorf("expected status '%s', got '%s'", tt.expectedStatus, status)
			}
		})
	}
}

// TestAgreementStatusBoundaryConditions tests edge cases and boundary conditions
func TestAgreementStatusBoundaryConditions(t *testing.T) {
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
			agreement := Agreement{
				ID:            "test",
				Model:         "Test",
				ItemKey:       "TEST-KEY",
				StartDate:     timePtr(now.AddDate(0, 0, -10)),
				EndDate:       timePtr(tt.endDate),
				SubcategoryID: "line-1",
				EntityID:      "client-1",
			}
			status := agreement.Status()
			if status != tt.expectedStatus {
				t.Errorf("expected status '%s', got '%s'", tt.expectedStatus, status)
			}
		})
	}
}

// TestClientModel tests the Entity domain model
func TestClientModel(t *testing.T) {
	t.Run("client model structure", func(t *testing.T) {
		regID := "12345678000180"
		entity := Entity{
			ID:             "test-id",
			Name:           "Test Entity",
			RegistrationID: &regID,
			Status:         "ativo",
			CreatedAt:      time.Now(),
		}

		if entity.ID != "test-id" {
			t.Errorf("expected ID 'test-id', got '%s'", entity.ID)
		}
		if entity.Name != "Test Entity" {
			t.Errorf("expected Name 'Test Entity', got '%s'", entity.Name)
		}
		if entity.RegistrationID == nil || *entity.RegistrationID != "12345678000180" {
			t.Errorf("expected RegistrationID '12345678000180', got '%v'", entity.RegistrationID)
		}
	})

	t.Run("client with archived_at", func(t *testing.T) {
		archivedTime := time.Now()
		regID := "12345678000180"
		entity := Entity{
			ID:             "test-id",
			Name:           "Test Entity",
			RegistrationID: &regID,
			Status:         "ativo",
			CreatedAt:      time.Now(),
			ArchivedAt:     &archivedTime,
		}

		if entity.ArchivedAt == nil {
			t.Error("expected ArchivedAt to be set")
		}
		if entity.ArchivedAt.Unix() != archivedTime.Unix() {
			t.Errorf("expected ArchivedAt to match")
		}
	})
}

// TestUserModel tests the User domain model
func TestUserModel(t *testing.T) {
	t.Run("user model structure", func(t *testing.T) {
		username := "testuser"
		displayName := "Test User"
		role := "user"
		user := User{
			ID:           "test-id",
			Username:     &username,
			DisplayName:  &displayName,
			PasswordHash: "hashed-password",
			CreatedAt:    time.Now(),
			Role:         &role,
		}

		if user.ID != "test-id" {
			t.Errorf("expected ID 'test-id', got '%s'", user.ID)
		}
		if user.Username == nil || *user.Username != "testuser" {
			t.Errorf("expected Username 'testuser', got '%v'", user.Username)
		}
		if user.Role == nil || *user.Role != "user" {
			t.Errorf("expected Role 'user', got '%v'", user.Role)
		}
	})

	t.Run("user with lock fields", func(t *testing.T) {
		lockedTime := time.Now().Add(1 * time.Hour)
		username := "testuser"
		displayName := "Test User"
		role := "admin"
		user := User{
			ID:             "test-id",
			Username:       &username,
			DisplayName:    &displayName,
			PasswordHash:   "hashed-password",
			CreatedAt:      time.Now(),
			Role:           &role,
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

// TestDependentModel tests the SubEntity domain model
func TestDependentModel(t *testing.T) {
	subEntity := SubEntity{
		ID:       "dependent-1",
		Name:     "Test SubEntity",
		EntityID: "client-1",
	}

	if subEntity.ID != "dependent-1" {
		t.Errorf("expected ID 'dependent-1', got '%s'", subEntity.ID)
	}
	if subEntity.Name != "Test SubEntity" {
		t.Errorf("expected Name 'Test SubEntity', got '%s'", subEntity.Name)
	}
	if subEntity.EntityID != "client-1" {
		t.Errorf("expected EntityID 'client-1', got '%s'", subEntity.EntityID)
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

// TestLineModel tests the Subcategory domain model
func TestLineModel(t *testing.T) {
	line := Subcategory{
		ID:         "line-1",
		Name:       "Windows Server",
		CategoryID: "category-1",
	}

	if line.ID != "line-1" {
		t.Errorf("expected ID 'line-1', got '%s'", line.ID)
	}
	if line.Name != "Windows Server" {
		t.Errorf("expected Subcategory 'Windows Server', got '%s'", line.Name)
	}
	if line.CategoryID != "category-1" {
		t.Errorf("expected CategoryID 'category-1', got '%s'", line.CategoryID)
	}
}
