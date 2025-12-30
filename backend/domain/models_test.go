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

package domain

import (
	"testing"
	"time"
)

// timePtr is a helper function to convert time.Time to *time.Time for tests
func timePtr(t time.Time) *time.Time {
	return &t
}

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
				ID:            "test-1",
				Model:         "Test Contract",
				ItemKey:       "TEST-KEY-1",
				StartDate:     timePtr(now.AddDate(0, 0, -10)),
				EndDate:       timePtr(now.AddDate(0, 0, 45)), // 45 days from now
				SubcategoryID: "line-1",
				ClientID:      "client-1",
			},
			expectedStatus: "Ativo",
		},
		// Test: Contract is expiring soon (less than or equal to 30 days)
		{
			name: "status - expirando em breve (exactly 30 days)",
			contract: Contract{
				ID:            "test-2",
				Model:         "Test Contract",
				ItemKey:       "TEST-KEY-2",
				StartDate:     timePtr(now.AddDate(0, 0, -10)),
				EndDate:       timePtr(now.AddDate(0, 0, 30)), // exactly 30 days from now
				SubcategoryID: "line-1",
				ClientID:      "client-1",
			},
			expectedStatus: "Expirando em Breve",
		},
		// Test: Contract is expiring soon (15 days remaining)
		{
			name: "status - expirando em breve (15 days)",
			contract: Contract{
				ID:            "test-3",
				Model:         "Test Contract",
				ItemKey:       "TEST-KEY-3",
				StartDate:     timePtr(now.AddDate(0, 0, -10)),
				EndDate:       timePtr(now.AddDate(0, 0, 15)), // 15 days from now
				SubcategoryID: "line-1",
				ClientID:      "client-1",
			},
			expectedStatus: "Expirando em Breve",
		},
		// Test: Contract is expiring soon (1 day remaining)
		{
			name: "status - expirando em breve (1 day)",
			contract: Contract{
				ID:            "test-4",
				Model:         "Test Contract",
				ItemKey:       "TEST-KEY-4",
				StartDate:     timePtr(now.AddDate(0, 0, -10)),
				EndDate:       timePtr(now.AddDate(0, 0, 1)), // 1 day from now
				SubcategoryID: "line-1",
				ClientID:      "client-1",
			},
			expectedStatus: "Expirando em Breve",
		},
		// Test: Contract has expired (past end date)
		{
			name: "status - expirado (past end date)",
			contract: Contract{
				ID:            "test-5",
				Model:         "Test Contract",
				ItemKey:       "TEST-KEY-5",
				StartDate:     timePtr(now.AddDate(0, 0, -30)),
				EndDate:       timePtr(now.AddDate(0, 0, -5)), // 5 days ago
				SubcategoryID: "line-1",
				ClientID:      "client-1",
			},
			expectedStatus: "Expirado",
		},
		// Test: Contract just expired (yesterday)
		{
			name: "status - expirado (yesterday)",
			contract: Contract{
				ID:            "test-6",
				Model:         "Test Contract",
				ItemKey:       "TEST-KEY-6",
				StartDate:     timePtr(now.AddDate(0, 0, -30)),
				EndDate:       timePtr(now.AddDate(0, 0, -1)), // yesterday
				SubcategoryID: "line-1",
				ClientID:      "client-1",
			},
			expectedStatus: "Expirado",
		},
		// Test: Contract expires far in the future (100+ days)
		{
			name: "status - ativo (100+ days)",
			contract: Contract{
				ID:            "test-7",
				Model:         "Test Contract",
				ItemKey:       "TEST-KEY-7",
				StartDate:     timePtr(now.AddDate(0, 0, -10)),
				EndDate:       timePtr(now.AddDate(0, 0, 365)), // 1 year from now
				SubcategoryID: "line-1",
				ClientID:      "client-1",
			},
			expectedStatus: "Ativo",
		},
		// Test: Contract expires in 31 days (should be ativo, not expiring soon)
		{
			name: "status - ativo (31 days)",
			contract: Contract{
				ID:            "test-8",
				Model:         "Test Contract",
				ItemKey:       "TEST-KEY-8",
				StartDate:     timePtr(now.AddDate(0, 0, -10)),
				EndDate:       timePtr(now.AddDate(0, 0, 31)), // 31 days from now
				SubcategoryID: "line-1",
				ClientID:      "client-1",
			},
			expectedStatus: "Ativo",
		},
		// Test: Contract starts today
		{
			name: "status - ativo (starts today)",
			contract: Contract{
				ID:            "test-9",
				Model:         "Test Contract",
				ItemKey:       "TEST-KEY-9",
				StartDate:     timePtr(now),
				EndDate:       timePtr(now.AddDate(0, 0, 60)), // 60 days from now
				SubcategoryID: "line-1",
				ClientID:      "client-1",
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
				ID:            "test",
				Model:         "Test",
				ItemKey:       "TEST-KEY",
				StartDate:     timePtr(now.AddDate(0, 0, -10)),
				EndDate:       timePtr(tt.endDate),
				SubcategoryID: "line-1",
				ClientID:      "client-1",
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
		regID := "12345678000180"
		client := Client{
			ID:             "test-id",
			Name:           "Test Client",
			RegistrationID: &regID,
			Status:         "ativo",
			CreatedAt:      time.Now(),
		}

		if client.ID != "test-id" {
			t.Errorf("expected ID 'test-id', got '%s'", client.ID)
		}
		if client.Name != "Test Client" {
			t.Errorf("expected Name 'Test Client', got '%s'", client.Name)
		}
		if client.RegistrationID == nil || *client.RegistrationID != "12345678000180" {
			t.Errorf("expected RegistrationID '12345678000180', got '%v'", client.RegistrationID)
		}
	})

	t.Run("client with archived_at", func(t *testing.T) {
		archivedTime := time.Now()
		regID := "12345678000180"
		client := Client{
			ID:             "test-id",
			Name:           "Test Client",
			RegistrationID: &regID,
			Status:         "ativo",
			CreatedAt:      time.Now(),
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

// TestAffiliateModel tests the Affiliate domain model
func TestAffiliateModel(t *testing.T) {
	affiliate := Affiliate{
		ID:       "affiliate-1",
		Name:     "Test Affiliate",
		ClientID: "client-1",
	}

	if affiliate.ID != "affiliate-1" {
		t.Errorf("expected ID 'affiliate-1', got '%s'", affiliate.ID)
	}
	if affiliate.Name != "Test Affiliate" {
		t.Errorf("expected Name 'Test Affiliate', got '%s'", affiliate.Name)
	}
	if affiliate.ClientID != "client-1" {
		t.Errorf("expected ClientID 'client-1', got '%s'", affiliate.ClientID)
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

// TestSubcategoryModel tests the Subcategory domain model
func TestSubcategoryModel(t *testing.T) {
	subcategory := Subcategory{
		ID:         "line-1",
		Name:       "Windows Server",
		CategoryID: "category-1",
	}

	if subcategory.ID != "line-1" {
		t.Errorf("expected ID 'line-1', got '%s'", subcategory.ID)
	}
	if subcategory.Name != "Windows Server" {
		t.Errorf("expected Subcategory 'Windows Server', got '%s'", subcategory.Name)
	}
	if subcategory.CategoryID != "category-1" {
		t.Errorf("expected CategoryID 'category-1', got '%s'", subcategory.CategoryID)
	}
}
