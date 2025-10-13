package domain_test

import (
	"testing"
	"time"

	"Licenses-Manager/backend/domain"
)

func TestClientValidations(t *testing.T) {
	t.Run("Valid Client", func(t *testing.T) {
		client := domain.Client{
			ID:             "1",
			Name:           "Test Client",
			RegistrationID: "12.345.678/0001-90",
		}

		if client.Name == "" {
			t.Error("Client name should not be empty")
		}

		if client.RegistrationID == "" {
			t.Error("Client registration ID should not be empty")
		}
	})

	t.Run("Archived Client", func(t *testing.T) {
		now := time.Now()
		client := domain.Client{
			ID:             "1",
			Name:           "Test Client",
			RegistrationID: "12.345.678/0001-90",
			ArchivedAt:     &now,
		}

		if client.ArchivedAt == nil {
			t.Error("Client should be archived")
		}
	})
}

func TestEntityValidations(t *testing.T) {
	t.Run("Valid Entity", func(t *testing.T) {
		entity := domain.Entity{
			ID:       "1",
			Name:     "Test Entity",
			ClientID: "client-1",
		}

		if entity.Name == "" {
			t.Error("Entity name should not be empty")
		}

		if entity.ClientID == "" {
			t.Error("Entity must belong to a client")
		}
	})
}

func TestLicenseValidations(t *testing.T) {
	t.Run("Valid License", func(t *testing.T) {
		now := time.Now()
		future := now.AddDate(0, 1, 0) // 1 month from now

		license := domain.License{
			ID:         "1",
			Model:      "Test License",
			ProductKey: "XXXX-YYYY-ZZZZ",
			StartDate:  now,
			EndDate:    future,
			LineID:     "line-1",
			ClientID:   "client-1",
		}

		if license.Model == "" {
			t.Error("License model should not be empty")
		}

		if license.LineID == "" {
			t.Error("License must have a line")
		}

		if license.ClientID == "" {
			t.Error("License must belong to a client")
		}

		if license.EndDate.Before(license.StartDate) {
			t.Error("License end date must be after start date")
		}
	})

	t.Run("License Status", func(t *testing.T) {
		now := time.Now()
		tests := []struct {
			name     string
			license  domain.License
			expected string
		}{
			{
				name: "Active License",
				license: domain.License{
					StartDate: now,
					EndDate:   now.AddDate(0, 2, 0), // 2 months ahead
				},
				expected: "Ativa",
			},
			{
				name: "Expiring Soon License",
				license: domain.License{
					StartDate: now,
					EndDate:   now.AddDate(0, 0, 15), // 15 days ahead
				},
				expected: "Expirando em Breve",
			},
			{
				name: "Expired License",
				license: domain.License{
					StartDate: now.AddDate(0, -2, 0), // 2 months ago
					EndDate:   now.AddDate(0, -1, 0), // 1 month ago
				},
				expected: "Expirada",
			},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				if status := tc.license.Status(); status != tc.expected {
					t.Errorf("Expected status %s, got %s", tc.expected, status)
				}
			})
		}
	})
}

func TestCategoryValidations(t *testing.T) {
	t.Run("Valid Category", func(t *testing.T) {
		category := domain.Category{
			ID:   "1",
			Name: "Test Category",
		}

		if category.Name == "" {
			t.Error("Category name should not be empty")
		}
	})
}

func TestLineValidations(t *testing.T) {
	t.Run("Valid Line", func(t *testing.T) {
		licenseLine := domain.Line{
			ID:         "1",
			Line:       "Test Line",
			CategoryID: "category-1",
		}

		if licenseLine.Line == "" {
			t.Error("Line type should not be empty")
		}

		if licenseLine.CategoryID == "" {
			t.Error("Line must belong to a category")
		}
	})
}
