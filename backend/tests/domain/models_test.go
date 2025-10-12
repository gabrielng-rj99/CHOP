package domain_test

import (
	"testing"
	"time"

	"Licenses-Manager/backend/domain"
)

func TestCompanyValidations(t *testing.T) {
	t.Run("Valid Company", func(t *testing.T) {
		company := domain.Company{
			ID:   "1",
			Name: "Test Company",
			CNPJ: "12.345.678/0001-90",
		}

		if company.Name == "" {
			t.Error("Company name should not be empty")
		}

		if company.CNPJ == "" {
			t.Error("Company CNPJ should not be empty")
		}
	})

	t.Run("Archived Company", func(t *testing.T) {
		now := time.Now()
		company := domain.Company{
			ID:         "1",
			Name:       "Test Company",
			CNPJ:       "12.345.678/0001-90",
			ArchivedAt: &now,
		}

		if company.ArchivedAt == nil {
			t.Error("Company should be archived")
		}
	})
}

func TestUnitValidations(t *testing.T) {
	t.Run("Valid Unit", func(t *testing.T) {
		unit := domain.Unit{
			ID:        "1",
			Name:      "Test Unit",
			CompanyID: "company-1",
		}

		if unit.Name == "" {
			t.Error("Unit name should not be empty")
		}

		if unit.CompanyID == "" {
			t.Error("Unit must belong to a company")
		}
	})
}

func TestLicenseValidations(t *testing.T) {
	t.Run("Valid License", func(t *testing.T) {
		now := time.Now()
		future := now.AddDate(0, 1, 0) // 1 month from now

		license := domain.License{
			ID:         "1",
			Name:       "Test License",
			ProductKey: "XXXX-YYYY-ZZZZ",
			StartDate:  now,
			EndDate:    future,
			TypeID:     "type-1",
			CompanyID:  "company-1",
		}

		if license.Name == "" {
			t.Error("License name should not be empty")
		}

		if license.TypeID == "" {
			t.Error("License must have a type")
		}

		if license.CompanyID == "" {
			t.Error("License must belong to a company")
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

func TestTypeValidations(t *testing.T) {
	t.Run("Valid Type", func(t *testing.T) {
		licenseType := domain.Type{
			ID:         "1",
			Name:       "Test Type",
			CategoryID: "category-1",
		}

		if licenseType.Name == "" {
			t.Error("Type name should not be empty")
		}

		if licenseType.CategoryID == "" {
			t.Error("Type must belong to a category")
		}
	})
}
