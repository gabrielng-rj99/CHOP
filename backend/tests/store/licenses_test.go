package tests

import (
	"testing"
	"time"

	"Licenses-Manager/backend/domain"
	"Licenses-Manager/backend/store"
)

func TestCreateLicense(t *testing.T) {
	now := time.Now()
	unitID := "unit-123"

	tests := []struct {
		name        string
		license     domain.License
		mockDB      *MockDB
		expectError bool
		expectID    bool
	}{
		{
			name: "sucesso - criação normal",
			license: domain.License{
				Name:       "Test License",
				ProductKey: "TEST-123",
				StartDate:  now,
				EndDate:    now.AddDate(1, 0, 0),
				TypeID:     "type-123",
				CompanyID:  "company-123",
			},
			mockDB:      &MockDB{},
			expectError: false,
			expectID:    true,
		},
		{
			name: "sucesso - com unidade",
			license: domain.License{
				Name:       "Test License",
				ProductKey: "TEST-123",
				StartDate:  now,
				EndDate:    now.AddDate(1, 0, 0),
				TypeID:     "type-123",
				CompanyID:  "company-123",
				UnitID:     &unitID,
			},
			mockDB:      &MockDB{},
			expectError: false,
			expectID:    true,
		},
		{
			name: "erro - falha no banco",
			license: domain.License{
				Name:       "Test License",
				ProductKey: "TEST-123",
				StartDate:  now,
				EndDate:    now.AddDate(1, 0, 0),
				TypeID:     "type-123",
				CompanyID:  "company-123",
			},
			mockDB: &MockDB{
				ShouldError: true,
			},
			expectError: true,
			expectID:    false,
		},
		{
			name: "erro - data final antes da inicial",
			license: domain.License{
				Name:       "Test License",
				ProductKey: "TEST-123",
				StartDate:  now,
				EndDate:    now.AddDate(0, 0, -1),
				TypeID:     "type-123",
				CompanyID:  "company-123",
			},
			mockDB:      &MockDB{},
			expectError: true,
			expectID:    false,
		},
		{
			name: "erro - sem company_id",
			license: domain.License{
				Name:       "Test License",
				ProductKey: "TEST-123",
				StartDate:  now,
				EndDate:    now.AddDate(1, 0, 0),
				TypeID:     "type-123",
			},
			mockDB:      &MockDB{},
			expectError: true,
			expectID:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			licenseStore := store.NewLicenseStore(tt.mockDB)
			id, err := licenseStore.CreateLicense(tt.license)

			// Verifica se Exec foi chamado quando necessário
			if !tt.expectError && !tt.mockDB.ExecCalled {
				t.Error("Expected Exec to be called")
			}

			// Verifica se o erro corresponde ao esperado
			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}

			// Verifica se retornou um ID quando deveria
			if tt.expectID && id == "" {
				t.Error("Expected ID but got empty string")
			}
			if !tt.expectID && id != "" {
				t.Error("Expected no ID but got one")
			}

			// Verifica a query executada
			expectedQuery := "INSERT INTO licenses (id, name, product_key, start_date, end_date, type_id, company_id, unit_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
			if !tt.expectError && tt.mockDB.LastQuery != expectedQuery {
				t.Errorf("Expected query %q, got %q", expectedQuery, tt.mockDB.LastQuery)
			}
		})
	}
}

func TestGetLicenseByID(t *testing.T) {
	tests := []struct {
		name        string
		id          string
		mockDB      *MockDB
		expectError bool
		expectFound bool
	}{
		{
			name:        "sucesso - licença encontrada",
			id:          "license-123",
			mockDB:      &MockDB{},
			expectError: false,
			expectFound: true,
		},
		{
			name: "erro - falha no banco",
			id:   "license-123",
			mockDB: &MockDB{
				ShouldError: true,
			},
			expectError: true,
			expectFound: false,
		},
		{
			name: "não encontrado - id inexistente",
			id:   "license-999",
			mockDB: &MockDB{
				NoRows: true,
			},
			expectError: false,
			expectFound: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			licenseStore := store.NewLicenseStore(tt.mockDB)
			license, err := licenseStore.GetLicenseByID(tt.id)

			// Verifica se QueryRow foi chamado
			if !tt.mockDB.QueryRowCalled {
				t.Error("Expected QueryRow to be called")
			}

			// Verifica se o erro corresponde ao esperado
			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}

			// Verifica se encontrou a licença quando deveria
			if tt.expectFound && license == nil {
				t.Error("Expected license but got nil")
			}
			if !tt.expectFound && license != nil {
				t.Error("Expected no license but got one")
			}

			// Verifica a query executada
			expectedQuery := "SELECT id, name, product_key, start_date, end_date, type_id, company_id, unit_id FROM licenses WHERE id = ?"
			if tt.mockDB.LastQuery != expectedQuery {
				t.Errorf("Expected query %q, got %q", expectedQuery, tt.mockDB.LastQuery)
			}
		})
	}
}

func TestGetLicensesByCompanyID(t *testing.T) {
	tests := []struct {
		name        string
		companyID   string
		mockDB      *MockDB
		expectError bool
		expectEmpty bool
	}{
		{
			name:        "sucesso - licenças encontradas",
			companyID:   "company-123",
			mockDB:      &MockDB{},
			expectError: false,
			expectEmpty: false,
		},
		{
			name:      "erro - falha no banco",
			companyID: "company-123",
			mockDB: &MockDB{
				ShouldError: true,
			},
			expectError: true,
			expectEmpty: true,
		},
		{
			name:      "sucesso - nenhuma licença",
			companyID: "company-999",
			mockDB: &MockDB{
				NoRows: true,
			},
			expectError: false,
			expectEmpty: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			licenseStore := store.NewLicenseStore(tt.mockDB)
			licenses, err := licenseStore.GetLicensesByCompanyID(tt.companyID)

			// Verifica se Query foi chamado
			if !tt.mockDB.QueryCalled {
				t.Error("Expected Query to be called")
			}

			// Verifica se o erro corresponde ao esperado
			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}

			// Verifica se a lista está vazia quando deveria
			if tt.expectEmpty && len(licenses) > 0 {
				t.Error("Expected empty list but got items")
			}

			// Verifica a query executada
			expectedQuery := "SELECT id, name, product_key, start_date, end_date, type_id, company_id, unit_id FROM licenses WHERE company_id = ? AND company_id IN (SELECT id FROM companies WHERE archived_at IS NULL)"
			if tt.mockDB.LastQuery != expectedQuery {
				t.Errorf("Expected query %q, got %q", expectedQuery, tt.mockDB.LastQuery)
			}
		})
	}
}

func TestGetLicensesExpiringSoon(t *testing.T) {
	tests := []struct {
		name        string
		days        int
		mockDB      *MockDB
		expectError bool
		expectEmpty bool
	}{
		{
			name:        "sucesso - licenças encontradas",
			days:        30,
			mockDB:      &MockDB{},
			expectError: false,
			expectEmpty: false,
		},
		{
			name: "erro - falha no banco",
			days: 30,
			mockDB: &MockDB{
				ShouldError: true,
			},
			expectError: true,
			expectEmpty: true,
		},
		{
			name: "sucesso - nenhuma licença expirando",
			days: 30,
			mockDB: &MockDB{
				NoRows: true,
			},
			expectError: false,
			expectEmpty: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			licenseStore := store.NewLicenseStore(tt.mockDB)
			licenses, err := licenseStore.GetLicensesExpiringSoon(tt.days)

			// Verifica se Query foi chamado
			if !tt.mockDB.QueryCalled {
				t.Error("Expected Query to be called")
			}

			// Verifica se o erro corresponde ao esperado
			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}

			// Verifica se a lista está vazia quando deveria
			if tt.expectEmpty && len(licenses) > 0 {
				t.Error("Expected empty list but got items")
			}

			// Verifica a query executada
			expectedQuery := "SELECT id, name, product_key, start_date, end_date, type_id, company_id, unit_id FROM licenses WHERE end_date BETWEEN ? AND ?"
			if tt.mockDB.LastQuery != expectedQuery {
				t.Errorf("Expected query %q, got %q", expectedQuery, tt.mockDB.LastQuery)
			}
		})
	}
}

func TestUpdateLicense(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name        string
		license     domain.License
		mockDB      *MockDB
		expectError bool
	}{
		{
			name: "sucesso - atualização normal",
			license: domain.License{
				ID:         "license-123",
				Name:       "Updated License",
				ProductKey: "UPDATED-123",
				StartDate:  now,
				EndDate:    now.AddDate(1, 0, 0),
			},
			mockDB:      &MockDB{},
			expectError: false,
		},
		{
			name: "erro - falha no banco",
			license: domain.License{
				ID:         "license-123",
				Name:       "Updated License",
				ProductKey: "UPDATED-123",
				StartDate:  now,
				EndDate:    now.AddDate(1, 0, 0),
			},
			mockDB: &MockDB{
				ShouldError: true,
			},
			expectError: true,
		},
		{
			name: "erro - data final antes da inicial",
			license: domain.License{
				ID:         "license-123",
				Name:       "Updated License",
				ProductKey: "UPDATED-123",
				StartDate:  now,
				EndDate:    now.AddDate(0, 0, -1),
			},
			mockDB:      &MockDB{},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			licenseStore := store.NewLicenseStore(tt.mockDB)
			err := licenseStore.UpdateLicense(tt.license)

			// Verifica se Exec foi chamado quando necessário
			if !tt.expectError && !tt.mockDB.ExecCalled {
				t.Error("Expected Exec to be called")
			}

			// Verifica se o erro corresponde ao esperado
			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}

			if !tt.expectError {
				// Verifica a query executada
				expectedQuery := "UPDATE licenses SET name = ?, product_key = ?, start_date = ?, end_date = ? WHERE id = ?"
				if tt.mockDB.LastQuery != expectedQuery {
					t.Errorf("Expected query %q, got %q", expectedQuery, tt.mockDB.LastQuery)
				}
			}
		})
	}
}

func TestDeleteLicense(t *testing.T) {
	tests := []struct {
		name        string
		id          string
		mockDB      *MockDB
		expectError bool
	}{
		{
			name:        "sucesso - deleção normal",
			id:          "license-123",
			mockDB:      &MockDB{},
			expectError: false,
		},
		{
			name: "erro - falha no banco",
			id:   "license-123",
			mockDB: &MockDB{
				ShouldError: true,
			},
			expectError: true,
		},
		{
			name: "erro - licença não encontrada",
			id:   "license-999",
			mockDB: &MockDB{
				NoRows: true,
			},
			expectError: true,
		},
		{
			name:        "erro - ID vazio",
			id:          "",
			mockDB:      &MockDB{},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			licenseStore := store.NewLicenseStore(tt.mockDB)
			err := licenseStore.DeleteLicense(tt.id)

			// Verifica se Exec foi chamado
			if !tt.expectError && !tt.mockDB.ExecCalled {
				t.Error("Expected Exec to be called")
			}

			// Verifica se o erro corresponde ao esperado
			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}

			if !tt.expectError {
				// Verifica a query executada
				expectedQuery := "DELETE FROM licenses WHERE id = ?"
				if tt.mockDB.LastQuery != expectedQuery {
					t.Errorf("Expected query %q, got %q", expectedQuery, tt.mockDB.LastQuery)
				}
			}
		})
	}
}
