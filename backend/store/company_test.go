package store

import (
	"Licenses-Manager/backend/domain"
	"testing"
)

func TestCreateCompany(t *testing.T) {
	tests := []struct {
		name        string
		company     domain.Company
		mockDB      *mockDB
		expectError bool
		expectID    bool
	}{
		{
			name: "sucesso - criação normal",
			company: domain.Company{
				Name: "Test Company",
				CNPJ: "12.345.678/0001-90",
			},
			mockDB:      &mockDB{},
			expectError: false,
			expectID:    true,
		},
		{
			name: "erro - falha no banco",
			company: domain.Company{
				Name: "Test Company",
				CNPJ: "12.345.678/0001-90",
			},
			mockDB: &mockDB{
				shouldError: true,
			},
			expectError: true,
			expectID:    false,
		},
		{
			name: "erro - CNPJ vazio",
			company: domain.Company{
				Name: "Test Company",
				CNPJ: "",
			},
			mockDB:      &mockDB{},
			expectError: true,
			expectID:    false,
		},
		{
			name: "erro - nome vazio",
			company: domain.Company{
				Name: "",
				CNPJ: "12.345.678/0001-90",
			},
			mockDB:      &mockDB{},
			expectError: true,
			expectID:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := NewCompanyStore(tt.mockDB)
			id, err := store.CreateCompany(tt.company)

			// Verifica se Exec foi chamado quando necessário
			if !tt.expectError && !tt.mockDB.execCalled {
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
			expectedQuery := "INSERT INTO companies (id, name, cnpj) VALUES (?, ?, ?)"
			if !tt.expectError && tt.mockDB.lastQuery != expectedQuery {
				t.Errorf("Expected query %q, got %q", expectedQuery, tt.mockDB.lastQuery)
			}
		})
	}
}

func TestGetCompanyByID(t *testing.T) {
	tests := []struct {
		name        string
		id          string
		mockDB      *mockDB
		expectError bool
		expectFound bool
	}{
		{
			name:        "sucesso - empresa encontrada",
			id:          "company-123",
			mockDB:      &mockDB{},
			expectError: false,
			expectFound: true,
		},
		{
			name: "erro - falha no banco",
			id:   "company-123",
			mockDB: &mockDB{
				shouldError: true,
			},
			expectError: true,
			expectFound: false,
		},
		{
			name: "não encontrado - id inexistente",
			id:   "company-999",
			mockDB: &mockDB{
				noRows: true,
			},
			expectError: false,
			expectFound: false,
		},
		{
			name:        "erro - id vazio",
			id:          "",
			mockDB:      &mockDB{},
			expectError: true,
			expectFound: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := NewCompanyStore(tt.mockDB)
			company, err := store.GetCompanyByID(tt.id)

			// Verifica se QueryRow foi chamado quando necessário
			if !tt.expectError && !tt.mockDB.queryRowCalled {
				t.Error("Expected QueryRow to be called")
			}

			// Verifica se o erro corresponde ao esperado
			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}

			// Verifica se encontrou a empresa quando deveria
			if tt.expectFound && company == nil {
				t.Error("Expected company but got nil")
			}
			if !tt.expectFound && company != nil {
				t.Error("Expected no company but got one")
			}

			// Verifica a query executada
			expectedQuery := "SELECT id, name, cnpj, archived_at FROM companies WHERE id = ?"
			if !tt.expectError && tt.mockDB.lastQuery != expectedQuery {
				t.Errorf("Expected query %q, got %q", expectedQuery, tt.mockDB.lastQuery)
			}
		})
	}
}

func TestArchiveCompany(t *testing.T) {
	tests := []struct {
		name        string
		id          string
		mockDB      *mockDB
		expectError bool
	}{
		{
			name:        "sucesso - arquivamento normal",
			id:          "company-123",
			mockDB:      &mockDB{},
			expectError: false,
		},
		{
			name: "erro - falha no banco",
			id:   "company-123",
			mockDB: &mockDB{
				shouldError: true,
			},
			expectError: true,
		},
		{
			name: "erro - empresa não encontrada",
			id:   "company-999",
			mockDB: &mockDB{
				noRows: true,
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := NewCompanyStore(tt.mockDB)
			err := store.ArchiveCompany(tt.id)

			// Verifica se Exec foi chamado
			if !tt.expectError && !tt.mockDB.execCalled {
				t.Error("Expected Exec to be called")
			}

			// Verifica se o erro corresponde ao esperado
			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}

			// Verifica a query executada
			expectedQuery := "UPDATE companies SET archived_at = ? WHERE id = ?"
			if !tt.expectError && tt.mockDB.lastQuery != expectedQuery {
				t.Errorf("Expected query %q, got %q", expectedQuery, tt.mockDB.lastQuery)
			}

			// Verifica se o timestamp foi passado como parâmetro
			if !tt.expectError && len(tt.mockDB.lastParams) != 2 {
				t.Errorf("Expected 2 parameters, got %d", len(tt.mockDB.lastParams))
			}
		})
	}
}

func TestUnarchiveCompany(t *testing.T) {
	tests := []struct {
		name        string
		id          string
		mockDB      *mockDB
		expectError bool
	}{
		{
			name:        "sucesso - desarquivamento normal",
			id:          "company-123",
			mockDB:      &mockDB{},
			expectError: false,
		},
		{
			name: "erro - falha no banco",
			id:   "company-123",
			mockDB: &mockDB{
				shouldError: true,
			},
			expectError: true,
		},
		{
			name: "erro - empresa não encontrada",
			id:   "company-999",
			mockDB: &mockDB{
				noRows: true,
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := NewCompanyStore(tt.mockDB)
			err := store.UnarchiveCompany(tt.id)

			// Verifica se Exec foi chamado
			if !tt.expectError && !tt.mockDB.execCalled {
				t.Error("Expected Exec to be called")
			}

			// Verifica se o erro corresponde ao esperado
			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}

			// Verifica a query executada
			expectedQuery := "UPDATE companies SET archived_at = NULL WHERE id = ?"
			if !tt.expectError && tt.mockDB.lastQuery != expectedQuery {
				t.Errorf("Expected query %q, got %q", expectedQuery, tt.mockDB.lastQuery)
			}
		})
	}
}

func TestDeleteCompanyPermanently(t *testing.T) {
	tests := []struct {
		name        string
		id          string
		mockDB      *mockDB
		expectError bool
	}{
		{
			name:        "sucesso - deleção normal",
			id:          "company-123",
			mockDB:      &mockDB{},
			expectError: false,
		},
		{
			name: "erro - falha no banco",
			id:   "company-123",
			mockDB: &mockDB{
				shouldError: true,
			},
			expectError: true,
		},
		{
			name: "erro - empresa não encontrada",
			id:   "company-999",
			mockDB: &mockDB{
				noRows: true,
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := NewCompanyStore(tt.mockDB)
			err := store.DeleteCompanyPermanently(tt.id)

			// Verifica se Exec foi chamado
			if !tt.expectError && !tt.mockDB.execCalled {
				t.Error("Expected Exec to be called")
			}

			// Verifica se o erro corresponde ao esperado
			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}

			// Verifica a query executada
			expectedQuery := "DELETE FROM companies WHERE id = ?"
			if !tt.expectError && tt.mockDB.lastQuery != expectedQuery {
				t.Errorf("Expected query %q, got %q", expectedQuery, tt.mockDB.lastQuery)
			}
		})
	}
}
