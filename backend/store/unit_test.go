package store

import (
	"Licenses-Manager/backend/domain"
	"testing"
)

func TestCreateUnit(t *testing.T) {
	tests := []struct {
		name        string
		unit        domain.Unit
		mockDB      *mockDB
		expectError bool
		expectID    bool
	}{
		{
			name: "sucesso - criação normal",
			unit: domain.Unit{
				Name:      "Test Unit",
				CompanyID: "company-123",
			},
			mockDB:      &mockDB{},
			expectError: false,
			expectID:    true,
		},
		{
			name: "erro - falha no banco",
			unit: domain.Unit{
				Name:      "Test Unit",
				CompanyID: "company-123",
			},
			mockDB: &mockDB{
				shouldError: true,
			},
			expectError: true,
			expectID:    false,
		},
		{
			name: "erro - sem company_id",
			unit: domain.Unit{
				Name: "Test Unit",
			},
			mockDB:      &mockDB{},
			expectError: true,
			expectID:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := NewUnitStore(tt.mockDB)
			id, err := store.CreateUnit(tt.unit)

			// Verifica se o método Exec foi chamado
			if !tt.mockDB.execCalled {
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
			expectedQuery := "INSERT INTO units (id, name, company_id) VALUES (?, ?, ?)"
			if tt.mockDB.lastQuery != expectedQuery {
				t.Errorf("Expected query %q, got %q", expectedQuery, tt.mockDB.lastQuery)
			}
		})
	}
}

func TestGetUnitByID(t *testing.T) {
	tests := []struct {
		name        string
		id          string
		mockDB      *mockDB
		expectError bool
		expectUnit  bool
	}{
		{
			name:        "sucesso - unidade encontrada",
			id:          "unit-123",
			mockDB:      &mockDB{},
			expectError: false,
			expectUnit:  true,
		},
		{
			name: "erro - falha no banco",
			id:   "unit-123",
			mockDB: &mockDB{
				shouldError: true,
			},
			expectError: true,
			expectUnit:  false,
		},
		{
			name: "não encontrado - id inexistente",
			id:   "unit-999",
			mockDB: &mockDB{
				noRows: true,
			},
			expectError: false,
			expectUnit:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := NewUnitStore(tt.mockDB)
			unit, err := store.GetUnitByID(tt.id)

			// Verifica se QueryRow foi chamado
			if !tt.mockDB.queryRowCalled {
				t.Error("Expected QueryRow to be called")
			}

			// Verifica se o erro corresponde ao esperado
			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}

			// Verifica se retornou uma unidade quando deveria
			if tt.expectUnit && unit == nil {
				t.Error("Expected unit but got nil")
			}
			if !tt.expectUnit && unit != nil {
				t.Error("Expected no unit but got one")
			}

			// Verifica a query executada
			expectedQuery := "SELECT id, name, company_id FROM units WHERE id = ?"
			if tt.mockDB.lastQuery != expectedQuery {
				t.Errorf("Expected query %q, got %q", expectedQuery, tt.mockDB.lastQuery)
			}
		})
	}
}

func TestUpdateUnit(t *testing.T) {
	tests := []struct {
		name        string
		unit        domain.Unit
		mockDB      *mockDB
		expectError bool
	}{
		{
			name: "sucesso - atualização normal",
			unit: domain.Unit{
				ID:        "unit-123",
				Name:      "Updated Unit",
				CompanyID: "company-123",
			},
			mockDB:      &mockDB{},
			expectError: false,
		},
		{
			name: "erro - falha no banco",
			unit: domain.Unit{
				ID:        "unit-123",
				Name:      "Updated Unit",
				CompanyID: "company-123",
			},
			mockDB: &mockDB{
				shouldError: true,
			},
			expectError: true,
		},
		{
			name: "erro - unidade não encontrada",
			unit: domain.Unit{
				ID:        "unit-999",
				Name:      "Updated Unit",
				CompanyID: "company-123",
			},
			mockDB: &mockDB{
				noRows: true,
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := NewUnitStore(tt.mockDB)
			err := store.UpdateUnit(tt.unit)

			// Verifica se Exec foi chamado
			if !tt.mockDB.execCalled {
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
			expectedQuery := "UPDATE units SET name = ? WHERE id = ?"
			if tt.mockDB.lastQuery != expectedQuery {
				t.Errorf("Expected query %q, got %q", expectedQuery, tt.mockDB.lastQuery)
			}
		})
	}
}

func TestDeleteUnit(t *testing.T) {
	tests := []struct {
		name        string
		id          string
		mockDB      *mockDB
		expectError bool
	}{
		{
			name:        "sucesso - deleção normal",
			id:          "unit-123",
			mockDB:      &mockDB{},
			expectError: false,
		},
		{
			name: "erro - falha no banco",
			id:   "unit-123",
			mockDB: &mockDB{
				shouldError: true,
			},
			expectError: true,
		},
		{
			name: "erro - unidade não encontrada",
			id:   "unit-999",
			mockDB: &mockDB{
				noRows: true,
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := NewUnitStore(tt.mockDB)
			err := store.DeleteUnit(tt.id)

			// Verifica se Exec foi chamado
			if !tt.mockDB.execCalled {
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
			expectedQuery := "DELETE FROM units WHERE id = ?"
			if tt.mockDB.lastQuery != expectedQuery {
				t.Errorf("Expected query %q, got %q", expectedQuery, tt.mockDB.lastQuery)
			}
		})
	}
}
