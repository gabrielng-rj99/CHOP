package store

import (
	"Licenses-Manager/backend/domain"
	"testing"
)

func TestCreateType(t *testing.T) {
	tests := []struct {
		name        string
		licenseType domain.Type
		mockDB      *mockDB
		expectError bool
		expectID    bool
	}{
		{
			name: "sucesso - criação normal",
			licenseType: domain.Type{
				Name:       "Test Type",
				CategoryID: "category-123",
			},
			mockDB:      &mockDB{},
			expectError: false,
			expectID:    true,
		},
		{
			name: "erro - falha no banco",
			licenseType: domain.Type{
				Name:       "Test Type",
				CategoryID: "category-123",
			},
			mockDB: &mockDB{
				shouldError: true,
			},
			expectError: true,
			expectID:    false,
		},
		{
			name: "erro - nome vazio",
			licenseType: domain.Type{
				Name:       "",
				CategoryID: "category-123",
			},
			mockDB:      &mockDB{},
			expectError: true,
			expectID:    false,
		},
		{
			name: "erro - sem category_id",
			licenseType: domain.Type{
				Name: "Test Type",
			},
			mockDB:      &mockDB{},
			expectError: true,
			expectID:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := NewTypeStore(tt.mockDB)
			id, err := store.CreateType(tt.licenseType)

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
			expectedQuery := "INSERT INTO types (id, name, category_id) VALUES (?, ?, ?)"
			if !tt.expectError && tt.mockDB.lastQuery != expectedQuery {
				t.Errorf("Expected query %q, got %q", expectedQuery, tt.mockDB.lastQuery)
			}
		})
	}
}

func TestGetTypeByID(t *testing.T) {
	tests := []struct {
		name        string
		id          string
		mockDB      *mockDB
		expectError bool
		expectFound bool
	}{
		{
			name:        "sucesso - tipo encontrado",
			id:          "type-123",
			mockDB:      &mockDB{},
			expectError: false,
			expectFound: true,
		},
		{
			name: "erro - falha no banco",
			id:   "type-123",
			mockDB: &mockDB{
				shouldError: true,
			},
			expectError: true,
			expectFound: false,
		},
		{
			name: "não encontrado - id inexistente",
			id:   "type-999",
			mockDB: &mockDB{
				noRows: true,
			},
			expectError: false,
			expectFound: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := NewTypeStore(tt.mockDB)
			licenseType, err := store.GetTypeByID(tt.id)

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

			// Verifica se encontrou o tipo quando deveria
			if tt.expectFound && licenseType == nil {
				t.Error("Expected type but got nil")
			}
			if !tt.expectFound && licenseType != nil {
				t.Error("Expected no type but got one")
			}

			// Verifica a query executada
			expectedQuery := "SELECT id, name, category_id FROM types WHERE id = ?"
			if tt.mockDB.lastQuery != expectedQuery {
				t.Errorf("Expected query %q, got %q", expectedQuery, tt.mockDB.lastQuery)
			}
		})
	}
}

func TestGetTypesByCategoryID(t *testing.T) {
	tests := []struct {
		name        string
		categoryID  string
		mockDB      *mockDB
		expectError bool
		expectEmpty bool
	}{
		{
			name:        "sucesso - tipos encontrados",
			categoryID:  "category-123",
			mockDB:      &mockDB{},
			expectError: false,
			expectEmpty: false,
		},
		{
			name:       "erro - falha no banco",
			categoryID: "category-123",
			mockDB: &mockDB{
				shouldError: true,
			},
			expectError: true,
			expectEmpty: true,
		},
		{
			name:       "sucesso - nenhum tipo",
			categoryID: "category-999",
			mockDB: &mockDB{
				noRows: true,
			},
			expectError: false,
			expectEmpty: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := NewTypeStore(tt.mockDB)
			types, err := store.GetTypesByCategoryID(tt.categoryID)

			// Verifica se Query foi chamado
			if !tt.mockDB.queryCalled {
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
			if tt.expectEmpty && len(types) > 0 {
				t.Error("Expected empty list but got items")
			}

			// Verifica a query executada
			expectedQuery := "SELECT id, name, category_id FROM types WHERE category_id = ?"
			if tt.mockDB.lastQuery != expectedQuery {
				t.Errorf("Expected query %q, got %q", expectedQuery, tt.mockDB.lastQuery)
			}
		})
	}
}

func TestUpdateType(t *testing.T) {
	tests := []struct {
		name        string
		licenseType domain.Type
		mockDB      *mockDB
		expectError bool
	}{
		{
			name: "sucesso - atualização normal",
			licenseType: domain.Type{
				ID:   "type-123",
				Name: "Updated Type",
			},
			mockDB:      &mockDB{},
			expectError: false,
		},
		{
			name: "erro - falha no banco",
			licenseType: domain.Type{
				ID:   "type-123",
				Name: "Updated Type",
			},
			mockDB: &mockDB{
				shouldError: true,
			},
			expectError: true,
		},
		{
			name: "erro - ID vazio",
			licenseType: domain.Type{
				Name: "Updated Type",
			},
			mockDB:      &mockDB{},
			expectError: true,
		},
		{
			name: "erro - nome vazio",
			licenseType: domain.Type{
				ID:   "type-123",
				Name: "",
			},
			mockDB:      &mockDB{},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := NewTypeStore(tt.mockDB)
			err := store.UpdateType(tt.licenseType)

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

			if !tt.expectError {
				// Verifica a query executada
				expectedQuery := "UPDATE types SET name = ? WHERE id = ?"
				if tt.mockDB.lastQuery != expectedQuery {
					t.Errorf("Expected query %q, got %q", expectedQuery, tt.mockDB.lastQuery)
				}
			}
		})
	}
}

func TestDeleteType(t *testing.T) {
	tests := []struct {
		name        string
		id          string
		mockDB      *mockDB
		expectError bool
	}{
		{
			name:        "sucesso - deleção normal",
			id:          "type-123",
			mockDB:      &mockDB{},
			expectError: false,
		},
		{
			name: "erro - falha no banco",
			id:   "type-123",
			mockDB: &mockDB{
				shouldError: true,
			},
			expectError: true,
		},
		{
			name: "erro - tipo não encontrado",
			id:   "type-999",
			mockDB: &mockDB{
				noRows: true,
			},
			expectError: true,
		},
		{
			name:        "erro - ID vazio",
			id:          "",
			mockDB:      &mockDB{},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := NewTypeStore(tt.mockDB)
			err := store.DeleteType(tt.id)

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

			if !tt.expectError {
				// Verifica a query executada
				expectedQuery := "DELETE FROM types WHERE id = ?"
				if tt.mockDB.lastQuery != expectedQuery {
					t.Errorf("Expected query %q, got %q", expectedQuery, tt.mockDB.lastQuery)
				}
			}
		})
	}
}
