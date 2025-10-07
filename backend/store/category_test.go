package store

import (
	"Licenses-Manager/backend/domain"
	"testing"
)

func TestCreateCategory(t *testing.T) {
	tests := []struct {
		name        string
		category    domain.Category
		mockDB      *mockDB
		expectError bool
		expectID    bool
	}{
		{
			name: "sucesso - criação normal",
			category: domain.Category{
				Name: "Test Category",
			},
			mockDB:      &mockDB{},
			expectError: false,
			expectID:    true,
		},
		{
			name: "erro - falha no banco",
			category: domain.Category{
				Name: "Test Category",
			},
			mockDB: &mockDB{
				shouldError: true,
			},
			expectError: true,
			expectID:    false,
		},
		{
			name: "erro - nome vazio",
			category: domain.Category{
				Name: "",
			},
			mockDB:      &mockDB{},
			expectError: true,
			expectID:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := NewCategoryStore(tt.mockDB)
			id, err := store.CreateCategory(tt.category)

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

			// Verifica se retornou um ID quando deveria
			if tt.expectID && id == "" {
				t.Error("Expected ID but got empty string")
			}
			if !tt.expectID && id != "" {
				t.Error("Expected no ID but got one")
			}

			// Verifica a query executada
			expectedQuery := "INSERT INTO categories (id, name) VALUES (?, ?)"
			if tt.mockDB.lastQuery != expectedQuery {
				t.Errorf("Expected query %q, got %q", expectedQuery, tt.mockDB.lastQuery)
			}
		})
	}
}

func TestGetAllCategories(t *testing.T) {
	tests := []struct {
		name        string
		mockDB      *mockDB
		expectError bool
		expectEmpty bool
	}{
		{
			name:        "sucesso - lista não vazia",
			mockDB:      &mockDB{},
			expectError: false,
			expectEmpty: false,
		},
		{
			name: "erro - falha no banco",
			mockDB: &mockDB{
				shouldError: true,
			},
			expectError: true,
			expectEmpty: true,
		},
		{
			name:        "sucesso - lista vazia",
			mockDB:      &mockDB{noRows: true},
			expectError: false,
			expectEmpty: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := NewCategoryStore(tt.mockDB)
			categories, err := store.GetAllCategories()

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
			if tt.expectEmpty && len(categories) > 0 {
				t.Error("Expected empty list but got items")
			}

			// Verifica a query executada
			expectedQuery := "SELECT id, name FROM categories"
			if tt.mockDB.lastQuery != expectedQuery {
				t.Errorf("Expected query %q, got %q", expectedQuery, tt.mockDB.lastQuery)
			}
		})
	}
}

func TestUpdateCategory(t *testing.T) {
	tests := []struct {
		name        string
		category    domain.Category
		mockDB      *mockDB
		expectError bool
	}{
		{
			name: "sucesso - atualização normal",
			category: domain.Category{
				ID:   "category-123",
				Name: "Updated Category",
			},
			mockDB:      &mockDB{},
			expectError: false,
		},
		{
			name: "erro - falha no banco",
			category: domain.Category{
				ID:   "category-123",
				Name: "Updated Category",
			},
			mockDB: &mockDB{
				shouldError: true,
			},
			expectError: true,
		},
		{
			name: "erro - ID vazio",
			category: domain.Category{
				Name: "Updated Category",
			},
			mockDB:      &mockDB{},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := NewCategoryStore(tt.mockDB)
			err := store.UpdateCategory(tt.category)

			// Verifica se Exec foi chamado
			if !tt.mockDB.execCalled && !tt.expectError {
				t.Error("Expected Exec to be called")
			}

			// Verifica se o erro corresponde ao esperado
			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}

			if err == nil {
				// Verifica a query executada
				expectedQuery := "UPDATE categories SET name = ? WHERE id = ?"
				if tt.mockDB.lastQuery != expectedQuery {
					t.Errorf("Expected query %q, got %q", expectedQuery, tt.mockDB.lastQuery)
				}
			}
		})
	}
}

func TestDeleteCategory(t *testing.T) {
	tests := []struct {
		name        string
		id          string
		mockDB      *mockDB
		expectError bool
	}{
		{
			name:        "sucesso - deleção normal",
			id:          "category-123",
			mockDB:      &mockDB{},
			expectError: false,
		},
		{
			name: "erro - falha no banco",
			id:   "category-123",
			mockDB: &mockDB{
				shouldError: true,
			},
			expectError: true,
		},
		{
			name: "erro - categoria não encontrada",
			id:   "category-999",
			mockDB: &mockDB{
				shouldError: true,
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
			store := NewCategoryStore(tt.mockDB)
			err := store.DeleteCategory(tt.id)

			// Verifica se Exec foi chamado
			if !tt.mockDB.execCalled && !tt.expectError {
				t.Error("Expected Exec to be called")
			}

			// Verifica se o erro corresponde ao esperado
			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}

			if err == nil {
				// Verifica a query executada
				expectedQuery := "DELETE FROM categories WHERE id = ?"
				if tt.mockDB.lastQuery != expectedQuery {
					t.Errorf("Expected query %q, got %q", expectedQuery, tt.mockDB.lastQuery)
				}
			}
		})
	}
}
