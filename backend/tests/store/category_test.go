package tests

import (
	"testing"

	"Licenses-Manager/backend/domain"
	"Licenses-Manager/backend/store"
)

func TestCreateCategory(t *testing.T) {
	tests := []struct {
		name        string
		category    domain.Category
		mockDB      *MockDB
		expectError bool
		expectID    bool
	}{
		{
			name: "sucesso - criação normal",
			category: domain.Category{
				Name: "Test Category",
			},
			mockDB:      &MockDB{},
			expectError: false,
			expectID:    true,
		},
		{
			name: "erro - falha no banco",
			category: domain.Category{
				Name: "Test Category",
			},
			mockDB: &MockDB{
				ShouldError: true,
			},
			expectError: true,
			expectID:    false,
		},
		{
			name: "erro - nome vazio",
			category: domain.Category{
				Name: "",
			},
			mockDB:      &MockDB{},
			expectError: true,
			expectID:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			categoryStore := store.NewCategoryStore(tt.mockDB)
			id, err := categoryStore.CreateCategory(tt.category)

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}

			if tt.expectID && id == "" {
				t.Error("Expected ID but got empty string")
			}
			if !tt.expectID && id != "" {
				t.Error("Expected no ID but got one")
			}

			if !tt.expectError {
				expectedQuery := "INSERT INTO categories (id, name) VALUES (?, ?)"
				if tt.mockDB.LastQuery != expectedQuery {
					t.Errorf("Expected query %q, got %q", expectedQuery, tt.mockDB.LastQuery)
				}
			}
		})
	}
}

func TestGetAllCategories(t *testing.T) {
	tests := []struct {
		name        string
		mockDB      *MockDB
		expectError bool
		expectEmpty bool
	}{
		{
			name:        "sucesso - lista não vazia",
			mockDB:      &MockDB{},
			expectError: false,
			expectEmpty: false,
		},
		{
			name: "erro - falha no banco",
			mockDB: &MockDB{
				ShouldError: true,
				NoRows:      true,
			},
			expectError: true,
			expectEmpty: true,
		},
		{
			name:        "sucesso - lista vazia",
			mockDB:      &MockDB{NoRows: true},
			expectError: false,
			expectEmpty: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			categoryStore := store.NewCategoryStore(tt.mockDB)
			categories, err := categoryStore.GetAllCategories()

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error but got: %v", err)
				}
				if tt.expectEmpty && len(categories) > 0 {
					t.Error("Expected empty list but got items")
				}
				if !tt.expectEmpty && len(categories) == 0 {
					t.Error("Expected non-empty list but got empty")
				}
			}

			if !tt.expectError {
				expectedQuery := "SELECT id, name FROM categories"
				if tt.mockDB.LastQuery != expectedQuery {
					t.Errorf("Expected query %q, got %q", expectedQuery, tt.mockDB.LastQuery)
				}
			}
		})
	}
}

func TestUpdateCategory(t *testing.T) {
	tests := []struct {
		name        string
		category    domain.Category
		mockDB      *MockDB
		expectError bool
	}{
		{
			name: "sucesso - atualização normal",
			category: domain.Category{
				ID:   "category-123",
				Name: "Updated Category",
			},
			mockDB:      &MockDB{},
			expectError: false,
		},
		{
			name: "erro - falha no banco",
			category: domain.Category{
				ID:   "category-123",
				Name: "Updated Category",
			},
			mockDB: &MockDB{
				ShouldError: true,
			},
			expectError: true,
		},
		{
			name: "erro - ID vazio",
			category: domain.Category{
				Name: "Updated Category",
			},
			mockDB:      &MockDB{},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			categoryStore := store.NewCategoryStore(tt.mockDB)
			err := categoryStore.UpdateCategory(tt.category)

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}

			if !tt.expectError {
				expectedQuery := "UPDATE categories SET name = ? WHERE id = ?"
				if tt.mockDB.LastQuery != expectedQuery {
					t.Errorf("Expected query %q, got %q", expectedQuery, tt.mockDB.LastQuery)
				}
			}
		})
	}
}

func TestDeleteCategory(t *testing.T) {
	tests := []struct {
		name        string
		id          string
		mockDB      *MockDB
		expectError bool
	}{
		{
			name:        "sucesso - deleção normal",
			id:          "category-123",
			mockDB:      &MockDB{},
			expectError: false,
		},
		{
			name: "erro - falha no banco",
			id:   "category-123",
			mockDB: &MockDB{
				ShouldError: true,
			},
			expectError: true,
		},
		{
			name: "erro - categoria não encontrada",
			id:   "category-999",
			mockDB: &MockDB{
				NoRows:      true,
				ShouldError: true,
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
			categoryStore := store.NewCategoryStore(tt.mockDB)
			err := categoryStore.DeleteCategory(tt.id)

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}

			if !tt.expectError {
				expectedQuery := "DELETE FROM categories WHERE id = ?"
				if tt.mockDB.LastQuery != expectedQuery {
					t.Errorf("Expected query %q, got %q", expectedQuery, tt.mockDB.LastQuery)
				}
			}
		})
	}
}
