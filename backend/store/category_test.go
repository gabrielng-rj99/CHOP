package store

import (
	"Contracts-Manager/backend/domain"
	"testing"
)

func TestCreateCategory(t *testing.T) {
	db, err := SetupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}
	defer func() {
		if err := CloseDB(db); err != nil {
			t.Errorf("Failed to close test database: %v", err)
		}
	}()

	tests := []struct {
		name        string
		category    domain.Category
		expectError bool
	}{
		{
			name: "sucesso - criação normal",
			category: domain.Category{
				Name: "Test Category",
			},
			expectError: false,
		},
		{
			name: "erro - nome vazio",
			category: domain.Category{
				Name: "",
			},
			expectError: true,
		},
		{
			name: "erro - nome duplicado",
			category: domain.Category{
				Name: "Test Category",
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clean up before each test to avoid leftover data
			if err := ClearTables(db); err != nil {
				t.Fatalf("Failed to clear tables: %v", err)
			}

			if tt.name == "erro - nome duplicado" {
				_, err := InsertTestCategory(db, "Test Category")
				if err != nil {
					t.Fatalf("Failed to insert category for duplicate test: %v", err)
				}
			}

			categoryStore := NewCategoryStore(db)
			id, err := categoryStore.CreateCategory(tt.category)

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}
			if !tt.expectError && id == "" {
				t.Error("Expected ID but got empty string")
			}
		})
	}
}

func TestGetCategoryByID(t *testing.T) {
	db, err := SetupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}
	defer func() {
		if err := CloseDB(db); err != nil {
			t.Errorf("Failed to close test database: %v", err)
		}
	}()

	// Insert test category
	categoryID, err := InsertTestCategory(db, "Test Category")
	if err != nil {
		t.Fatalf("Failed to insert test category: %v", err)
	}

	tests := []struct {
		name        string
		id          string
		expectError bool
		expectFound bool
	}{
		{
			name:        "sucesso - categoria encontrada",
			id:          categoryID,
			expectError: false,
			expectFound: true,
		},
		{
			name:        "erro - id vazio",
			id:          "",
			expectError: true,
			expectFound: false,
		},
		{
			name:        "não encontrado - id inexistente",
			id:          "non-existent-id",
			expectError: false,
			expectFound: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clean up before each test to avoid leftover data
			if err := ClearTables(db); err != nil {
				t.Fatalf("Failed to clear tables: %v", err)
			}
			// Insert test category for valid cases
			if tt.id == categoryID {
				_, err := InsertTestCategory(db, "Test Category")
				if err != nil {
					t.Fatalf("Failed to insert test category: %v", err)
				}
			}
			categoryStore := NewCategoryStore(db)
			category, err := categoryStore.GetCategoryByID(tt.id)

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}
			if tt.expectFound && category == nil {
				t.Error("Expected category but got nil")
			}
			if !tt.expectFound && category != nil {
				t.Error("Expected no category but got one")
			}
		})
	}
}

func TestDeleteCategoryWithLinesAssociated(t *testing.T) {
	db, err := SetupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}
	defer func() {
		if err := CloseDB(db); err != nil {
			t.Errorf("Failed to close test database: %v", err)
		}
	}()

	if err := ClearTables(db); err != nil {
		t.Fatalf("Failed to clear tables: %v", err)
	}

	categoryID, err := InsertTestCategory(db, "Categoria Com Linha")
	if err != nil {
		t.Fatalf("Failed to insert test category: %v", err)
	}

	lineStore := NewLineStore(db)
	line := domain.Line{
		Line:       "Linha Teste",
		CategoryID: categoryID,
	}
	_, err = lineStore.CreateLine(line)
	if err != nil {
		t.Fatalf("Failed to create line: %v", err)
	}

	categoryStore := NewCategoryStore(db)
	err = categoryStore.DeleteCategory(categoryID)
	if err == nil {
		t.Error("Expected error when deleting category with lines associated, got none")
	}
}

func TestLineNameUniquePerCategory(t *testing.T) {
	db, err := SetupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}
	defer func() {
		if err := CloseDB(db); err != nil {
			t.Errorf("Failed to close test database: %v", err)
		}
	}()

	if err := ClearTables(db); err != nil {
		t.Fatalf("Failed to clear tables: %v", err)
	}

	categoryID, err := InsertTestCategory(db, "Categoria Unica")
	if err != nil {
		t.Fatalf("Failed to insert test category: %v", err)
	}

	lineStore := NewLineStore(db)
	line := domain.Line{
		Line:       "Linha Unica",
		CategoryID: categoryID,
	}
	_, err = lineStore.CreateLine(line)
	if err != nil {
		t.Fatalf("Failed to create first line: %v", err)
	}

	// Tentar criar segunda linha com mesmo nome na mesma categoria
	_, err = lineStore.CreateLine(line)
	if err == nil {
		t.Error("Expected error when creating duplicate line name in same category, got none")
	}
}

func TestGetAllCategories(t *testing.T) {
	db, err := SetupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}
	defer func() {
		if err := CloseDB(db); err != nil {
			t.Errorf("Failed to close test database: %v", err)
		}
	}()

	if err := ClearTables(db); err != nil {
		t.Fatalf("Failed to clear tables: %v", err)
	}

	// Insert test categories
	testCategories := []string{"Category 1", "Category 2", "Category 3"}
	for _, name := range testCategories {
		_, err := InsertTestCategory(db, name)
		if err != nil {
			t.Fatalf("Failed to insert test category %q: %v", name, err)
		}
	}

	categoryStore := NewCategoryStore(db)
	categories, err := categoryStore.GetAllCategories()

	if err != nil {
		t.Errorf("Expected no error but got: %v", err)
	}
	if len(categories) != len(testCategories) {
		t.Errorf("Expected %d categories but got %d", len(testCategories), len(categories))
	}
	// Clean up after test
	if err := ClearTables(db); err != nil {
		t.Errorf("Failed to clear tables after test: %v", err)
	}
}

func TestUpdateCategory(t *testing.T) {
	db, err := SetupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}
	defer func() {
		if err := CloseDB(db); err != nil {
			t.Errorf("Failed to close test database: %v", err)
		}
	}()

	// Insert test category
	categoryID, err := InsertTestCategory(db, "Test Category")
	if err != nil {
		t.Fatalf("Failed to insert test category: %v", err)
	}

	tests := []struct {
		name        string
		category    domain.Category
		expectError bool
	}{
		{
			name: "sucesso - atualização normal",
			category: domain.Category{
				ID:   categoryID,
				Name: "Updated Category",
			},
			expectError: false,
		},
		{
			name: "erro - id vazio",
			category: domain.Category{
				Name: "Updated Category",
			},
			expectError: true,
		},
		{
			name: "erro - nome vazio",
			category: domain.Category{
				ID: categoryID,
			},
			expectError: true,
		},
		{
			name: "erro - categoria não existe",
			category: domain.Category{
				ID:   "non-existent-id",
				Name: "Updated Category",
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clean up before each test to avoid leftover data
			if err := ClearTables(db); err != nil {
				t.Fatalf("Failed to clear tables: %v", err)
			}
			// Insert test category for valid cases
			if tt.category.ID == categoryID {
				_, err := InsertTestCategory(db, "Test Category")
				if err != nil {
					t.Fatalf("Failed to insert test category: %v", err)
				}
			}
			categoryStore := NewCategoryStore(db)
			err := categoryStore.UpdateCategory(tt.category)

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}

			if !tt.expectError {
				// Verify update
				var name string
				err = db.QueryRow("SELECT name FROM categories WHERE id = $1", tt.category.ID).Scan(&name)
				if err != nil {
					t.Errorf("Failed to query updated category: %v", err)
				}
				if name != tt.category.Name {
					t.Errorf("Expected name %q but got %q", tt.category.Name, name)
				}
			}
		})
	}
}

func TestDeleteCategory(t *testing.T) {
	db, err := SetupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}
	defer func() {
		if err := CloseDB(db); err != nil {
			t.Errorf("Failed to close test database: %v", err)
		}
	}()

	// Insert test category
	categoryID, err := InsertTestCategory(db, "Test Category")
	if err != nil {
		t.Fatalf("Failed to insert test category: %v", err)
	}

	tests := []struct {
		name        string
		id          string
		expectError bool
	}{
		{
			name:        "sucesso - deleção normal",
			id:          categoryID,
			expectError: false,
		},
		{
			name:        "erro - id vazio",
			id:          "",
			expectError: true,
		},
		{
			name:        "erro - categoria não existe",
			id:          "non-existent-id",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clean up before each test to avoid leftover data
			if err := ClearTables(db); err != nil {
				t.Fatalf("Failed to clear tables: %v", err)
			}
			// Insert test category for valid cases
			if tt.id == categoryID {
				_, err := InsertTestCategory(db, "Test Category")
				if err != nil {
					t.Fatalf("Failed to insert test category: %v", err)
				}
			}
			categoryStore := NewCategoryStore(db)
			err := categoryStore.DeleteCategory(tt.id)

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}

			if !tt.expectError {
				// Verify deletion
				var count int
				err = db.QueryRow("SELECT COUNT(*) FROM categories WHERE id = $1", tt.id).Scan(&count)
				if err != nil {
					t.Errorf("Failed to query deleted category: %v", err)
				}
				if count != 0 {
					t.Error("Expected category to be deleted, but it still exists")
				}
			}
		})
	}
}
