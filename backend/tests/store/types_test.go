package tests

import (
	"Licenses-Manager/backend/domain"
	"Licenses-Manager/backend/store"
	"testing"
)

func TestCreateType(t *testing.T) {
	db, err := SetupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}
	defer func() {
		if err := CloseDB(db); err != nil {
			t.Errorf("Failed to close test database: %v", err)
		}
	}()

	// Create a test category first
	categoryID, err := InsertTestCategory(db, "Test Category")
	if err != nil {
		t.Fatalf("Failed to insert test category: %v", err)
	}

	tests := []struct {
		name        string
		typeData    domain.Type
		expectError bool
	}{
		{
			name: "sucesso - criação normal",
			typeData: domain.Type{
				Name:       "Test Type",
				CategoryID: categoryID,
			},
			expectError: false,
		},
		{
			name: "erro - nome vazio",
			typeData: domain.Type{
				Name:       "",
				CategoryID: categoryID,
			},
			expectError: true,
		},
		{
			name: "erro - categoria não existe",
			typeData: domain.Type{
				Name:       "Test Type",
				CategoryID: "non-existent-category",
			},
			expectError: true,
		},
		{
			name: "erro - categoria vazia",
			typeData: domain.Type{
				Name:       "Test Type",
				CategoryID: "",
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.name == "sucesso - criação normal" {
				if err := ClearTables(db); err != nil {
					t.Fatalf("Failed to clear tables: %v", err)
				}
				// Recreate category after clearing
				categoryID, err = InsertTestCategory(db, "Test Category")
				if err != nil {
					t.Fatalf("Failed to insert test category: %v", err)
				}
				tt.typeData.CategoryID = categoryID
			}

			typeStore := store.NewTypeStore(db)
			id, err := typeStore.CreateType(tt.typeData)

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

func TestGetTypeByID(t *testing.T) {
	db, err := SetupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}
	defer func() {
		if err := CloseDB(db); err != nil {
			t.Errorf("Failed to close test database: %v", err)
		}
	}()

	// Create test category and type
	categoryID, err := InsertTestCategory(db, "Test Category")
	if err != nil {
		t.Fatalf("Failed to insert test category: %v", err)
	}

	typeID, err := InsertTestType(db, "Test Type", categoryID)
	if err != nil {
		t.Fatalf("Failed to insert test type: %v", err)
	}

	tests := []struct {
		name        string
		id          string
		expectError bool
		expectFound bool
	}{
		{
			name:        "sucesso - tipo encontrado",
			id:          typeID,
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
			typeStore := store.NewTypeStore(db)
			typeData, err := typeStore.GetTypeByID(tt.id)

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}
			if tt.expectFound && typeData == nil {
				t.Error("Expected type but got nil")
			}
			if !tt.expectFound && typeData != nil {
				t.Error("Expected no type but got one")
			}
		})
	}
}

func TestGetTypesByCategoryID(t *testing.T) {
	db, err := SetupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}
	defer func() {
		if err := CloseDB(db); err != nil {
			t.Errorf("Failed to close test database: %v", err)
		}
	}()

	// Create test category
	categoryID, err := InsertTestCategory(db, "Test Category")
	if err != nil {
		t.Fatalf("Failed to insert test category: %v", err)
	}

	// Insert test types
	testTypes := []string{"Type 1", "Type 2", "Type 3"}
	for _, name := range testTypes {
		_, err := InsertTestType(db, name, categoryID)
		if err != nil {
			t.Fatalf("Failed to insert test type: %v", err)
		}
	}

	tests := []struct {
		name        string
		categoryID  string
		expectError bool
		expectCount int
	}{
		{
			name:        "sucesso - tipos encontrados",
			categoryID:  categoryID,
			expectError: false,
			expectCount: len(testTypes),
		},
		{
			name:        "erro - categoria vazia",
			categoryID:  "",
			expectError: true,
			expectCount: 0,
		},
		{
			name:        "sucesso - categoria sem tipos",
			categoryID:  "non-existent-category",
			expectError: false,
			expectCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			typeStore := store.NewTypeStore(db)
			types, err := typeStore.GetTypesByCategoryID(tt.categoryID)

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}
			if !tt.expectError && len(types) != tt.expectCount {
				t.Errorf("Expected %d types but got %d", tt.expectCount, len(types))
			}
		})
	}
}

func TestUpdateType(t *testing.T) {
	db, err := SetupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}
	defer func() {
		if err := CloseDB(db); err != nil {
			t.Errorf("Failed to close test database: %v", err)
		}
	}()

	// Create test category and type
	categoryID, err := InsertTestCategory(db, "Test Category")
	if err != nil {
		t.Fatalf("Failed to insert test category: %v", err)
	}

	typeID, err := InsertTestType(db, "Test Type", categoryID)
	if err != nil {
		t.Fatalf("Failed to insert test type: %v", err)
	}

	tests := []struct {
		name        string
		typeData    domain.Type
		expectError bool
	}{
		{
			name: "sucesso - atualização normal",
			typeData: domain.Type{
				ID:         typeID,
				Name:       "Updated Type",
				CategoryID: categoryID,
			},
			expectError: false,
		},
		{
			name: "erro - id vazio",
			typeData: domain.Type{
				Name:       "Updated Type",
				CategoryID: categoryID,
			},
			expectError: true,
		},
		{
			name: "erro - nome vazio",
			typeData: domain.Type{
				ID:         typeID,
				Name:       "",
				CategoryID: categoryID,
			},
			expectError: true,
		},
		{
			name: "erro - categoria inválida",
			typeData: domain.Type{
				ID:         typeID,
				Name:       "Updated Type",
				CategoryID: "non-existent-category",
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			typeStore := store.NewTypeStore(db)
			err := typeStore.UpdateType(tt.typeData)

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}

			if !tt.expectError {
				// Verify update
				var name, categoryID string
				err = db.QueryRow("SELECT name, category_id FROM types WHERE id = ?", tt.typeData.ID).
					Scan(&name, &categoryID)
				if err != nil {
					t.Errorf("Failed to query updated type: %v", err)
				}
				if name != tt.typeData.Name {
					t.Errorf("Expected name %q but got %q", tt.typeData.Name, name)
				}
				if categoryID != tt.typeData.CategoryID {
					t.Errorf("Expected category_id %q but got %q", tt.typeData.CategoryID, categoryID)
				}
			}
		})
	}
}

func TestDeleteType(t *testing.T) {
	db, err := SetupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}
	defer func() {
		if err := CloseDB(db); err != nil {
			t.Errorf("Failed to close test database: %v", err)
		}
	}()

	// Create test category and type
	categoryID, err := InsertTestCategory(db, "Test Category")
	if err != nil {
		t.Fatalf("Failed to insert test category: %v", err)
	}

	typeID, err := InsertTestType(db, "Test Type", categoryID)
	if err != nil {
		t.Fatalf("Failed to insert test type: %v", err)
	}

	tests := []struct {
		name        string
		id          string
		expectError bool
	}{
		{
			name:        "sucesso - deleção normal",
			id:          typeID,
			expectError: false,
		},
		{
			name:        "erro - id vazio",
			id:          "",
			expectError: true,
		},
		{
			name:        "erro - id inexistente",
			id:          "non-existent-id",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			typeStore := store.NewTypeStore(db)
			err := typeStore.DeleteType(tt.id)

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}

			if !tt.expectError {
				// Verify deletion
				var count int
				err = db.QueryRow("SELECT COUNT(*) FROM types WHERE id = ?", tt.id).Scan(&count)
				if err != nil {
					t.Errorf("Failed to query deleted type: %v", err)
				}
				if count != 0 {
					t.Error("Expected type to be deleted, but it still exists")
				}
			}
		})
	}
}
