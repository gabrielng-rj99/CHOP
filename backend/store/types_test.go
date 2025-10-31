package store

import (
	"Contracts-Manager/backend/domain"
	"testing"
)

func TestCreateLine(t *testing.T) {
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
		lineData    domain.Line
		expectError bool
	}{
		{
			name: "sucesso - criação normal",
			lineData: domain.Line{
				Line:       "Test Line",
				CategoryID: categoryID,
			},
			expectError: false,
		},
		{
			name: "erro - nome vazio",
			lineData: domain.Line{
				Line:       "",
				CategoryID: categoryID,
			},
			expectError: true,
		},
		{
			name: "erro - categoria não existe",
			lineData: domain.Line{
				Line:       "Test Line",
				CategoryID: "non-existent-category",
			},
			expectError: true,
		},
		{
			name: "erro - categoria vazia",
			lineData: domain.Line{
				Line:       "Test Line",
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
				tt.lineData.CategoryID = categoryID
			}

			lineStore := NewLineStore(db)
			id, err := lineStore.CreateLine(tt.lineData)

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

func TestGetLineByID(t *testing.T) {
	db, err := SetupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}
	defer func() {
		if err := CloseDB(db); err != nil {
			t.Errorf("Failed to close test database: %v", err)
		}
	}()

	// Create test category and line
	categoryID, err := InsertTestCategory(db, "Test Category")
	if err != nil {
		t.Fatalf("Failed to insert test category: %v", err)
	}

	lineID, err := InsertTestLine(db, "Test Line", categoryID)
	if err != nil {
		t.Fatalf("Failed to insert test line: %v", err)
	}

	tests := []struct {
		name        string
		id          string
		expectError bool
		expectFound bool
	}{
		{
			name:        "sucesso - tipo encontrado",
			id:          lineID,
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
			lineStore := NewLineStore(db)
			lineData, err := lineStore.GetLineByID(tt.id)

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}
			if tt.expectFound && lineData == nil {
				t.Error("Expected type but got nil")
			}
			if !tt.expectFound && lineData != nil {
				t.Error("Expected no type but got one")
			}
		})
	}
}

func TestGetLinesByCategoryID(t *testing.T) {
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

	// Insert test lines
	testLines := []string{"Line 1", "Line 2", "Line 3"}
	for _, name := range testLines {
		_, err := InsertTestLine(db, name, categoryID)
		if err != nil {
			t.Fatalf("Failed to insert test line: %v", err)
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
			expectCount: len(testLines),
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
			lineStore := NewLineStore(db)
			lines, err := lineStore.GetLinesByCategoryID(tt.categoryID)

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}
			if !tt.expectError && len(lines) != tt.expectCount {
				t.Errorf("Expected %d lines but got %d", tt.expectCount, len(lines))
			}
		})
	}
}

func TestUpdateLine(t *testing.T) {
	db, err := SetupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}
	defer func() {
		if err := CloseDB(db); err != nil {
			t.Errorf("Failed to close test database: %v", err)
		}
	}()

	// Create test category and line
	categoryID, err := InsertTestCategory(db, "Test Category")
	if err != nil {
		t.Fatalf("Failed to insert test category: %v", err)
	}

	lineID, err := InsertTestLine(db, "Test Line", categoryID)
	if err != nil {
		t.Fatalf("Failed to insert test line: %v", err)
	}

	tests := []struct {
		name        string
		lineData    domain.Line
		expectError bool
	}{
		{
			name: "sucesso - atualização normal",
			lineData: domain.Line{
				ID:         lineID,
				Line:       "Updated Line",
				CategoryID: categoryID,
			},
			expectError: false,
		},
		{
			name: "erro - id vazio",
			lineData: domain.Line{
				ID:         "",
				Line:       "Updated Line",
				CategoryID: categoryID,
			},
			expectError: true,
		},
		{
			name: "erro - nome vazio",
			lineData: domain.Line{
				ID:         lineID,
				Line:       "",
				CategoryID: categoryID,
			},
			expectError: true,
		},
		{
			name: "erro - categoria inválida",
			lineData: domain.Line{
				ID:         lineID,
				Line:       "Updated Line",
				CategoryID: "non-existent-category",
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lineStore := NewLineStore(db)
			err := lineStore.UpdateLine(tt.lineData)

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}

			if !tt.expectError {
				// Verify update
				var name, categoryID string
				err = db.QueryRow("SELECT name, category_id FROM lines WHERE id = ?", tt.lineData.ID).
					Scan(&name, &categoryID)
				if err != nil {
					t.Errorf("Failed to query updated line: %v", err)
				}
				if name != tt.lineData.Line {
					t.Errorf("Expected type %q but got %q", tt.lineData.Line, name)
				}
				if categoryID != tt.lineData.CategoryID {
					t.Errorf("Expected category_id %q but got %q", tt.lineData.CategoryID, categoryID)
				}
			}
		})
	}
}

func TestDeleteLine(t *testing.T) {
	db, err := SetupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}
	defer func() {
		if err := CloseDB(db); err != nil {
			t.Errorf("Failed to close test database: %v", err)
		}
	}()

	// Create test category and line
	categoryID, err := InsertTestCategory(db, "Test Category")
	if err != nil {
		t.Fatalf("Failed to insert test category: %v", err)
	}

	lineID, err := InsertTestLine(db, "Test Line", categoryID)
	if err != nil {
		t.Fatalf("Failed to insert test line: %v", err)
	}

	tests := []struct {
		name        string
		id          string
		expectError bool
	}{
		{
			name:        "sucesso - deleção normal",
			id:          lineID,
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
			lineStore := NewLineStore(db)
			err := lineStore.DeleteLine(tt.id)

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}

			if !tt.expectError {
				// Verify deletion
				var count int
				err = db.QueryRow("SELECT COUNT(*) FROM lines WHERE id = ?", tt.id).Scan(&count)
				if err != nil {
					t.Errorf("Failed to query deleted line: %v", err)
				}
				if count != 0 {
					t.Error("Expected type to be deleted, but it still exists")
				}
			}
		})
	}
}
