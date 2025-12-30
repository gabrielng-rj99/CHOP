/*
 * Client Hub Open Project
 * Copyright (C) 2025 Client Hub Contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package store

import (
	"Open-Generic-Hub/backend/domain"
	"testing"

	"github.com/google/uuid"
)

func TestCreateSubcategory(t *testing.T) {
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

	// Create a test category first
	categoryID, err := InsertTestCategory(db, "Test Category")
	if err != nil {
		t.Fatalf("Failed to insert test category: %v", err)
	}

	tests := []struct {
		name        string
		lineData    domain.Subcategory
		expectError bool
	}{
		{
			name: "sucesso - criação normal",
			lineData: domain.Subcategory{
				Name:       "Test Subcategory",
				CategoryID: categoryID,
			},
			expectError: false,
		},
		{
			name: "erro - nome vazio",
			lineData: domain.Subcategory{
				Name:       "",
				CategoryID: categoryID,
			},
			expectError: true,
		},
		{
			name: "erro - categoria não existe",
			lineData: domain.Subcategory{
				Name:       "Test Subcategory",
				CategoryID: "non-existent-category",
			},
			expectError: true,
		},
		{
			name: "erro - categoria vazia",
			lineData: domain.Subcategory{
				Name:       "Test Subcategory",
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

			subcategoryStore := NewSubcategoryStore(db)
			id, err := subcategoryStore.CreateSubcategory(tt.lineData)

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

func TestGetSubcategoryByID(t *testing.T) {
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

	// Create a test category first
	// Create test category and line
	categoryID, err := InsertTestCategory(db, "Test Category")
	if err != nil {
		t.Fatalf("Failed to insert test category: %v", err)
	}

	subcategoryID, err := InsertTestSubcategory(db, "Test Subcategory", categoryID)
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
			id:          subcategoryID,
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
			id:          uuid.New().String(),
			expectError: false,
			expectFound: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			subcategoryStore := NewSubcategoryStore(db)
			lineData, err := subcategoryStore.GetSubcategoryByID(tt.id)

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

func TestGetSubcategoriesByCategoryID(t *testing.T) {
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

	// Create test categories
	categoryID, err := InsertTestCategory(db, "Test Category")
	if err != nil {
		t.Fatalf("Failed to insert test category: %v", err)
	}

	// Insert test subcategories
	testLines := []string{"Subcategory 1", "Subcategory 2", "Subcategory 3"}
	for _, name := range testLines {
		_, err := InsertTestSubcategory(db, name, categoryID)
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
			categoryID:  uuid.New().String(),
			expectError: false,
			expectCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			subcategoryStore := NewSubcategoryStore(db)
			subcategories, err := subcategoryStore.GetSubcategoriesByCategoryID(tt.categoryID)

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}
			if !tt.expectError && len(subcategories) != tt.expectCount {
				t.Errorf("Expected %d subcategories but got %d", tt.expectCount, len(subcategories))
			}
		})
	}
}

func TestUpdateSubcategory(t *testing.T) {
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

	// Create a test category first
	// Create test category and line
	categoryID, err := InsertTestCategory(db, "Test Category")
	if err != nil {
		t.Fatalf("Failed to insert test category: %v", err)
	}

	subcategoryID, err := InsertTestSubcategory(db, "Test Subcategory", categoryID)
	if err != nil {
		t.Fatalf("Failed to insert test line: %v", err)
	}

	tests := []struct {
		name        string
		lineData    domain.Subcategory
		expectError bool
	}{
		{
			name: "sucesso - atualização normal",
			lineData: domain.Subcategory{
				ID:         subcategoryID,
				Name:       "Updated Subcategory",
				CategoryID: categoryID,
			},
			expectError: false,
		},
		{
			name: "erro - id vazio",
			lineData: domain.Subcategory{
				ID:         "",
				Name:       "Updated Subcategory",
				CategoryID: categoryID,
			},
			expectError: true,
		},
		{
			name: "erro - nome vazio",
			lineData: domain.Subcategory{
				ID:         subcategoryID,
				Name:       "",
				CategoryID: categoryID,
			},
			expectError: true,
		},
		{
			name: "erro - categoria inválida",
			lineData: domain.Subcategory{
				ID:         subcategoryID,
				Name:       "Updated Subcategory",
				CategoryID: "non-existent-category",
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			subcategoryStore := NewSubcategoryStore(db)
			err := subcategoryStore.UpdateSubcategory(tt.lineData)

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}

			if !tt.expectError {
				// Verify update
				var name, categoryID string
				err = db.QueryRow("SELECT name, category_id FROM subcategories WHERE id = $1", tt.lineData.ID).
					Scan(&name, &categoryID)
				if err != nil {
					t.Errorf("Failed to query updated line: %v", err)
				}
				if name != tt.lineData.Name {
					t.Errorf("Expected type %q but got %q", tt.lineData.Name, name)
				}
				if categoryID != tt.lineData.CategoryID {
					t.Errorf("Expected category_id %q but got %q", tt.lineData.CategoryID, categoryID)
				}
			}
		})
	}
}

func TestDeleteSubcategory(t *testing.T) {
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

	// Create a test category first
	// Create test category and line
	categoryID, err := InsertTestCategory(db, "Test Category")
	if err != nil {
		t.Fatalf("Failed to insert test category: %v", err)
	}

	subcategoryID, err := InsertTestSubcategory(db, "Test Subcategory", categoryID)
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
			id:          subcategoryID,
			expectError: false,
		},
		{
			name:        "erro - id vazio",
			id:          "",
			expectError: true,
		},
		{
			name:        "erro - id inexistente",
			id:          uuid.New().String(),
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			subcategoryStore := NewSubcategoryStore(db)
			err := subcategoryStore.DeleteSubcategory(tt.id)

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}

			if !tt.expectError {
				// Verify deletion
				var count int
				err = db.QueryRow("SELECT COUNT(*) FROM subcategories WHERE id = $1", tt.id).Scan(&count)
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
