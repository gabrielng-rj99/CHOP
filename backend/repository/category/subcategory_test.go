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

package categorystore

import (
	"Open-Generic-Hub/backend/domain"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func setupLineTestDB(t *testing.T) *sql.DB {
	db, err := SetupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}
	if err := ClearTables(db); err != nil {
		t.Fatalf("Failed to clear tables: %v", err)
	}
	return db
}

// TestGetAllSubcategories tests retrieving all license subcategories
func TestGetAllSubcategories(t *testing.T) {
	db := setupLineTestDB(t)
	defer CloseDB(db)

	subcategoryStore := NewSubcategoryStore(db)

	// Insert test data
	categoryID, err := InsertTestCategory(db, "Software")
	if err != nil {
		t.Fatalf("Failed to insert test category: %v", err)
	}

	// Insert multiple subcategories
	line1, err := InsertTestSubcategory(db, "Windows", categoryID)
	if err != nil {
		t.Fatalf("Failed to insert line 1: %v", err)
	}

	line2, err := InsertTestSubcategory(db, "Linux", categoryID)
	if err != nil {
		t.Fatalf("Failed to insert line 2: %v", err)
	}

	// Get all subcategories
	subcategories, err := subcategoryStore.GetAllSubcategories()
	if err != nil {
		t.Fatalf("Failed to get all subcategories: %v", err)
	}

	if len(subcategories) != 2 {
		t.Errorf("Expected 2 subcategories, got %d", len(subcategories))
	}

	// Verify subcategories are present
	subcategoryIDs := make(map[string]bool)
	for _, l := range subcategories {
		subcategoryIDs[l.ID] = true
	}

	if !subcategoryIDs[line1] || !subcategoryIDs[line2] {
		t.Error("Expected both subcategories in results")
	}
}

// TestUpdateSubcategoryCritical tests updating a line
func TestUpdateSubcategoryCritical(t *testing.T) {
	db := setupLineTestDB(t)
	defer CloseDB(db)

	subcategoryStore := NewSubcategoryStore(db)

	// Insert test data
	categoryID, err := InsertTestCategory(db, "Software")
	if err != nil {
		t.Fatalf("Failed to insert test category: %v", err)
	}

	subcategoryID, err := InsertTestSubcategory(db, "Original Subcategory", categoryID)
	if err != nil {
		t.Fatalf("Failed to insert test line: %v", err)
	}

	tests := []struct {
		name        string
		line        domain.Subcategory
		expectError bool
		errorMsg    string
	}{
		{
			name: "success - update line name",
			line: domain.Subcategory{
				ID:         subcategoryID,
				Name:       "Updated Subcategory",
				CategoryID: categoryID,
			},
			expectError: false,
		},
		{
			name: "error - empty line id",
			line: domain.Subcategory{
				ID:         "",
				Name:       "Test",
				CategoryID: categoryID,
			},
			expectError: true,
		},
		{
			name: "error - empty line name",
			line: domain.Subcategory{
				ID:         subcategoryID,
				Name:       "",
				CategoryID: categoryID,
			},
			expectError: true,
		},
		{
			name: "error - line name too long",
			line: domain.Subcategory{
				ID:         subcategoryID,
				Name:       string(make([]byte, 256)),
				CategoryID: categoryID,
			},
			expectError: true,
			errorMsg:    "255",
		},
		{
			name: "error - empty category id",
			line: domain.Subcategory{
				ID:         subcategoryID,
				Name:       "Test",
				CategoryID: "",
			},
			expectError: true,
		},
		{
			name: "error - non-existent category",
			line: domain.Subcategory{
				ID:         subcategoryID,
				Name:       "Test",
				CategoryID: uuid.New().String(),
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := subcategoryStore.UpdateSubcategory(tt.line)

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}
		})
	}
}

// TestDeleteSubcategoryCritical tests deleting a line
func TestDeleteSubcategoryCritical(t *testing.T) {
	db := setupLineTestDB(t)
	defer CloseDB(db)

	subcategoryStore := NewSubcategoryStore(db)

	// Insert test data
	categoryID, err := InsertTestCategory(db, "Software")
	if err != nil {
		t.Fatalf("Failed to insert test category: %v", err)
	}

	subcategoryID, err := InsertTestSubcategory(db, "Test Subcategory", categoryID)
	if err != nil {
		t.Fatalf("Failed to insert test line: %v", err)
	}

	// Delete the line
	err = subcategoryStore.DeleteSubcategory(subcategoryID)
	if err != nil {
		t.Errorf("Expected no error deleting line, got: %v", err)
	}

	// Verify line is deleted
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM subcategories WHERE id = $1", subcategoryID).Scan(&count)
	if err != nil {
		t.Fatalf("Failed to query line: %v", err)
	}
	if count != 0 {
		t.Error("Expected line to be deleted")
	}
}

// TestDeleteSubcategoryWithActiveContracts tests that deletion fails with associated contracts
func TestDeleteSubcategoryWithActiveContracts(t *testing.T) {
	db := setupLineTestDB(t)
	defer CloseDB(db)

	subcategoryStore := NewSubcategoryStore(db)

	// Insert test data
	clientID, err := InsertTestClient(db, "Test Client", "45.723.174/0001-10")
	if err != nil {
		t.Fatalf("Failed to insert test client: %v", err)
	}

	categoryID, err := InsertTestCategory(db, "Software")
	if err != nil {
		t.Fatalf("Failed to insert test category: %v", err)
	}

	subcategoryID, err := InsertTestSubcategory(db, "Test Subcategory", categoryID)
	if err != nil {
		t.Fatalf("Failed to insert test line: %v", err)
	}

	// Insert a license for this line
	now := time.Now()
	_, err = InsertTestContract(db, "Test License", "TEST-KEY", timePtr(now.AddDate(0, 0, -10)), timePtr(now.AddDate(0, 0, 30)), subcategoryID, clientID, nil)
	if err != nil {
		t.Fatalf("Failed to insert test license: %v", err)
	}

	// Try to delete - should fail
	err = subcategoryStore.DeleteSubcategory(subcategoryID)
	if err == nil {
		t.Error("Expected error deleting line with associated contracts")
	}

	// Verify line still exists
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM subcategories WHERE id = $1", subcategoryID).Scan(&count)
	if err != nil {
		t.Fatalf("Failed to query line: %v", err)
	}
	if count != 1 {
		t.Error("Expected line to still exist after failed deletion")
	}
}

// TestUpdateSubcategoryCannotMoveBetweenCategories tests that subcategories cannot be moved between categories
func TestUpdateSubcategoryCannotMoveBetweenCategories(t *testing.T) {
	db := setupLineTestDB(t)
	defer CloseDB(db)

	subcategoryStore := NewSubcategoryStore(db)

	// Insert test data
	categoryID1, err := InsertTestCategory(db, "Software")
	if err != nil {
		t.Fatalf("Failed to insert category 1: %v", err)
	}

	categoryID2, err := InsertTestCategory(db, "Hardware")
	if err != nil {
		t.Fatalf("Failed to insert category 2: %v", err)
	}

	subcategoryID, err := InsertTestSubcategory(db, "Test Subcategory", categoryID1)
	if err != nil {
		t.Fatalf("Failed to insert test line: %v", err)
	}

	// Try to move line to different category
	updatedLine := domain.Subcategory{
		ID:         subcategoryID,
		Name:       "Test Subcategory",
		CategoryID: categoryID2,
	}

	err = subcategoryStore.UpdateSubcategory(updatedLine)
	if err == nil {
		t.Error("Expected error when trying to move line between categories")
	}

	// Verify line is still in original category
	var currentCategoryID string
	err = db.QueryRow("SELECT category_id FROM subcategories WHERE id = $1", subcategoryID).Scan(&currentCategoryID)
	if err != nil {
		t.Fatalf("Failed to query line: %v", err)
	}
	if currentCategoryID != categoryID1 {
		t.Errorf("Expected line to still be in category '%s', got '%s'", categoryID1, currentCategoryID)
	}
}

// TestGetLinesByCategory tests retrieving subcategories by category
func TestGetLinesByCategory(t *testing.T) {
	db := setupLineTestDB(t)
	defer CloseDB(db)

	subcategoryStore := NewSubcategoryStore(db)

	// Insert test data
	categoryID1, err := InsertTestCategory(db, "Software")
	if err != nil {
		t.Fatalf("Failed to insert category 1: %v", err)
	}

	categoryID2, err := InsertTestCategory(db, "Hardware")
	if err != nil {
		t.Fatalf("Failed to insert category 2: %v", err)
	}

	// Insert subcategories for different categories
	line1, err := InsertTestSubcategory(db, "Windows", categoryID1)
	if err != nil {
		t.Fatalf("Failed to insert line 1: %v", err)
	}

	line2, err := InsertTestSubcategory(db, "Linux", categoryID1)
	if err != nil {
		t.Fatalf("Failed to insert line 2: %v", err)
	}

	line3, err := InsertTestSubcategory(db, "Monitor", categoryID2)
	if err != nil {
		t.Fatalf("Failed to insert line 3: %v", err)
	}

	// Get subcategories for category 1
	subcategories, err := subcategoryStore.GetSubcategoriesByCategoryID(categoryID1)
	if err != nil {
		t.Fatalf("Failed to get subcategories by category: %v", err)
	}

	if len(subcategories) != 2 {
		t.Errorf("Expected 2 subcategories for category 1, got %d", len(subcategories))
	}

	// Verify correct subcategories are returned
	subcategoryIDs := make(map[string]bool)
	for _, l := range subcategories {
		subcategoryIDs[l.ID] = true
		if l.CategoryID != categoryID1 {
			t.Errorf("Expected category ID '%s', got '%s'", categoryID1, l.CategoryID)
		}
	}

	if !subcategoryIDs[line1] || !subcategoryIDs[line2] {
		t.Error("Expected subcategories 1 and 2 in results")
	}
	if subcategoryIDs[line3] {
		t.Error("Did not expect line 3 in results")
	}
}

// TestCreateSubcategoryUniquePerCategory tests that line names must be unique per category
func TestCreateSubcategoryUniquePerCategory(t *testing.T) {
	db := setupLineTestDB(t)
	defer CloseDB(db)

	subcategoryStore := NewSubcategoryStore(db)

	// Insert test data
	categoryID, err := InsertTestCategory(db, "Software")
	if err != nil {
		t.Fatalf("Failed to insert test category: %v", err)
	}

	// Create first line
	firstLine := domain.Subcategory{
		Name:       "Windows",
		CategoryID: categoryID,
	}

	id, err := subcategoryStore.CreateSubcategory(firstLine)
	if err != nil {
		t.Fatalf("Failed to create first line: %v", err)
	}
	if id == "" {
		t.Error("Expected line ID")
	}

	// Try to create duplicate line in same category
	duplicateLine := domain.Subcategory{
		Name:       "Windows",
		CategoryID: categoryID,
	}

	_, err = subcategoryStore.CreateSubcategory(duplicateLine)
	if err == nil {
		t.Error("Expected error creating duplicate line in same category")
	}
}

// TestGetSubcategoryByIDCritical tests retrieving a specific line
func TestGetSubcategoryByIDCritical(t *testing.T) {
	db := setupLineTestDB(t)
	defer CloseDB(db)

	subcategoryStore := NewSubcategoryStore(db)

	// Insert test data
	categoryID, err := InsertTestCategory(db, "Software")
	if err != nil {
		t.Fatalf("Failed to insert test category: %v", err)
	}

	subcategoryID, err := InsertTestSubcategory(db, "Test Subcategory", categoryID)
	if err != nil {
		t.Fatalf("Failed to insert test line: %v", err)
	}

	// Get the line
	line, err := subcategoryStore.GetSubcategoryByID(subcategoryID)
	if err != nil {
		t.Fatalf("Failed to get line: %v", err)
	}

	if line == nil {
		t.Error("Expected line, got nil")
	}

	if line != nil && line.ID != subcategoryID {
		t.Errorf("Expected line ID '%s', got '%s'", subcategoryID, line.ID)
	}

	if line != nil && line.Name != "Test Subcategory" {
		t.Errorf("Expected line name 'Test Subcategory', got '%s'", line.Name)
	}

	if line != nil && line.CategoryID != categoryID {
		t.Errorf("Expected category ID '%s', got '%s'", categoryID, line.CategoryID)
	}
}

// TestGetSubcategoryByIDNonExistent tests retrieving a non-existent line
func TestGetSubcategoryByIDNonExistent(t *testing.T) {
	db := setupLineTestDB(t)
	defer CloseDB(db)

	subcategoryStore := NewSubcategoryStore(db)

	line, err := subcategoryStore.GetSubcategoryByID(uuid.New().String())
	if err != nil {
		t.Fatalf("Expected no error for non-existent line, got: %v", err)
	}

	if line != nil {
		t.Error("Expected nil for non-existent line")
	}
}

// ============================================================================
// CATEGORY AND LINES VALIDATION & EDGE CASES
// ============================================================================

// TestCreateCategoryWithInvalidNames tests various invalid category name formats
func TestCreateCategoryWithInvalidNames(t *testing.T) {
	db, err := SetupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}
	defer CloseDB(db)

	categoryStore := NewCategoryStore(db)

	// Generate long names
	longName := strings.Repeat("a", 256)
	veryLongName := strings.Repeat("a", 1000)

	tests := []struct {
		name         string
		categoryName string
		expectError  bool
		description  string
	}{
		{
			name:         "invalid - name too long (256 chars)",
			categoryName: longName,
			expectError:  true,
			description:  "Category name with 256 characters should be rejected",
		},
		{
			name:         "invalid - name way too long (1000 chars)",
			categoryName: veryLongName,
			expectError:  true,
			description:  "Category name with 1000 characters should be rejected",
		},
		{
			name:         "invalid - name with only spaces",
			categoryName: "     ",
			expectError:  true,
			description:  "Category name with only whitespace should be rejected",
		},
		{
			name:         "invalid - name with only tabs",
			categoryName: "\t\t\t",
			expectError:  true,
			description:  "Category name with only tabs should be rejected",
		},
		{
			name:         "valid - name at max length (255 chars)",
			categoryName: strings.Repeat("a", 255),
			expectError:  false,
			description:  "Category name with exactly 255 characters should be allowed",
		},
		{
			name:         "valid - name with special characters",
			categoryName: "Software & Hardware - 2025",
			expectError:  false,
			description:  "Category name with special characters should be allowed",
		},
		{
			name:         "valid - name with accents",
			categoryName: "Tecnologia & Inovação",
			expectError:  false,
			description:  "Category name with Portuguese accents should be allowed",
		},
		{
			name:         "valid - name with numbers",
			categoryName: "Category 123",
			expectError:  false,
			description:  "Category name with numbers should be allowed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear tables between tests to avoid duplicates
			if err := ClearTables(db); err != nil {
				t.Fatalf("Failed to clear tables: %v", err)
			}

			category := domain.Category{
				Name: tt.categoryName,
			}

			_, err := categoryStore.CreateCategory(category)

			if tt.expectError && err == nil {
				t.Errorf("Expected error for %s, but got none", tt.description)
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error for %s, but got: %v", tt.description, err)
			}
		})
	}
}

// TestUpdateCategoryWithInvalidData tests update operations with invalid data
func TestUpdateCategoryWithInvalidData(t *testing.T) {
	db, err := SetupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}
	defer CloseDB(db)

	categoryStore := NewCategoryStore(db)

	// Create initial category
	categoryID, err := InsertTestCategory(db, "Original Category")
	if err != nil {
		t.Fatalf("Failed to insert test category: %v", err)
	}

	tests := []struct {
		name        string
		category    domain.Category
		expectError bool
		description string
	}{
		{
			name: "invalid - update with name too long",
			category: domain.Category{
				ID:   categoryID,
				Name: strings.Repeat("a", 256),
			},
			expectError: true,
			description: "Update with name too long should fail",
		},
		{
			name: "invalid - update with only whitespace",
			category: domain.Category{
				ID:   categoryID,
				Name: "    ",
			},
			expectError: true,
			description: "Update with whitespace-only name should fail",
		},
		{
			name: "invalid - update with empty name",
			category: domain.Category{
				ID:   categoryID,
				Name: "",
			},
			expectError: true,
			description: "Update with empty name should fail",
		},
		{
			name: "valid - update with valid name",
			category: domain.Category{
				ID:   categoryID,
				Name: "Updated Category Name",
			},
			expectError: false,
			description: "Update with valid name should succeed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := categoryStore.UpdateCategory(tt.category)

			if tt.expectError && err == nil {
				t.Errorf("Expected error for %s, but got none", tt.description)
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error for %s, but got: %v", tt.description, err)
			}
		})
	}
}

// TestCategoryNameTrimming tests that whitespace is properly handled for categories
func TestCategoryNameTrimming(t *testing.T) {
	db, err := SetupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}
	defer CloseDB(db)

	categoryStore := NewCategoryStore(db)

	tests := []struct {
		name         string
		inputName    string
		expectedName string
		expectError  bool
	}{
		{
			name:         "name with leading spaces",
			inputName:    "   Leading Spaces",
			expectedName: "Leading Spaces",
			expectError:  false,
		},
		{
			name:         "name with trailing spaces",
			inputName:    "Trailing Spaces   ",
			expectedName: "Trailing Spaces",
			expectError:  false,
		},
		{
			name:         "name with both leading and trailing spaces",
			inputName:    "   Both Spaces   ",
			expectedName: "Both Spaces",
			expectError:  false,
		},
		{
			name:        "only spaces",
			inputName:   "     ",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear tables between tests
			if err := ClearTables(db); err != nil {
				t.Fatalf("Failed to clear tables: %v", err)
			}

			category := domain.Category{
				Name: tt.inputName,
			}

			id, err := categoryStore.CreateCategory(category)

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}

			// If creation succeeded, verify the name was trimmed
			if !tt.expectError && err == nil {
				retrievedCategory, err := categoryStore.GetCategoryByID(id)
				if err != nil {
					t.Errorf("Failed to retrieve category: %v", err)
				}
				if retrievedCategory != nil && retrievedCategory.Name != tt.expectedName {
					t.Errorf("Expected name '%s', got '%s'", tt.expectedName, retrievedCategory.Name)
				}
			}
		})
	}
}

// TestCreateSubcategoryWithInvalidNames tests various invalid line name formats
func TestCreateSubcategoryWithInvalidNames(t *testing.T) {
	db, err := SetupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}
	defer CloseDB(db)

	// Create category first
	categoryID, err := InsertTestCategory(db, "Test Category")
	if err != nil {
		t.Fatalf("Failed to insert test category: %v", err)
	}

	subcategoryStore := NewSubcategoryStore(db)

	// Generate long names
	longName := strings.Repeat("a", 256)
	veryLongName := strings.Repeat("a", 1000)

	tests := []struct {
		name        string
		lineName    string
		expectError bool
		description string
	}{
		{
			name:        "invalid - name too long (256 chars)",
			lineName:    longName,
			expectError: true,
			description: "Subcategory name with 256 characters should be rejected",
		},
		{
			name:        "invalid - name way too long (1000 chars)",
			lineName:    veryLongName,
			expectError: true,
			description: "Subcategory name with 1000 characters should be rejected",
		},
		{
			name:        "invalid - name with only spaces",
			lineName:    "     ",
			expectError: true,
			description: "Subcategory name with only whitespace should be rejected",
		},
		{
			name:        "valid - name at max length (255 chars)",
			lineName:    strings.Repeat("a", 255),
			expectError: false,
			description: "Subcategory name with exactly 255 characters should be allowed",
		},
		{
			name:        "valid - name with special characters",
			lineName:    "Subcategory Pro - Edition 2025",
			expectError: false,
			description: "Subcategory name with special characters should be allowed",
		},
		{
			name:        "valid - name with accents",
			lineName:    "Linha Profissional",
			expectError: false,
			description: "Subcategory name with Portuguese accents should be allowed",
		},
	}

	counter := 0
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			line := domain.Subcategory{
				Name:       tt.lineName,
				CategoryID: categoryID,
			}

			_, err := subcategoryStore.CreateSubcategory(line)

			if tt.expectError && err == nil {
				t.Errorf("Expected error for %s, but got none", tt.description)
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error for %s, but got: %v", tt.description, err)
			}
			counter++
		})
	}
}

// TestCreateSubcategoryWithInvalidCategory tests line creation with invalid category
func TestCreateSubcategoryWithInvalidCategory(t *testing.T) {
	db, err := SetupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}
	defer CloseDB(db)

	subcategoryStore := NewSubcategoryStore(db)

	tests := []struct {
		name        string
		categoryID  string
		expectError bool
		description string
	}{
		{
			name:        "invalid - non-existent category",
			categoryID:  "non-existent-category-id",
			expectError: true,
			description: "Subcategory with non-existent category should be rejected",
		},
		{
			name:        "invalid - empty category ID",
			categoryID:  "",
			expectError: true,
			description: "Subcategory with empty category ID should be rejected",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			line := domain.Subcategory{
				Name:       "Test Subcategory",
				CategoryID: tt.categoryID,
			}

			_, err := subcategoryStore.CreateSubcategory(line)

			if tt.expectError && err == nil {
				t.Errorf("Expected error for %s, but got none", tt.description)
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error for %s, but got: %v", tt.description, err)
			}
		})
	}
}

// TestLineNameUniquePerCategoryAdvanced tests advanced uniqueness scenarios
func TestLineNameUniquePerCategoryAdvanced(t *testing.T) {
	db, err := SetupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}
	defer CloseDB(db)

	subcategoryStore := NewSubcategoryStore(db)

	// Create two categories
	category1ID, err := InsertTestCategory(db, "Category 1")
	if err != nil {
		t.Fatalf("Failed to insert category 1: %v", err)
	}

	category2ID, err := InsertTestCategory(db, "Category 2")
	if err != nil {
		t.Fatalf("Failed to insert category 2: %v", err)
	}

	// Create line in category 1
	_, err = subcategoryStore.CreateSubcategory(domain.Subcategory{
		Name:       "Shared Subcategory Name",
		CategoryID: category1ID,
	})
	if err != nil {
		t.Fatalf("Failed to create line in category 1: %v", err)
	}

	tests := []struct {
		name        string
		lineName    string
		categoryID  string
		expectError bool
		description string
	}{
		{
			name:        "duplicate - same name in same category",
			lineName:    "Shared Subcategory Name",
			categoryID:  category1ID,
			expectError: true,
			description: "Duplicate line name in same category should be rejected",
		},
		{
			name:        "valid - same name in different category",
			lineName:    "Shared Subcategory Name",
			categoryID:  category2ID,
			expectError: false,
			description: "Same line name in different category should be allowed",
		},
		{
			name:        "duplicate - case sensitivity check (lowercase)",
			lineName:    "shared subcategory name",
			categoryID:  category1ID,
			expectError: true, // Depends on DB collation - may need to adjust
			description: "Subcategory name with different case in same category",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			line := domain.Subcategory{
				Name:       tt.lineName,
				CategoryID: tt.categoryID,
			}

			_, err := subcategoryStore.CreateSubcategory(line)

			if tt.expectError && err == nil {
				t.Errorf("Expected error for %s, but got none", tt.description)
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error for %s, but got: %v", tt.description, err)
			}
		})
	}
}

// TestUpdateSubcategoryWithInvalidData tests update operations with invalid data
func TestUpdateSubcategoryWithInvalidData(t *testing.T) {
	db, err := SetupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}
	defer CloseDB(db)

	if err := ClearTables(db); err != nil {
		t.Fatalf("Failed to clear tables: %v", err)
	}

	subcategoryStore := NewSubcategoryStore(db)

	// Create category and line
	categoryID, err := InsertTestCategory(db, "TestCategory-"+uuid.New().String()[:8])
	if err != nil {
		t.Fatalf("Failed to insert test category: %v", err)
	}

	subcategoryID, err := InsertTestSubcategory(db, "Original Subcategory", categoryID)
	if err != nil {
		t.Fatalf("Failed to insert test line: %v", err)
	}

	tests := []struct {
		name        string
		line        domain.Subcategory
		expectError bool
		description string
	}{
		{
			name: "invalid - update with name too long",
			line: domain.Subcategory{
				ID:         subcategoryID,
				Name:       strings.Repeat("a", 256),
				CategoryID: categoryID,
			},
			expectError: true,
			description: "Update with name too long should fail",
		},
		{
			name: "invalid - update with only whitespace",
			line: domain.Subcategory{
				ID:         subcategoryID,
				Name:       "    ",
				CategoryID: categoryID,
			},
			expectError: true,
			description: "Update with whitespace-only name should fail",
		},
		{
			name: "invalid - update with empty name",
			line: domain.Subcategory{
				ID:         subcategoryID,
				Name:       "",
				CategoryID: categoryID,
			},
			expectError: true,
			description: "Update with empty name should fail",
		},
		{
			name: "valid - update with valid name",
			line: domain.Subcategory{
				ID:         subcategoryID,
				Name:       "Updated Subcategory Name",
				CategoryID: categoryID,
			},
			expectError: false,
			description: "Update with valid name should succeed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := subcategoryStore.UpdateSubcategory(tt.line)

			if tt.expectError && err == nil {
				t.Errorf("Expected error for %s, but got none", tt.description)
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error for %s, but got: %v", tt.description, err)
			}
		})
	}
}

// TestCreateAffiliateWithInvalidNames tests various invalid affiliate name formats
func TestCreateAffiliateWithInvalidNames(t *testing.T) {
	db, err := SetupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}
	defer CloseDB(db)

	if err := ClearTables(db); err != nil {
		t.Fatalf("Failed to clear tables: %v", err)
	}

	// Create test client first
	clientID, err := InsertTestClient(db, "TestClient-"+uuid.New().String()[:8], generateUniqueCNPJ())
	if err != nil {
		t.Fatalf("Failed to insert test client: %v", err)
	}

	subClientStore := NewAffiliateStore(db)

	// Generate long names
	longName := strings.Repeat("a", 256)
	veryLongName := strings.Repeat("a", 1000)

	tests := []struct {
		name          string
		affiliateName string
		expectError   bool
		description   string
	}{
		{
			name:          "invalid - name too long (256 chars)",
			affiliateName: longName,
			expectError:   true,
			description:   "Affiliate name with 256 characters should be rejected",
		},
		{
			name:          "invalid - name way too long (1000 chars)",
			affiliateName: veryLongName,
			expectError:   true,
			description:   "Affiliate name with 1000 characters should be rejected",
		},
		{
			name:          "invalid - name with only spaces",
			affiliateName: "     ",
			expectError:   true,
			description:   "Affiliate name with only whitespace should be rejected",
		},
		{
			name:          "valid - name at max length (255 chars)",
			affiliateName: strings.Repeat("a", 255),
			expectError:   false,
			description:   "Affiliate name with exactly 255 characters should be allowed",
		},
		{
			name:          "valid - name with special characters",
			affiliateName: "Unit A - Building 2",
			expectError:   false,
			description:   "Affiliate name with special characters should be allowed",
		},
		{
			name:          "valid - name with accents",
			affiliateName: "Unidade São Paulo",
			expectError:   false,
			description:   "Affiliate name with Portuguese accents should be allowed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear affiliates table between tests
			_, err = db.Exec("DELETE FROM affiliates")
			if err != nil {
				t.Fatalf("Failed to clear affiliates: %v", err)
			}

			affiliate := domain.Affiliate{
				Name:     tt.affiliateName,
				ClientID: clientID,
				Status:   "ativo",
			}

			_, err = subClientStore.CreateAffiliate(affiliate)

			if tt.expectError && err == nil {
				t.Errorf("Expected error for %s, but got none", tt.description)
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error for %s, but got: %v", tt.description, err)
			}
		})
	}
}

// TestCreateAffiliateWithInvalidClient tests affiliate creation with invalid client
func TestCreateAffiliateWithInvalidClient(t *testing.T) {
	db, err := SetupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}
	defer CloseDB(db)

	subClientStore := NewAffiliateStore(db)

	tests := []struct {
		name        string
		clientID    string
		expectError bool
		description string
	}{
		{
			name:        "invalid - non-existent client",
			clientID:    "non-existent-client-id",
			expectError: true,
			description: "Affiliate with non-existent client should be rejected",
		},
		{
			name:        "invalid - empty client ID",
			clientID:    "",
			expectError: true,
			description: "Affiliate with empty client ID should be rejected",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			affiliate := domain.Affiliate{
				Name:     "Test Affiliate",
				ClientID: tt.clientID,
				Status:   "ativo",
			}

			_, err := subClientStore.CreateAffiliate(affiliate)

			if tt.expectError && err == nil {
				t.Errorf("Expected error for %s, but got none", tt.description)
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error for %s, but got: %v", tt.description, err)
			}
		})
	}
}

// TestUpdateAffiliateWithInvalidData tests update operations with invalid data
func TestUpdateAffiliateWithInvalidData(t *testing.T) {
	db, err := SetupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}
	defer CloseDB(db)

	subClientStore := NewAffiliateStore(db)

	// Create client and affiliate
	clientID, err := InsertTestClient(db, "Test Client", "45.723.174/0001-10")
	if err != nil {
		t.Fatalf("Failed to insert test client: %v", err)
	}

	subClientID := uuid.New().String()
	_, err = db.Exec("INSERT INTO affiliates (id, name, client_id) VALUES ($1, $2, $3)",
		subClientID, "Original Affiliate", clientID)
	if err != nil {
		t.Fatalf("Failed to insert test affiliate: %v", err)
	}

	tests := []struct {
		name        string
		affiliate   domain.Affiliate
		expectError bool
		description string
	}{
		{
			name: "invalid - update with name too long",
			affiliate: domain.Affiliate{
				ID:       subClientID,
				Name:     strings.Repeat("a", 256),
				ClientID: clientID,
				Status:   "ativo",
			},
			expectError: true,
			description: "Update with name too long should fail",
		},
		{
			name: "invalid - update with only whitespace",
			affiliate: domain.Affiliate{
				ID:       subClientID,
				Name:     "    ",
				ClientID: clientID,
				Status:   "ativo",
			},
			expectError: true,
			description: "Update with whitespace-only name should fail",
		},
		{
			name: "invalid - update with empty name",
			affiliate: domain.Affiliate{
				ID:       subClientID,
				Name:     "",
				ClientID: clientID,
				Status:   "ativo",
			},
			expectError: true,
			description: "Update with empty name should fail",
		},
		{
			name: "valid - update with valid name",
			affiliate: domain.Affiliate{
				ID:       subClientID,
				Name:     "Updated Affiliate Name",
				ClientID: clientID,
				Status:   "ativo",
			},
			expectError: false,
			description: "Update with valid name should succeed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := subClientStore.UpdateAffiliate(tt.affiliate)

			if tt.expectError && err == nil {
				t.Errorf("Expected error for %s, but got none", tt.description)
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error for %s, but got: %v", tt.description, err)
			}
		})
	}
}

// TestAffiliateNameTrimming tests that whitespace is properly handled for affiliates
func TestAffiliateNameTrimming(t *testing.T) {
	db, err := SetupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}
	defer CloseDB(db)

	if err := ClearTables(db); err != nil {
		t.Fatalf("Failed to clear tables: %v", err)
	}

	// Create test client first
	clientID, err := InsertTestClient(db, "TestClient-"+uuid.New().String()[:8], generateUniqueCNPJ())
	if err != nil {
		t.Fatalf("Failed to insert test client: %v", err)
	}

	subClientStore := NewAffiliateStore(db)

	tests := []struct {
		name         string
		inputName    string
		expectedName string
		expectError  bool
	}{
		{
			name:         "name with leading spaces",
			inputName:    "   Leading Spaces",
			expectedName: "Leading Spaces",
			expectError:  false,
		},
		{
			name:         "name with trailing spaces",
			inputName:    "Trailing Spaces   ",
			expectedName: "Trailing Spaces",
			expectError:  false,
		},
		{
			name:         "name with both leading and trailing spaces",
			inputName:    "   Both Spaces   ",
			expectedName: "Both Spaces",
			expectError:  false,
		},
		{
			name:        "only spaces",
			inputName:   "     ",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear affiliates between tests
			_, err := db.Exec("DELETE FROM affiliates")
			if err != nil {
				t.Fatalf("Failed to clear affiliates: %v", err)
			}

			affiliate := domain.Affiliate{
				Name:     tt.inputName,
				ClientID: clientID,
				Status:   "ativo",
			}

			id, err := subClientStore.CreateAffiliate(affiliate)

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}

			// If creation succeeded, verify the name was trimmed
			if !tt.expectError && err == nil {
				retrievedAffiliate, err := subClientStore.GetAffiliateByID(id)
				if err != nil {
					t.Errorf("Failed to retrieve affiliate: %v", err)
				}
				if retrievedAffiliate != nil && retrievedAffiliate.Name != tt.expectedName {
					t.Errorf("Expected name '%s', got '%s'", tt.expectedName, retrievedAffiliate.Name)
				}
			}
		})
	}
}

func TestArchiveSubcategory(t *testing.T) {
	db := setupLineTestDB(t)
	defer CloseDB(db)

	subcategoryStore := NewSubcategoryStore(db)

	// Insert test data
	categoryID, err := InsertTestCategory(db, "Software")
	if err != nil {
		t.Fatalf("Failed to insert test category: %v", err)
	}

	id, err := InsertTestSubcategory(db, "Archivable Line", categoryID)
	if err != nil {
		t.Fatalf("Failed to insert test line: %v", err)
	}

	// Archive
	err = subcategoryStore.ArchiveSubcategory(id)
	if err != nil {
		t.Fatalf("Failed to archive line: %v", err)
	}

	// Verify not in standard list
	lines, err := subcategoryStore.GetAllSubcategories()
	if err != nil {
		t.Fatalf("GetAllSubcategories failed: %v", err)
	}
	for _, l := range lines {
		if l.ID == id {
			t.Error("Archived line should not appear in GetAllSubcategories")
		}
	}

	// Verify in including archived
	linesArch, err := subcategoryStore.GetAllSubcategoriesIncludingArchived()
	if err != nil {
		t.Fatalf("GetAllSubcategoriesIncludingArchived failed: %v", err)
	}
	found := false
	for _, l := range linesArch {
		if l.ID == id {
			found = true
			if l.ArchivedAt == nil {
				t.Error("Archived line should have ArchivedAt set")
			}
			break
		}
	}
	if !found {
		t.Error("Archived line should appear in GetAllSubcategoriesIncludingArchived")
	}

	// Unarchive
	err = subcategoryStore.UnarchiveSubcategory(id)
	if err != nil {
		t.Fatalf("Failed to unarchive line: %v", err)
	}

	// Verify back in standard list
	lines, err = subcategoryStore.GetAllSubcategories()
	if err != nil {
		t.Fatalf("GetAllSubcategories failed: %v", err)
	}
	found = false
	for _, l := range lines {
		if l.ID == id {
			found = true
			break
		}
	}
	if !found {
		t.Error("Unarchived line should appear in GetAllSubcategories")
	}
}

func TestGetSubcategoriesByName(t *testing.T) {
	db := setupLineTestDB(t)
	defer CloseDB(db)

	subcategoryStore := NewSubcategoryStore(db)
	categoryID, _ := InsertTestCategory(db, "Software")

	InsertTestSubcategory(db, "Alpha Line", categoryID)
	InsertTestSubcategory(db, "Beta Line", categoryID)
	InsertTestSubcategory(db, "Alpha Two", categoryID)

	lines, err := subcategoryStore.GetSubcategoriesByName("Alpha")
	if err != nil {
		t.Fatalf("GetSubcategoriesByName failed: %v", err)
	}
	if len(lines) != 2 {
		t.Errorf("Expected 2 lines, got %d", len(lines))
	}

	lines, err = subcategoryStore.GetSubcategoriesByName("Beta")
	if err != nil {
		t.Fatalf("GetSubcategoriesByName failed: %v", err)
	}
	if len(lines) != 1 {
		t.Errorf("Expected 1 line, got %d", len(lines))
	}
}
