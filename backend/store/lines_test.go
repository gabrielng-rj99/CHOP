package store

import (
	"Contracts-Manager/backend/domain"
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
	return db
}

// TestGetAllLines tests retrieving all license lines
func TestGetAllLines(t *testing.T) {
	db := setupLineTestDB(t)
	defer CloseDB(db)

	lineStore := NewLineStore(db)

	// Insert test data
	categoryID, err := InsertTestCategory(db, "Software")
	if err != nil {
		t.Fatalf("Failed to insert test category: %v", err)
	}

	// Insert multiple lines
	line1, err := InsertTestLine(db, "Windows", categoryID)
	if err != nil {
		t.Fatalf("Failed to insert line 1: %v", err)
	}

	line2, err := InsertTestLine(db, "Linux", categoryID)
	if err != nil {
		t.Fatalf("Failed to insert line 2: %v", err)
	}

	// Get all lines
	lines, err := lineStore.GetAllLines()
	if err != nil {
		t.Fatalf("Failed to get all lines: %v", err)
	}

	if len(lines) != 2 {
		t.Errorf("Expected 2 lines, got %d", len(lines))
	}

	// Verify lines are present
	lineIDs := make(map[string]bool)
	for _, l := range lines {
		lineIDs[l.ID] = true
	}

	if !lineIDs[line1] || !lineIDs[line2] {
		t.Error("Expected both lines in results")
	}
}

// TestUpdateLineCritical tests updating a line
func TestUpdateLineCritical(t *testing.T) {
	db := setupLineTestDB(t)
	defer CloseDB(db)

	lineStore := NewLineStore(db)

	// Insert test data
	categoryID, err := InsertTestCategory(db, "Software")
	if err != nil {
		t.Fatalf("Failed to insert test category: %v", err)
	}

	lineID, err := InsertTestLine(db, "Original Line", categoryID)
	if err != nil {
		t.Fatalf("Failed to insert test line: %v", err)
	}

	tests := []struct {
		name        string
		line        domain.Line
		expectError bool
		errorMsg    string
	}{
		{
			name: "success - update line name",
			line: domain.Line{
				ID:         lineID,
				Line:       "Updated Line",
				CategoryID: categoryID,
			},
			expectError: false,
		},
		{
			name: "error - empty line id",
			line: domain.Line{
				ID:         "",
				Line:       "Test",
				CategoryID: categoryID,
			},
			expectError: true,
		},
		{
			name: "error - empty line name",
			line: domain.Line{
				ID:         lineID,
				Line:       "",
				CategoryID: categoryID,
			},
			expectError: true,
		},
		{
			name: "error - line name too long",
			line: domain.Line{
				ID:         lineID,
				Line:       string(make([]byte, 256)),
				CategoryID: categoryID,
			},
			expectError: true,
			errorMsg:    "255",
		},
		{
			name: "error - empty category id",
			line: domain.Line{
				ID:         lineID,
				Line:       "Test",
				CategoryID: "",
			},
			expectError: true,
		},
		{
			name: "error - non-existent category",
			line: domain.Line{
				ID:         lineID,
				Line:       "Test",
				CategoryID: uuid.New().String(),
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := lineStore.UpdateLine(tt.line)

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}
		})
	}
}

// TestDeleteLineCritical tests deleting a line
func TestDeleteLineCritical(t *testing.T) {
	db := setupLineTestDB(t)
	defer CloseDB(db)

	lineStore := NewLineStore(db)

	// Insert test data
	categoryID, err := InsertTestCategory(db, "Software")
	if err != nil {
		t.Fatalf("Failed to insert test category: %v", err)
	}

	lineID, err := InsertTestLine(db, "Test Line", categoryID)
	if err != nil {
		t.Fatalf("Failed to insert test line: %v", err)
	}

	// Delete the line
	err = lineStore.DeleteLine(lineID)
	if err != nil {
		t.Errorf("Expected no error deleting line, got: %v", err)
	}

	// Verify line is deleted
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM lines WHERE id = ?", lineID).Scan(&count)
	if err != nil {
		t.Fatalf("Failed to query line: %v", err)
	}
	if count != 0 {
		t.Error("Expected line to be deleted")
	}
}

// TestDeleteLineWithActiveContracts tests that deletion fails with associated contracts
func TestDeleteLineWithActiveContracts(t *testing.T) {
	db := setupLineTestDB(t)
	defer CloseDB(db)

	lineStore := NewLineStore(db)

	// Insert test data
	clientID, err := InsertTestClient(db, "Test Client", "45.723.174/0001-10")
	if err != nil {
		t.Fatalf("Failed to insert test client: %v", err)
	}

	categoryID, err := InsertTestCategory(db, "Software")
	if err != nil {
		t.Fatalf("Failed to insert test category: %v", err)
	}

	lineID, err := InsertTestLine(db, "Test Line", categoryID)
	if err != nil {
		t.Fatalf("Failed to insert test line: %v", err)
	}

	// Insert a license for this line
	now := time.Now()
	_, err = InsertTestContract(db, "Test License", "TEST-KEY", now.AddDate(0, 0, -10), now.AddDate(0, 0, 30), lineID, clientID, nil)
	if err != nil {
		t.Fatalf("Failed to insert test license: %v", err)
	}

	// Try to delete - should fail
	err = lineStore.DeleteLine(lineID)
	if err == nil {
		t.Error("Expected error deleting line with associated contracts")
	}

	// Verify line still exists
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM lines WHERE id = ?", lineID).Scan(&count)
	if err != nil {
		t.Fatalf("Failed to query line: %v", err)
	}
	if count != 1 {
		t.Error("Expected line to still exist after failed deletion")
	}
}

// TestUpdateLineCannotMoveBetweenCategories tests that lines cannot be moved between categories
func TestUpdateLineCannotMoveBetweenCategories(t *testing.T) {
	db := setupLineTestDB(t)
	defer CloseDB(db)

	lineStore := NewLineStore(db)

	// Insert test data
	categoryID1, err := InsertTestCategory(db, "Software")
	if err != nil {
		t.Fatalf("Failed to insert category 1: %v", err)
	}

	categoryID2, err := InsertTestCategory(db, "Hardware")
	if err != nil {
		t.Fatalf("Failed to insert category 2: %v", err)
	}

	lineID, err := InsertTestLine(db, "Test Line", categoryID1)
	if err != nil {
		t.Fatalf("Failed to insert test line: %v", err)
	}

	// Try to move line to different category
	updatedLine := domain.Line{
		ID:         lineID,
		Line:       "Test Line",
		CategoryID: categoryID2,
	}

	err = lineStore.UpdateLine(updatedLine)
	if err == nil {
		t.Error("Expected error when trying to move line between categories")
	}

	// Verify line is still in original category
	var currentCategoryID string
	err = db.QueryRow("SELECT category_id FROM lines WHERE id = ?", lineID).Scan(&currentCategoryID)
	if err != nil {
		t.Fatalf("Failed to query line: %v", err)
	}
	if currentCategoryID != categoryID1 {
		t.Errorf("Expected line to still be in category '%s', got '%s'", categoryID1, currentCategoryID)
	}
}

// TestGetLinesByCategory tests retrieving lines by category
func TestGetLinesByCategory(t *testing.T) {
	db := setupLineTestDB(t)
	defer CloseDB(db)

	lineStore := NewLineStore(db)

	// Insert test data
	categoryID1, err := InsertTestCategory(db, "Software")
	if err != nil {
		t.Fatalf("Failed to insert category 1: %v", err)
	}

	categoryID2, err := InsertTestCategory(db, "Hardware")
	if err != nil {
		t.Fatalf("Failed to insert category 2: %v", err)
	}

	// Insert lines for different categories
	line1, err := InsertTestLine(db, "Windows", categoryID1)
	if err != nil {
		t.Fatalf("Failed to insert line 1: %v", err)
	}

	line2, err := InsertTestLine(db, "Linux", categoryID1)
	if err != nil {
		t.Fatalf("Failed to insert line 2: %v", err)
	}

	line3, err := InsertTestLine(db, "Monitor", categoryID2)
	if err != nil {
		t.Fatalf("Failed to insert line 3: %v", err)
	}

	// Get lines for category 1
	lines, err := lineStore.GetLinesByCategoryID(categoryID1)
	if err != nil {
		t.Fatalf("Failed to get lines by category: %v", err)
	}

	if len(lines) != 2 {
		t.Errorf("Expected 2 lines for category 1, got %d", len(lines))
	}

	// Verify correct lines are returned
	lineIDs := make(map[string]bool)
	for _, l := range lines {
		lineIDs[l.ID] = true
		if l.CategoryID != categoryID1 {
			t.Errorf("Expected category ID '%s', got '%s'", categoryID1, l.CategoryID)
		}
	}

	if !lineIDs[line1] || !lineIDs[line2] {
		t.Error("Expected lines 1 and 2 in results")
	}
	if lineIDs[line3] {
		t.Error("Did not expect line 3 in results")
	}
}

// TestCreateLineUniquePerCategory tests that line names must be unique per category
func TestCreateLineUniquePerCategory(t *testing.T) {
	db := setupLineTestDB(t)
	defer CloseDB(db)

	lineStore := NewLineStore(db)

	// Insert test data
	categoryID, err := InsertTestCategory(db, "Software")
	if err != nil {
		t.Fatalf("Failed to insert test category: %v", err)
	}

	// Create first line
	firstLine := domain.Line{
		Line:       "Windows",
		CategoryID: categoryID,
	}

	id, err := lineStore.CreateLine(firstLine)
	if err != nil {
		t.Fatalf("Failed to create first line: %v", err)
	}
	if id == "" {
		t.Error("Expected line ID")
	}

	// Try to create duplicate line in same category
	duplicateLine := domain.Line{
		Line:       "Windows",
		CategoryID: categoryID,
	}

	_, err = lineStore.CreateLine(duplicateLine)
	if err == nil {
		t.Error("Expected error creating duplicate line in same category")
	}
}

// TestGetLineByIDCritical tests retrieving a specific line
func TestGetLineByIDCritical(t *testing.T) {
	db := setupLineTestDB(t)
	defer CloseDB(db)

	lineStore := NewLineStore(db)

	// Insert test data
	categoryID, err := InsertTestCategory(db, "Software")
	if err != nil {
		t.Fatalf("Failed to insert test category: %v", err)
	}

	lineID, err := InsertTestLine(db, "Test Line", categoryID)
	if err != nil {
		t.Fatalf("Failed to insert test line: %v", err)
	}

	// Get the line
	line, err := lineStore.GetLineByID(lineID)
	if err != nil {
		t.Fatalf("Failed to get line: %v", err)
	}

	if line == nil {
		t.Error("Expected line, got nil")
	}

	if line != nil && line.ID != lineID {
		t.Errorf("Expected line ID '%s', got '%s'", lineID, line.ID)
	}

	if line != nil && line.Line != "Test Line" {
		t.Errorf("Expected line name 'Test Line', got '%s'", line.Line)
	}

	if line != nil && line.CategoryID != categoryID {
		t.Errorf("Expected category ID '%s', got '%s'", categoryID, line.CategoryID)
	}
}

// TestGetLineByIDNonExistent tests retrieving a non-existent line
func TestGetLineByIDNonExistent(t *testing.T) {
	db := setupLineTestDB(t)
	defer CloseDB(db)

	lineStore := NewLineStore(db)

	line, err := lineStore.GetLineByID(uuid.New().String())
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

// TestCreateLineWithInvalidNames tests various invalid line name formats
func TestCreateLineWithInvalidNames(t *testing.T) {
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

	lineStore := NewLineStore(db)

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
			description: "Line name with 256 characters should be rejected",
		},
		{
			name:        "invalid - name way too long (1000 chars)",
			lineName:    veryLongName,
			expectError: true,
			description: "Line name with 1000 characters should be rejected",
		},
		{
			name:        "invalid - name with only spaces",
			lineName:    "     ",
			expectError: true,
			description: "Line name with only whitespace should be rejected",
		},
		{
			name:        "valid - name at max length (255 chars)",
			lineName:    strings.Repeat("a", 255),
			expectError: false,
			description: "Line name with exactly 255 characters should be allowed",
		},
		{
			name:        "valid - name with special characters",
			lineName:    "Line Pro - Edition 2025",
			expectError: false,
			description: "Line name with special characters should be allowed",
		},
		{
			name:        "valid - name with accents",
			lineName:    "Linha Profissional",
			expectError: false,
			description: "Line name with Portuguese accents should be allowed",
		},
	}

	counter := 0
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			line := domain.Line{
				Line:       tt.lineName,
				CategoryID: categoryID,
			}

			_, err := lineStore.CreateLine(line)

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

// TestCreateLineWithInvalidCategory tests line creation with invalid category
func TestCreateLineWithInvalidCategory(t *testing.T) {
	db, err := SetupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}
	defer CloseDB(db)

	lineStore := NewLineStore(db)

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
			description: "Line with non-existent category should be rejected",
		},
		{
			name:        "invalid - empty category ID",
			categoryID:  "",
			expectError: true,
			description: "Line with empty category ID should be rejected",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			line := domain.Line{
				Line:       "Test Line",
				CategoryID: tt.categoryID,
			}

			_, err := lineStore.CreateLine(line)

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

	lineStore := NewLineStore(db)

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
	_, err = lineStore.CreateLine(domain.Line{
		Line:       "Shared Line Name",
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
			lineName:    "Shared Line Name",
			categoryID:  category1ID,
			expectError: true,
			description: "Duplicate line name in same category should be rejected",
		},
		{
			name:        "valid - same name in different category",
			lineName:    "Shared Line Name",
			categoryID:  category2ID,
			expectError: false,
			description: "Same line name in different category should be allowed",
		},
		{
			name:        "duplicate - case sensitivity check (lowercase)",
			lineName:    "shared line name",
			categoryID:  category1ID,
			expectError: true, // Depends on DB collation - may need to adjust
			description: "Line name with different case in same category",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			line := domain.Line{
				Line:       tt.lineName,
				CategoryID: tt.categoryID,
			}

			_, err := lineStore.CreateLine(line)

			if tt.expectError && err == nil {
				t.Errorf("Expected error for %s, but got none", tt.description)
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error for %s, but got: %v", tt.description, err)
			}
		})
	}
}

// TestUpdateLineWithInvalidData tests update operations with invalid data
func TestUpdateLineWithInvalidData(t *testing.T) {
	db, err := SetupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}
	defer CloseDB(db)

	lineStore := NewLineStore(db)

	// Create category and line
	categoryID, err := InsertTestCategory(db, "Test Category")
	if err != nil {
		t.Fatalf("Failed to insert test category: %v", err)
	}

	lineID, err := InsertTestLine(db, "Original Line", categoryID)
	if err != nil {
		t.Fatalf("Failed to insert test line: %v", err)
	}

	tests := []struct {
		name        string
		line        domain.Line
		expectError bool
		description string
	}{
		{
			name: "invalid - update with name too long",
			line: domain.Line{
				ID:         lineID,
				Line:       strings.Repeat("a", 256),
				CategoryID: categoryID,
			},
			expectError: true,
			description: "Update with name too long should fail",
		},
		{
			name: "invalid - update with only whitespace",
			line: domain.Line{
				ID:         lineID,
				Line:       "    ",
				CategoryID: categoryID,
			},
			expectError: true,
			description: "Update with whitespace-only name should fail",
		},
		{
			name: "invalid - update with empty name",
			line: domain.Line{
				ID:         lineID,
				Line:       "",
				CategoryID: categoryID,
			},
			expectError: true,
			description: "Update with empty name should fail",
		},
		{
			name: "valid - update with valid name",
			line: domain.Line{
				ID:         lineID,
				Line:       "Updated Line Name",
				CategoryID: categoryID,
			},
			expectError: false,
			description: "Update with valid name should succeed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := lineStore.UpdateLine(tt.line)

			if tt.expectError && err == nil {
				t.Errorf("Expected error for %s, but got none", tt.description)
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error for %s, but got: %v", tt.description, err)
			}
		})
	}
}

// TestCreateDependentWithInvalidNames tests various invalid dependent name formats
func TestCreateDependentWithInvalidNames(t *testing.T) {
	db, err := SetupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}
	defer CloseDB(db)

	// Create client first
	clientID, err := InsertTestClient(db, "Test Client", "45.723.174/0001-10")
	if err != nil {
		t.Fatalf("Failed to insert test client: %v", err)
	}

	dependentStore := NewDependentStore(db)

	// Generate long names
	longName := strings.Repeat("a", 256)
	veryLongName := strings.Repeat("a", 1000)

	tests := []struct {
		name          string
		dependentName string
		expectError   bool
		description   string
	}{
		{
			name:          "invalid - name too long (256 chars)",
			dependentName: longName,
			expectError:   true,
			description:   "Dependent name with 256 characters should be rejected",
		},
		{
			name:          "invalid - name way too long (1000 chars)",
			dependentName: veryLongName,
			expectError:   true,
			description:   "Dependent name with 1000 characters should be rejected",
		},
		{
			name:          "invalid - name with only spaces",
			dependentName: "     ",
			expectError:   true,
			description:   "Dependent name with only whitespace should be rejected",
		},
		{
			name:          "valid - name at max length (255 chars)",
			dependentName: strings.Repeat("a", 255),
			expectError:   false,
			description:   "Dependent name with exactly 255 characters should be allowed",
		},
		{
			name:          "valid - name with special characters",
			dependentName: "Unit A - Building 2",
			expectError:   false,
			description:   "Dependent name with special characters should be allowed",
		},
		{
			name:          "valid - name with accents",
			dependentName: "Unidade São Paulo",
			expectError:   false,
			description:   "Dependent name with Portuguese accents should be allowed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear dependents table between tests
			_, err = db.Exec("DELETE FROM dependents")
			if err != nil {
				t.Fatalf("Failed to clear dependents: %v", err)
			}

			dependent := domain.Dependent{
				Name:     tt.dependentName,
				ClientID: clientID,
			}

			_, err = dependentStore.CreateDependent(dependent)

			if tt.expectError && err == nil {
				t.Errorf("Expected error for %s, but got none", tt.description)
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error for %s, but got: %v", tt.description, err)
			}
		})
	}
}

// TestCreateDependentWithInvalidClient tests dependent creation with invalid client
func TestCreateDependentWithInvalidClient(t *testing.T) {
	db, err := SetupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}
	defer CloseDB(db)

	dependentStore := NewDependentStore(db)

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
			description: "Dependent with non-existent client should be rejected",
		},
		{
			name:        "invalid - empty client ID",
			clientID:    "",
			expectError: true,
			description: "Dependent with empty client ID should be rejected",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dependent := domain.Dependent{
				Name:     "Test Dependent",
				ClientID: tt.clientID,
			}

			_, err := dependentStore.CreateDependent(dependent)

			if tt.expectError && err == nil {
				t.Errorf("Expected error for %s, but got none", tt.description)
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error for %s, but got: %v", tt.description, err)
			}
		})
	}
}

// TestUpdateDependentWithInvalidData tests update operations with invalid data
func TestUpdateDependentWithInvalidData(t *testing.T) {
	db, err := SetupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}
	defer CloseDB(db)

	dependentStore := NewDependentStore(db)

	// Create client and dependent
	clientID, err := InsertTestClient(db, "Test Client", "45.723.174/0001-10")
	if err != nil {
		t.Fatalf("Failed to insert test client: %v", err)
	}

	dependentID := "test-dependent-id"
	_, err = db.Exec("INSERT INTO dependents (id, name, client_id) VALUES (?, ?, ?)",
		dependentID, "Original Dependent", clientID)
	if err != nil {
		t.Fatalf("Failed to insert test dependent: %v", err)
	}

	tests := []struct {
		name        string
		dependent   domain.Dependent
		expectError bool
		description string
	}{
		{
			name: "invalid - update with name too long",
			dependent: domain.Dependent{
				ID:       dependentID,
				Name:     strings.Repeat("a", 256),
				ClientID: clientID,
			},
			expectError: true,
			description: "Update with name too long should fail",
		},
		{
			name: "invalid - update with only whitespace",
			dependent: domain.Dependent{
				ID:       dependentID,
				Name:     "    ",
				ClientID: clientID,
			},
			expectError: true,
			description: "Update with whitespace-only name should fail",
		},
		{
			name: "invalid - update with empty name",
			dependent: domain.Dependent{
				ID:       dependentID,
				Name:     "",
				ClientID: clientID,
			},
			expectError: true,
			description: "Update with empty name should fail",
		},
		{
			name: "valid - update with valid name",
			dependent: domain.Dependent{
				ID:       dependentID,
				Name:     "Updated Dependent Name",
				ClientID: clientID,
			},
			expectError: false,
			description: "Update with valid name should succeed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := dependentStore.UpdateDependent(tt.dependent)

			if tt.expectError && err == nil {
				t.Errorf("Expected error for %s, but got none", tt.description)
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error for %s, but got: %v", tt.description, err)
			}
		})
	}
}

// TestDependentNameTrimming tests that whitespace is properly handled for dependents
func TestDependentNameTrimming(t *testing.T) {
	db, err := SetupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}
	defer CloseDB(db)

	// Create client first
	clientID, err := InsertTestClient(db, "Test Client", "45.723.174/0001-10")
	if err != nil {
		t.Fatalf("Failed to insert test client: %v", err)
	}

	dependentStore := NewDependentStore(db)

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
			// Clear dependents between tests
			_, err := db.Exec("DELETE FROM dependents")
			if err != nil {
				t.Fatalf("Failed to clear dependents: %v", err)
			}

			dependent := domain.Dependent{
				Name:     tt.inputName,
				ClientID: clientID,
			}

			id, err := dependentStore.CreateDependent(dependent)

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}

			// If creation succeeded, verify the name was trimmed
			if !tt.expectError && err == nil {
				retrievedDependent, err := dependentStore.GetDependentByID(id)
				if err != nil {
					t.Errorf("Failed to retrieve dependent: %v", err)
				}
				if retrievedDependent != nil && retrievedDependent.Name != tt.expectedName {
					t.Errorf("Expected name '%s', got '%s'", tt.expectedName, retrievedDependent.Name)
				}
			}
		})
	}
}
