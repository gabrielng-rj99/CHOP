package tests

import (
	"Licenses-Manager/backend/domain"
	"Licenses-Manager/backend/store"
	"database/sql"
	"testing"
	"time"
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

	lineStore := store.NewLineStore(db)

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

	lineStore := store.NewLineStore(db)

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
				CategoryID: "non-existent",
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

	lineStore := store.NewLineStore(db)

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

// TestDeleteLineWithActiveLicenses tests that deletion fails with associated licenses
func TestDeleteLineWithActiveLicenses(t *testing.T) {
	db := setupLineTestDB(t)
	defer CloseDB(db)

	lineStore := store.NewLineStore(db)

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
	_, err = InsertTestLicense(db, "Test License", "TEST-KEY", now.AddDate(0, 0, -10), now.AddDate(0, 0, 30), lineID, clientID, nil)
	if err != nil {
		t.Fatalf("Failed to insert test license: %v", err)
	}

	// Try to delete - should fail
	err = lineStore.DeleteLine(lineID)
	if err == nil {
		t.Error("Expected error deleting line with associated licenses")
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

	lineStore := store.NewLineStore(db)

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

	lineStore := store.NewLineStore(db)

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

	lineStore := store.NewLineStore(db)

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

	lineStore := store.NewLineStore(db)

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

	lineStore := store.NewLineStore(db)

	line, err := lineStore.GetLineByID("non-existent-id")
	if err != nil {
		t.Fatalf("Expected no error for non-existent line, got: %v", err)
	}

	if line != nil {
		t.Error("Expected nil for non-existent line")
	}
}
